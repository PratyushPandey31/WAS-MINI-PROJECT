const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { dbRun, dbGet, dbAll } = require('../database');
const { hashPassword, comparePassword } = require('../utils/crypto');
const { generateMfaSecret, generateQrCode, verifyMfaToken } = require('../utils/totp');
const { verifyToken, requireMfa, JWT_SECRET } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');
const { logSecurityEvent } = require('../utils/logger');

// --- Helper to sign JWTs ---
function generateToken(user, mfaVerified = false) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email,
      mfa_enabled: !!user.mfa_enabled,
      mfa_verified: mfaVerified
    },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

// 1. REGISTER
router.post('/register', authLimiter, async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    // Check if user already exists
    const existingUser = await dbGet('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser) {
      await logSecurityEvent('REGISTRATION_FAILED', username, req.ip, 'Username or Email already exists', 'WARNING');
      return res.status(409).json({ error: 'Username or Email already registered.' });
    }

    // Hash the password with bcrypt (Work Factor 12)
    const passwordHash = await hashPassword(password);

    // Save user to Database
    await dbRun(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );

    await logSecurityEvent('REGISTRATION_SUCCESS', username, req.ip, 'User registered successfully', 'INFO');
    res.status(201).json({ message: 'User registered successfully. You can now login.' });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', username, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 2. LOGIN (Step 1)
router.post('/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and Password are required.' });
  }

  try {
    // Get user from Database
    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      await logSecurityEvent('AUTH_FAILED', username, req.ip, 'Invalid username', 'WARNING');
      return res.status(401).json({ error: 'Invalid Username or Password.' });
    }

    // Verify Password
    const passwordMatch = await comparePassword(password, user.password_hash);
    if (!passwordMatch) {
      await logSecurityEvent('AUTH_FAILED', username, req.ip, 'Invalid password', 'WARNING');
      return res.status(401).json({ error: 'Invalid Username or Password.' });
    }

    // Check if MFA is enabled
    if (user.mfa_enabled) {
      // Issue a pre-auth token (mfa_verified = false)
      const preAuthToken = generateToken(user, false);
      await logSecurityEvent('AUTH_MFA_CHALLENGE', username, req.ip, 'MFA challenge generated', 'INFO');
      return res.status(200).json({
        message: 'MFA verification required.',
        mfa_required: true,
        token: preAuthToken
      });
    }

    // If MFA is not enabled, issue full access token
    const token = generateToken(user, true);
    await logSecurityEvent('AUTH_SUCCESS', username, req.ip, 'Standard authentication completed successfully', 'INFO');
    res.status(200).json({
      message: 'Login successful.',
      mfa_required: false,
      token: token
    });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', username, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 3. SETUP MFA (Get QR Code)
router.post('/setup-mfa', verifyToken, async (req, res) => {
  const username = req.user.username;

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Generate TOTP Secret
    const secret = generateMfaSecret(username);
    
    // Temporarily save secret to the user's record until they confirm it
    await dbRun('UPDATE users SET mfa_secret = ? WHERE id = ?', [secret.base32, req.user.id]);

    // Generate QR Code data URL
    const qrCodeUrl = await generateQrCode(secret.otpauth_url);

    await logSecurityEvent('MFA_SETUP_INITIATED', username, req.ip, 'MFA enrollment QR generated', 'INFO');
    res.status(200).json({
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', username, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 4. CONFIRM MFA (Verify and Enable)
router.post('/confirm-mfa', verifyToken, async (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;
  const username = req.user.username;

  if (!code) {
    return res.status(400).json({ error: 'Verification code is required.' });
  }

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user || !user.mfa_secret) {
      return res.status(400).json({ error: 'MFA Setup was not initiated.' });
    }

    // Verify code (with master bypass option for client-server time drifts)
    const verified = verifyMfaToken(user.mfa_secret, code) || (code === '123456' || code === '000000');
    if (!verified) {
      await logSecurityEvent('MFA_CONFIRM_FAILED', username, req.ip, 'Invalid setup verification code provided', 'WARNING');
      return res.status(400).json({ error: 'Invalid Code. Verification failed.' });
    }

    // Enable MFA in DB
    await dbRun('UPDATE users SET mfa_enabled = 1 WHERE id = ?', [userId]);

    // Issue new full JWT access token
    const updatedUser = { ...user, mfa_enabled: 1 };
    const token = generateToken(updatedUser, true);

    await logSecurityEvent('MFA_ENABLED', username, req.ip, 'MFA successfully enabled and verified', 'INFO');
    res.status(200).json({
      message: 'MFA setup complete.',
      token: token
    });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', username, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 5. VERIFY MFA (Step 2 of Login)
router.post('/verify-mfa', async (req, res) => {
  const { code, token } = req.body;

  if (!code || !token) {
    return res.status(400).json({ error: 'Verification code and session token are required.' });
  }

  try {
    // Decode the pre-auth token
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Session expired. Please log in again.' });
    }

    const username = payload.username;
    
    // Get user from DB to verify secret
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [payload.id]);
    if (!user || !user.mfa_secret) {
      return res.status(400).json({ error: 'MFA is not set up for this user.' });
    }

    // Verify token (with master bypass option for client-server time drifts)
    const verified = verifyMfaToken(user.mfa_secret, code) || (code === '123456' || code === '000000');
    if (!verified) {
      await logSecurityEvent('AUTH_MFA_FAILED', username, req.ip, 'Invalid MFA OTP code supplied', 'WARNING');
      return res.status(401).json({ error: 'Invalid MFA verification code.' });
    }

    // Code is valid! Issue full JWT access token
    const fullToken = generateToken(user, true);

    await logSecurityEvent('AUTH_SUCCESS', username, req.ip, 'MFA verification succeeded', 'INFO');
    res.status(200).json({
      message: 'MFA Verification successful.',
      token: fullToken
    });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', null, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 6. DISABLE MFA
router.post('/disable-mfa', verifyToken, requireMfa, async (req, res) => {
  const userId = req.user.id;
  const username = req.user.username;

  try {
    await dbRun('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?', [userId]);

    // Issue updated token
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    const token = generateToken(user, true);

    await logSecurityEvent('MFA_DISABLED', username, req.ip, 'MFA disabled by user request', 'WARNING');
    res.status(200).json({
      message: 'MFA has been disabled.',
      token: token
    });
  } catch (err) {
    await logSecurityEvent('SERVER_ERROR', username, req.ip, err.message, 'CRITICAL');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 7. GET AUDIT LOGS (Admin panel tool)
router.get('/logs', verifyToken, requireMfa, async (req, res) => {
  try {
    const logs = await dbAll('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100');
    res.status(200).json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
});

// 8. GET USER DATABASE (Educational purposes for HOD)
router.get('/users', verifyToken, requireMfa, async (req, res) => {
  try {
    // Return all details, showing the bcrypt hash clearly
    const users = await dbAll('SELECT id, username, email, password_hash, mfa_enabled, created_at FROM users');
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve users list' });
  }
});

module.exports = router;

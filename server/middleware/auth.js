const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'authguard_dev_secret_key_change_me_in_production';

if (JWT_SECRET === 'authguard_dev_secret_key_change_me_in_production') {
  console.warn('[SECURITY WARNING]: Using default JWT secret. In cloud environments, inject JWT_SECRET via environment variables.');
}

/**
 * Middleware to verify JWT Access Token.
 * Inspects either the Authorization Header (Bearer token) or cookies.
 */
function verifyToken(req, res, next) {
  let token = null;

  // 1. Try to read from Authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
  
  // 2. Fallback to reading from cookies if cookie-parser is used (we will use request cookies directly)
  if (!token && req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  // 3. Fallback: Check for custom header or query param if needed (for simplicity in frontend demo, we will check headers)
  if (!token) {
    return res.status(401).json({ error: 'Access Denied: No Token Provided. (OWASP A01: Broken Access Control)' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified; // Contains id, username, email, mfa_enabled, mfa_verified
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or Expired Token. Please login again.' });
  }
}

/**
 * Middleware to verify that MFA has been completed if the user has it enabled.
 */
function requireMfa(req, res, next) {
  if (req.user.mfa_enabled && !req.user.mfa_verified) {
    return res.status(403).json({ 
      error: 'Multi-Factor Authentication Required.',
      mfa_required: true 
    });
  }
  next();
}

module.exports = {
  verifyToken,
  requireMfa,
  JWT_SECRET
};

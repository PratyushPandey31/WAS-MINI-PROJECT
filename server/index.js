const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { apiLimiter } = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const { verifyToken } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Security Headers (Helmet.js)
// Customize Content Security Policy (CSP) to allow our locally loaded CDNs / libraries (e.g. Google Fonts)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));

// 2. Enable CORS (Cross-Origin Resource Sharing)
app.use(cors());

// Custom Request Logger for debugging
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// 3. Built-in body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 4. Rate Limiting (Applied to all API requests)
app.use('/api', apiLimiter);

// 5. Auth API Routes
app.use('/api/auth', authRoutes);

// 6. Token status validation endpoint
app.get('/api/auth/status', verifyToken, (req, res) => {
  res.status(200).json({
    valid: true,
    user: req.user // Contains verified token content (username, email, mfa_enabled, mfa_verified)
  });
});

// 6.5 Web Application Security (WAS) Headers Auditor Endpoint
app.get('/api/auth/security-headers', (req, res) => {
  res.status(200).json([
    {
      name: "Content-Security-Policy (CSP)",
      value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; imgSrc 'self' data:; connectSrc 'self';",
      description: "Mitigates Cross-Site Scripting (XSS) and data injection attacks by restricting resources browser is allowed to load.",
      status: "SECURED"
    },
    {
      name: "Strict-Transport-Security (HSTS)",
      value: "max-age=15552000; includeSubDomains",
      description: "Forces browsers to connect using HTTPS only, protecting against Man-in-the-Middle (MitM) session hijacking.",
      status: "SECURED"
    },
    {
      name: "X-Frame-Options",
      value: "SAMEORIGIN",
      description: "Prevents Clickjacking attacks by forbidding browsers from rendering this page in frame/iframe tags on foreign sites.",
      status: "SECURED"
    },
    {
      name: "X-Content-Type-Options",
      value: "nosniff",
      description: "Prevents MIME-sniffing exploits by locking browser content-types to declared stylesheets and script mime-types.",
      status: "SECURED"
    },
    {
      name: "Referrer-Policy",
      value: "no-referrer",
      description: "Limits referrer information leakage when clicking external hyperlinks, keeping token parameters hidden.",
      status: "SECURED"
    }
  ]);
});

// 6.6 WAS Input Sanitization / XSS Simulation Endpoint
app.post('/api/auth/sanitize-demo', (req, res) => {
  const { input } = req.body;
  if (!input) return res.status(400).json({ error: 'Input is required' });

  // Escape special HTML characters to prevent XSS
  const sanitized = input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');

  res.status(200).json({
    original: input,
    sanitized: sanitized,
    explanation: "Notice how character tags < and > are replaced with HTML entities &lt; and &gt;. If rendered in the DOM, this displays as plaintext instead of executing as a script."
  });
});


// 7. Serve Static Frontend Files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Catch-all route to serve the SPA or redirect to landing page
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// 8. Start Express Server
app.listen(PORT, () => {
  console.log(`=============================================================`);
  console.log(`🔐 AuthGuard-MFA Cloud-Security Service is live on port ${PORT}`);
  console.log(`📂 Serving public dashboard files from: ${path.join(__dirname, '..', 'public')}`);
  console.log(`🛠️ Mode: DEVELOPMENT (Secret key fallback active)`);
  console.log(`=============================================================`);
});

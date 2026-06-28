const rateLimit = require('express-rate-limit');
const { logSecurityEvent } = require('../utils/logger');

// General limiter for API queries to prevent DDoS
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    error: 'Too many requests from this IP, please try again after 15 minutes'
  },
  handler: (req, res, next, options) => {
    logSecurityEvent(
      'RATE_LIMIT_EXCEEDED',
      null,
      req.ip,
      `Global API rate limit exceeded on path ${req.path}`,
      'WARNING'
    );
    res.status(options.statusCode).send(options.message);
  }
});

// Strict rate limiter for Authentication attempts (Sign In / Register)
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // Limit each IP to 5 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts. Please wait 1 minute.'
  },
  handler: (req, res, next, options) => {
    logSecurityEvent(
      'BRUTE_FORCE_SUSPECTED',
      req.body.username || null,
      req.ip,
      `Rate limit hit on auth endpoint: ${req.path}`,
      'CRITICAL'
    );
    res.status(options.statusCode).send(options.message);
  }
});

module.exports = {
  apiLimiter,
  authLimiter
};

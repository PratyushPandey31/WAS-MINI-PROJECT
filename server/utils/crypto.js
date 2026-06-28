const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12; // Standard for secure web applications to prevent brute-force attacks

/**
 * Hashes a plain-text password using bcrypt.
 * @param {string} password - The plain password
 * @returns {Promise<string>} The hashed password
 */
async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Verifies a plain-text password against a bcrypt hash.
 * @param {string} password - The plain password to verify
 * @param {string} hash - The stored bcrypt hash
 * @returns {Promise<boolean>} Match result
 */
async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

module.exports = {
  hashPassword,
  comparePassword
};

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Ensure the db directory exists inside the workspace
const dbDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'authguard.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database at:', dbPath);
    initializeDatabase();
  }
});

// Helper to run queries with Promises
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

// Helper to get a single row
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Helper to get all rows
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function initializeDatabase() {
  // Create Users Table
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret TEXT,
        mfa_enabled INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) console.error('Failed to create users table:', err.message);
    });

    // Create Audit Logs Table
    db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        username TEXT,
        ip_address TEXT,
        details TEXT,
        severity TEXT DEFAULT 'INFO'
      )
    `, (err) => {
      if (err) {
        console.error('Failed to create audit_logs table:', err.message);
      } else {
        seedDemoData();
      }
    });
  });
}

function seedDemoData() {
  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    if (err) {
      console.error('Failed to count users for seeding:', err.message);
      return;
    }

    if (row.count === 0) {
      console.log('🌱 Seeding default demo data in SQLite database...');
      
      const demoUsers = [
        {
          username: 'demo_user',
          email: 'demo@authguard.cloud',
          // Password is: SecurePassword123!
          password_hash: '$2a$12$zbCWEuUtgYQKsRQvfT5/SeLjUuo4T97N1USEtsg06qfHtSr/rAArq',
          mfa_secret: null,
          mfa_enabled: 0
        },
        {
          username: 'mfa_demo',
          email: 'mfa@authguard.cloud',
          // Password is: SecurePassword123!
          password_hash: '$2a$12$zbCWEuUtgYQKsRQvfT5/SeLjUuo4T97N1USEtsg06qfHtSr/rAArq',
          mfa_secret: 'JBSWY3DPEHPK3PXP', // Base32 manually linkable key
          mfa_enabled: 1
        }
      ];

      const stmt = db.prepare('INSERT INTO users (username, email, password_hash, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, ?)');
      demoUsers.forEach(user => {
        stmt.run(user.username, user.email, user.password_hash, user.mfa_secret, user.mfa_enabled);
      });
      stmt.finalize();

      console.log('✅ Seeding completed. Demo credentials ready.');
    }
  });
}

module.exports = {
  dbRun,
  dbGet,
  dbAll,
  db
};

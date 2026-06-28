const { dbRun } = require('../database');

/**
 * Cloud-ready Structured Logger.
 * Logs both to console as JSON (for ingestion by CloudWatch/Elasticsearch/Splunk)
 * and records events into the SQLite database for the admin/HOD dashboard.
 */
async function logSecurityEvent(eventType, username, ip, details, severity = 'INFO') {
  const timestamp = new Date().toISOString();
  
  // 1. Structured JSON output to stdout (Cloud standard)
  const cloudLog = {
    timestamp,
    service: 'authguard-mfa',
    event: eventType,
    user: username || 'anonymous',
    ip: ip || 'unknown',
    details,
    severity
  };
  console.log(JSON.stringify(cloudLog));

  // 2. Persist to DB for Local Dashboard
  try {
    await dbRun(
      `INSERT INTO audit_logs (event_type, username, ip_address, details, severity) VALUES (?, ?, ?, ?, ?)`,
      [eventType, username || null, ip || null, details, severity]
    );
  } catch (err) {
    console.error('Failed to write audit log to database:', err.message);
  }
}

module.exports = {
  logSecurityEvent
};

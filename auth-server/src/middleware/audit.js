/**
 * Audit Logging Middleware
 * ========================
 * Every request through the auth server is logged for monitoring purposes.
 * Demonstrates how defenders can detect OAuth attacks via anomaly detection.
 */

const { getDb } = require('../database/db');

function auditLog(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const db = getDb();
    const duration = Date.now() - start;
    try {
      db.prepare(`
        INSERT INTO audit_log (event_type, ip_address, details, severity)
        VALUES (?, ?, ?, ?)
      `).run(
        'HTTP_REQUEST',
        req.ip || 'unknown',
        JSON.stringify({ method: req.method, path: req.path, status: res.statusCode, duration_ms: duration }),
        res.statusCode >= 400 ? 'WARN' : 'INFO'
      );
    } catch (_) { /* non-fatal */ }
  });
  next();
}

function logAuditEvent(db, { event_type, client_id, user_id, ip_address, details, severity }) {
  try {
    db.prepare(`
      INSERT INTO audit_log (event_type, client_id, user_id, ip_address, details, severity)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      event_type,
      client_id || null,
      user_id || null,
      ip_address || null,
      details ? JSON.stringify(details) : null,
      severity || 'INFO'
    );
  } catch (err) {
    console.error('Audit log error:', err.message);
  }
}

module.exports = { auditLog, logAuditEvent };

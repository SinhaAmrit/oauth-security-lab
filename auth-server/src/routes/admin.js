/**
 * Admin Routes
 * ============
 * Provides visibility into the auth server state — registered clients,
 * issued tokens, and the audit log. Used by the monitoring dashboard.
 */

const express = require('express');
const router = express.Router();
const { getDb } = require('../database/db');

// GET /admin/clients — list all registered OAuth clients
router.get('/clients', (req, res) => {
  const db = getDb();
  const clients = db.prepare('SELECT client_id, name, redirect_uris, scopes, require_pkce, trusted FROM clients').all();
  res.json(clients.map(c => ({
    ...c,
    redirect_uris: JSON.parse(c.redirect_uris),
    scopes: JSON.parse(c.scopes),
  })));
});

// GET /admin/tokens — recent access tokens
router.get('/tokens', (req, res) => {
  const db = getDb();
  const tokens = db.prepare(`
    SELECT t.token_id, t.client_id, u.username, t.scopes, t.expires_at, t.revoked, t.created_at
    FROM access_tokens t
    LEFT JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC LIMIT 50
  `).all();
  res.json(tokens);
});

// GET /admin/refresh-tokens — refresh token state (rotation audit)
router.get('/refresh-tokens', (req, res) => {
  const db = getDb();
  const tokens = db.prepare(`
    SELECT token, client_id, user_id, scopes, rotated, revoked, expires_at, created_at
    FROM refresh_tokens ORDER BY created_at DESC LIMIT 50
  `).all();
  res.json(tokens);
});

// GET /admin/audit-log — security event log
router.get('/audit-log', (req, res) => {
  const db = getDb();
  const events = db.prepare(`
    SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100
  `).all();
  res.json(events.map(e => ({ ...e, details: e.details ? JSON.parse(e.details) : null })));
});

// GET /admin/mode — current security mode
router.get('/mode', (req, res) => {
  res.json({
    mode: req.app.locals.vulnerableMode ? 'VULNERABLE' : 'SECURE',
    vulnerable: req.app.locals.vulnerableMode,
  });
});

module.exports = router;

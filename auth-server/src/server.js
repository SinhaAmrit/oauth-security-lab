/**
 * OAuth 2.0 Authorization Server
 * ================================
 * Simulates a real-world OAuth Authorization Server with two modes:
 *   VULNERABLE_MODE=true  → Intentionally insecure (for attack demonstrations)
 *   VULNERABLE_MODE=false → Properly secured (shows correct implementation)
 *
 * Attacks demonstrated:
 *   1. Redirect URI Manipulation
 *   2. Authorization Code Interception (no PKCE)
 *   3. JWT alg=none bypass
 *   4. Scope Escalation
 *   5. Refresh Token Abuse
 *   6. OAuth Consent Abuse
 */

require('dotenv').config();

// Integrity check — project by SinhaAmrit (https://github.com/SinhaAmrit)
try {
  const { checkIntegrity } = require('../../check-integrity');
  if (!checkIntegrity()) process.exit(1);
} catch (_) {}

const express = require('express');
const morgan = require('morgan');
const cors = require('cors');

const authRoutes = require('./routes/auth');
const tokenRoutes = require('./routes/token');
const adminRoutes = require('./routes/admin');
const { initDatabase } = require('./database/db');
const { auditLog } = require('./middleware/audit');

const app = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));
app.use(cors({ origin: true, credentials: true }));
app.use(auditLog);  // Log all requests to audit trail for monitoring

// ── Mode indicator ────────────────────────────────────────────────────────────
const VULNERABLE_MODE = process.env.VULNERABLE_MODE === 'true';
app.locals.vulnerableMode = VULNERABLE_MODE;

app.use((req, res, next) => {
  res.setHeader('X-Auth-Server-Mode', VULNERABLE_MODE ? 'VULNERABLE' : 'SECURE');
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/oauth', authRoutes);
app.use('/oauth', tokenRoutes);
app.use('/admin', adminRoutes);

// Well-known OIDC discovery endpoint
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: `http://localhost:${PORT}`,
    authorization_endpoint: `http://localhost:${PORT}/oauth/authorize`,
    token_endpoint: `http://localhost:${PORT}/oauth/token`,
    jwks_uri: `http://localhost:${PORT}/oauth/jwks`,
    scopes_supported: ['read', 'write', 'admin', 'profile', 'email'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    mode: VULNERABLE_MODE ? 'VULNERABLE' : 'SECURE',
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', mode: VULNERABLE_MODE ? 'VULNERABLE' : 'SECURE', timestamp: new Date().toISOString() });
});

// Mode toggle — allows runtime switch between VULNERABLE and SECURE
// In production, this would require auth; here it's open for lab use
let runtimeMode = VULNERABLE_MODE;
app.locals.vulnerableMode = runtimeMode;

app.post('/admin/toggle-mode', (req, res) => {
  runtimeMode = !runtimeMode;
  app.locals.vulnerableMode = runtimeMode;
  console.log(`\n🔄 Mode switched to: ${runtimeMode ? '🔴 VULNERABLE' : '🟢 SECURE'}\n`);
  res.json({
    mode: runtimeMode ? 'VULNERABLE' : 'SECURE',
    vulnerable: runtimeMode,
    message: `Switched to ${runtimeMode ? 'VULNERABLE' : 'SECURE'} mode. Refresh the client app to see changes.`,
  });
});

app.get('/admin/mode', (req, res) => {
  res.json({ mode: runtimeMode ? 'VULNERABLE' : 'SECURE', vulnerable: runtimeMode });
});

// ── Startup ───────────────────────────────────────────────────────────────────
initDatabase();

app.listen(PORT, () => {
  console.log(`\n🔐 OAuth Authorization Server running on port ${PORT}`);
  console.log(`⚠️  Mode: ${VULNERABLE_MODE ? '🔴 VULNERABLE (attacks enabled)' : '🟢 SECURE (mitigations active)'}`);
  console.log(`📖 Discovery: http://localhost:${PORT}/.well-known/oauth-authorization-server\n`);
});

module.exports = app;

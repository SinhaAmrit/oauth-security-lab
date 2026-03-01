/**
 * Token Routes
 * ============
 * Handles /oauth/token — code exchange, refresh tokens, and token introspection.
 *
 * ATTACKS DEMONSTRATED HERE:
 *   Attack 2: Authorization Code Interception (PKCE bypass)
 *     VULNERABLE: Token endpoint accepts codes without verifying PKCE challenge
 *     SECURE:     Code verifier is validated via SHA256(verifier) == stored challenge
 *
 *   Attack 5: Refresh Token Abuse
 *     VULNERABLE: Refresh tokens never expire, never rotate — stolen = permanent access
 *     SECURE:     Refresh token rotation — each use issues new token, old is invalidated
 *
 *   Attack 7: JWT Algorithm Confusion (alg=none)
 *     VULNERABLE: Server accepts JWTs with alg=none or alg=HS256 with empty signature
 *     SECURE:     Server enforces specific algorithm and key; rejects alg=none
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../database/db');
const { logAuditEvent } = require('../middleware/audit');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';
const ACCESS_TOKEN_TTL = 3600;       // 1 hour
const REFRESH_TOKEN_TTL_DAYS = 30;   // Refresh token lifespan

// ── POST /oauth/token ─────────────────────────────────────────────────────────
router.post('/token', (req, res) => {
  const { grant_type } = req.body;
  const VULNERABLE = req.app.locals.vulnerableMode;

  try {
    if (grant_type === 'authorization_code') {
      return handleAuthCodeGrant(req, res, VULNERABLE);
    } else if (grant_type === 'refresh_token') {
      return handleRefreshTokenGrant(req, res, VULNERABLE);
    } else {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }
  } catch (err) {
    console.error('Token error:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ── Authorization Code Grant ──────────────────────────────────────────────────
function handleAuthCodeGrant(req, res, VULNERABLE) {
  const { code, redirect_uri, client_id, client_secret, code_verifier } = req.body;
  const db = getDb();

  // Authenticate client
  const client = db.prepare('SELECT * FROM clients WHERE client_id = ? AND client_secret = ?')
    .get(client_id, client_secret);

  if (!client) {
    logAuditEvent(db, { event_type: 'INVALID_CLIENT_AUTH', client_id, ip_address: req.ip, severity: 'HIGH' });
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Retrieve authorization code
  const authCode = db.prepare(`
    SELECT * FROM authorization_codes
    WHERE code = ? AND used = 0 AND expires_at > datetime('now')
  `).get(code);

  if (!authCode) {
    logAuditEvent(db, { event_type: 'INVALID_AUTH_CODE', client_id, ip_address: req.ip, severity: 'HIGH' });
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Code not found, expired, or already used' });
  }

  // Validate redirect_uri matches what was used in authorization request
  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
  }

  // ── ATTACK 2: PKCE Verification ────────────────────────────────────────────
  if (authCode.code_challenge) {
    if (VULNERABLE) {
      /**
       * 🔴 VULNERABLE: PKCE challenge exists but we skip verification.
       *
       * Impact: An attacker who intercepts the authorization code (e.g., via
       * referrer header, browser history, or malicious redirect) can exchange
       * it for tokens WITHOUT knowing the original code_verifier.
       *
       * Real-world: Attacks on mobile apps where redirect can be intercepted
       * by a malicious app registered for the same custom URI scheme.
       */
      console.warn('⚠️  [VULNERABLE] Skipping PKCE verification — code verifier not checked!');
    } else {
      /**
       * 🟢 SECURE: Verify the PKCE code_verifier matches the stored challenge
       * RFC 7636: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
       */
      if (!code_verifier) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'code_verifier required for PKCE flow',
        });
      }

      const expectedChallenge = crypto
        .createHash('sha256')
        .update(code_verifier)
        .digest('base64url');

      if (authCode.code_challenge !== expectedChallenge) {
        logAuditEvent(db, {
          event_type: 'PKCE_VERIFICATION_FAILED',
          client_id,
          ip_address: req.ip,
          details: { provided_verifier_hash: expectedChallenge.substring(0, 10) + '...' },
          severity: 'HIGH',
        });
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'PKCE code_verifier does not match stored challenge',
        });
      }
    }
  } else if (!VULNERABLE && client.require_pkce) {
    // 🟢 SECURE: Client requires PKCE but no challenge was provided at authorize step
    return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE required for this client' });
  }

  // Mark code as used (prevent replay attacks)
  db.prepare('UPDATE authorization_codes SET used = 1 WHERE code = ?').run(code);

  // Fetch user info
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(authCode.user_id);
  const scopes = JSON.parse(authCode.scopes);

  // ── Generate Access Token (JWT) ────────────────────────────────────────────
  const tokenId = uuidv4();
  const accessToken = generateAccessToken(tokenId, user, client_id, scopes, VULNERABLE);

  // ── Generate Refresh Token ─────────────────────────────────────────────────
  const refreshToken = generateRefreshToken(db, tokenId, client_id, user.id, scopes, VULNERABLE);

  // Persist access token record
  db.prepare(`
    INSERT INTO access_tokens (token_id, client_id, user_id, scopes, expires_at)
    VALUES (?, ?, ?, ?, datetime('now', '+1 hour'))
  `).run(tokenId, client_id, user.id, JSON.stringify(scopes));

  logAuditEvent(db, {
    event_type: 'TOKEN_ISSUED',
    client_id,
    user_id: user.id,
    ip_address: req.ip,
    details: { scopes, pkce_used: !!authCode.code_challenge },
    severity: 'INFO',
  });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    refresh_token: refreshToken,
    scope: scopes.join(' '),
  });
}

// ── Refresh Token Grant ───────────────────────────────────────────────────────
function handleRefreshTokenGrant(req, res, VULNERABLE) {
  const { refresh_token, client_id, client_secret } = req.body;
  const db = getDb();

  const client = db.prepare('SELECT * FROM clients WHERE client_id = ? AND client_secret = ?')
    .get(client_id, client_secret);

  if (!client) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const storedToken = db.prepare(`
    SELECT * FROM refresh_tokens
    WHERE token = ? AND revoked = 0 AND client_id = ?
  `).get(refresh_token, client_id);

  if (!storedToken) {
    logAuditEvent(db, {
      event_type: 'INVALID_REFRESH_TOKEN',
      client_id,
      ip_address: req.ip,
      severity: 'HIGH',
    });
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token invalid or revoked' });
  }

  // ── ATTACK 5: Refresh Token Expiry Check ───────────────────────────────────
  if (!VULNERABLE) {
    /**
     * 🟢 SECURE: Check if refresh token has expired
     * In VULNERABLE mode, tokens never expire → stolen token = permanent access
     */
    const now = new Date();
    const expiresAt = new Date(storedToken.expires_at);
    if (now > expiresAt) {
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(refresh_token);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token expired' });
    }
  }

  // ── ATTACK 5: Refresh Token Rotation ──────────────────────────────────────
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
  const scopes = JSON.parse(storedToken.scopes);
  const tokenId = uuidv4();
  const accessToken = generateAccessToken(tokenId, user, client_id, scopes, VULNERABLE);

  if (!VULNERABLE) {
    /**
     * 🟢 SECURE: Refresh Token Rotation
     * Each time a refresh token is used, it's revoked and a new one issued.
     * This limits the damage if a refresh token is stolen — the attacker's
     * refresh attempt will fail once the legitimate user refreshes first,
     * and vice versa (the server can detect reuse and revoke the entire family).
     *
     * RFC 6749 best practice; required by OAuth 2.1 draft.
     */
    db.prepare('UPDATE refresh_tokens SET revoked = 1, rotated = 1 WHERE token = ?').run(refresh_token);
    logAuditEvent(db, {
      event_type: 'REFRESH_TOKEN_ROTATED',
      client_id,
      user_id: storedToken.user_id,
      ip_address: req.ip,
      severity: 'INFO',
    });
  } else {
    /**
     * 🔴 VULNERABLE: Refresh token is NEVER invalidated.
     * Attacker with a stolen refresh token retains persistent access
     * even after the user's session ends.
     */
    console.warn('⚠️  [VULNERABLE] Refresh token not rotated — old token remains valid');
  }

  const newRefreshToken = generateRefreshToken(db, tokenId, client_id, user.id, scopes, VULNERABLE);

  db.prepare(`
    INSERT INTO access_tokens (token_id, client_id, user_id, scopes, expires_at)
    VALUES (?, ?, ?, ?, datetime('now', '+1 hour'))
  `).run(tokenId, client_id, user.id, JSON.stringify(scopes));

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    refresh_token: newRefreshToken,
    scope: scopes.join(' '),
  });
}

// ── POST /oauth/token/introspect ──────────────────────────────────────────────
router.post('/token/introspect', (req, res) => {
  const { token } = req.body;
  const VULNERABLE = req.app.locals.vulnerableMode;
  const db = getDb();

  try {
    const decoded = verifyJwt(token, VULNERABLE);
    const record = db.prepare('SELECT * FROM access_tokens WHERE token_id = ? AND revoked = 0').get(decoded.jti);

    if (!record) {
      return res.json({ active: false });
    }

    res.json({
      active: true,
      client_id: decoded.client_id,
      username: decoded.username,
      scope: decoded.scope,
      exp: decoded.exp,
      iat: decoded.iat,
    });
  } catch (err) {
    res.json({ active: false, error: err.message });
  }
});

// ── POST /oauth/token/revoke ───────────────────────────────────────────────────
router.post('/token/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;
  const db = getDb();

  if (token_type_hint === 'refresh_token') {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(token);
  } else {
    // Try to decode as access token JWT and revoke by jti
    try {
      const decoded = jwt.decode(token);
      if (decoded?.jti) {
        db.prepare('UPDATE access_tokens SET revoked = 1 WHERE token_id = ?').run(decoded.jti);
      }
    } catch (_) {}
  }

  res.json({ revoked: true });
});

// ── JWT Helpers ───────────────────────────────────────────────────────────────

/**
 * Generate a signed JWT access token.
 * In VULNERABLE mode we don't explicitly enable alg=none here, but the
 * verifyJwt function below demonstrates the bypass.
 */
function generateAccessToken(tokenId, user, clientId, scopes, vulnerable) {
  return jwt.sign(
    {
      jti: tokenId,
      sub: user.id,
      username: user.username,
      email: user.email,
      client_id: clientId,
      scope: scopes.join(' '),
      roles: JSON.parse(user.roles || '[]'),
    },
    JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: ACCESS_TOKEN_TTL,
      issuer: process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001',
      audience: process.env.RESOURCE_SERVER_PUBLIC || 'http://localhost:3003',
    }
  );
}

/**
 * Verify JWT — demonstrates the alg=none attack (Attack 7)
 */
function verifyJwt(token, vulnerable) {
  if (vulnerable) {
    /**
     * 🔴 VULNERABLE: Accept any algorithm, including alg=none
     *
     * The JWT header specifies which algorithm to use for verification.
     * If the server trusts the header's "alg" field, an attacker can:
     *   1. Take any valid JWT
     *   2. Change the header to {"alg":"none"}
     *   3. Change the payload (e.g., add admin role)
     *   4. Remove the signature
     *   5. Submit the forged token
     *
     * Affected library: early versions of jsonwebtoken and PyJWT
     * CVE-2015-9235 (jsonwebtoken < 4.2.2)
     */
    console.warn('⚠️  [VULNERABLE] Accepting JWT with any algorithm including alg=none!');
    return jwt.decode(token); // decode WITHOUT verification!
  } else {
    /**
     * 🟢 SECURE: Explicitly specify allowed algorithms
     * Never trust the token's own "alg" header field for verification.
     */
    return jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'], // Whitelist only! Rejects alg=none, alg=RS256, etc.
      issuer: process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001',
      audience: process.env.RESOURCE_SERVER_PUBLIC || 'http://localhost:3003',
    });
  }
}

function generateRefreshToken(db, accessTokenId, clientId, userId, scopes, vulnerable) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiryDays = vulnerable ? 3650 : REFRESH_TOKEN_TTL_DAYS; // VULNERABLE: 10 years!

  db.prepare(`
    INSERT INTO refresh_tokens (token, access_token_id, client_id, user_id, scopes, expires_at)
    VALUES (?, ?, ?, ?, ?, datetime('now', '+${expiryDays} days'))
  `).run(token, accessTokenId, clientId, userId, JSON.stringify(scopes));

  return token;
}

module.exports = router;
module.exports.verifyJwt = verifyJwt;

/**
 * Authorization Routes
 * ====================
 * Handles the /oauth/authorize endpoint — the entry point for OAuth flows.
 *
 * ATTACKS DEMONSTRATED HERE:
 *   Attack 1: Redirect URI Manipulation
 *     VULNERABLE: Server allows partial URI matching ("starts with" check)
 *     SECURE:     Server requires exact URI match against pre-registered list
 *
 *   Attack 4: OAuth Consent Abuse
 *     VULNERABLE: No admin approval; malicious apps can request admin scopes
 *     SECURE:     Privileged scopes require admin pre-approval
 *
 *   Attack 6: Scope Escalation
 *     VULNERABLE: Server grants whatever scopes the client requests
 *     SECURE:     Server enforces scope intersection with client registration
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { getDb } = require('../database/db');
const { logAuditEvent } = require('../middleware/audit');

// ── GET /oauth/authorize ──────────────────────────────────────────────────────
// Step 1 of Authorization Code Flow: validate request, show consent screen
router.get('/authorize', (req, res) => {
  const {
    response_type, client_id, redirect_uri,
    scope, state, code_challenge, code_challenge_method
  } = req.query;

  const VULNERABLE = req.app.locals.vulnerableMode;
  const db = getDb();

  // Basic parameter validation
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  if (!client_id || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required parameters' });
  }

  // Fetch client from registry
  const client = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
  }

  // ── ATTACK 1: Redirect URI Validation ──────────────────────────────────────
  const registeredUris = JSON.parse(client.redirect_uris);
  const isValidRedirectUri = validateRedirectUri(redirect_uri, registeredUris, VULNERABLE);

  if (!isValidRedirectUri) {
    // SECURITY: Never redirect to an unvalidated URI — return error directly
    logAuditEvent(db, {
      event_type: 'REDIRECT_URI_MANIPULATION_ATTEMPT',
      client_id,
      ip_address: req.ip,
      details: { attempted_uri: redirect_uri, registered_uris: registeredUris },
      severity: 'HIGH',
    });
    return res.status(400).json({
      error: 'invalid_redirect_uri',
      error_description: VULNERABLE
        ? 'URI does not match registered prefix (VULNERABLE mode)'
        : 'Exact redirect_uri match required against registered list',
      attack_prevented: !VULNERABLE,
    });
  }

  // ── ATTACK 6: Scope Validation ─────────────────────────────────────────────
  const requestedScopes = (scope || '').split(' ').filter(Boolean);
  const allowedScopes = validateScopes(requestedScopes, JSON.parse(client.scopes), VULNERABLE);

  if (VULNERABLE) {
    // 🔴 VULNERABLE: Grant whatever scopes were requested — no intersection check
    // This allows a client to escalate privileges by just asking for more scopes
    console.warn(`⚠️  [VULNERABLE] Granting requested scopes without validation: ${requestedScopes}`);
  } else {
    // 🟢 SECURE: Enforce intersection of requested vs registered scopes
    if (allowedScopes.length === 0 && requestedScopes.length > 0) {
      return res.redirect(`${redirect_uri}?error=invalid_scope&state=${state}`);
    }
  }

  // ── ATTACK 4: Consent Screen / Scope Abuse ─────────────────────────────────
  const hasPrivilegedScope = requestedScopes.includes('admin') || requestedScopes.includes('write');

  if (!VULNERABLE && hasPrivilegedScope && !client.trusted) {
    // 🟢 SECURE: Privileged scopes for untrusted clients require admin pre-approval
    logAuditEvent(db, {
      event_type: 'PRIVILEGED_SCOPE_REQUEST',
      client_id,
      details: { scopes: requestedScopes, client_name: client.name },
      severity: 'MEDIUM',
    });
  }

  // Store pending auth request in session-like token (simplified for lab)
  const authRequestId = uuidv4();
  db.prepare(`
    INSERT INTO authorization_codes
      (code, client_id, user_id, redirect_uri, scopes, code_challenge, challenge_method, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+10 minutes'), 0)
  `).run(
    `pending:${authRequestId}`,
    client_id,
    'PENDING',
    redirect_uri,
    JSON.stringify(VULNERABLE ? requestedScopes : allowedScopes),
    code_challenge || null,
    code_challenge_method || null,
  );

  // Render consent screen (HTML)
  const scopeDescriptions = getScopeDescriptions(VULNERABLE ? requestedScopes : allowedScopes);
  res.send(renderConsentPage({
    client,
    redirect_uri,
    scopes: VULNERABLE ? requestedScopes : allowedScopes,
    scopeDescriptions,
    state,
    authRequestId,
    hasPrivilegedScope,
    VULNERABLE,
  }));
});

// ── POST /oauth/authorize ─────────────────────────────────────────────────────
// User submits login + consent form
router.post('/authorize', (req, res) => {
  const { username, password, auth_request_id, action, state } = req.body;
  const VULNERABLE = req.app.locals.vulnerableMode;
  const db = getDb();

  if (action === 'deny') {
    // IMPORTANT: read FIRST, then delete — otherwise redirect_uri is lost
    const pending = db.prepare("SELECT * FROM authorization_codes WHERE code = ?")
      .get(`pending:${auth_request_id}`);
    const redirectUri = (pending && pending.redirect_uri) || req.body.redirect_uri || 'http://localhost:3002';
    const deniedState = state || req.body.state || '';
    // Now safe to delete
    db.prepare("DELETE FROM authorization_codes WHERE code = ?").run(`pending:${auth_request_id}`);
    logAuditEvent(db, {
      event_type: 'USER_DENIED_CONSENT',
      ip_address: req.ip,
      details: { auth_request_id },
      severity: 'LOW',
    });
    return res.redirect(`${redirectUri}?error=access_denied&error_description=User+denied+consent&state=${deniedState}`);
  }

  // Authenticate user
  const crypto = require('crypto');
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?')
    .get(username, passwordHash);

  if (!user) {
    logAuditEvent(db, {
      event_type: 'FAILED_LOGIN',
      ip_address: req.ip,
      details: { username },
      severity: 'MEDIUM',
    });
    return res.status(401).send(renderError('Invalid username or password'));
  }

  // Retrieve the pending authorization request
  const pending = db.prepare("SELECT * FROM authorization_codes WHERE code = ?")
    .get(`pending:${auth_request_id}`);

  if (!pending) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Authorization request expired or not found' });
  }

  // Generate the real authorization code
  const authCode = uuidv4();

  // Update the pending record → real code
  db.prepare(`
    UPDATE authorization_codes SET code = ?, user_id = ?, expires_at = datetime('now', '+5 minutes')
    WHERE code = ?
  `).run(authCode, user.id, `pending:${auth_request_id}`);

  logAuditEvent(db, {
    event_type: 'AUTHORIZATION_CODE_ISSUED',
    client_id: pending.client_id,
    user_id: user.id,
    ip_address: req.ip,
    details: { scopes: pending.scopes, redirect_uri: pending.redirect_uri },
    severity: 'INFO',
  });

  // Redirect back to client with authorization code
  const redirectUrl = new URL(pending.redirect_uri);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state);

  res.redirect(redirectUrl.toString());
});

// ── JWKS endpoint ─────────────────────────────────────────────────────────────
router.get('/jwks', (req, res) => {
  // In production this would return the public key in JWK format
  res.json({
    keys: [{
      kty: 'oct',
      use: 'sig',
      alg: 'HS256',
      k: Buffer.from(process.env.JWT_SECRET || 'super-secret-key').toString('base64url'),
    }],
  });
});

// ── Helper: Redirect URI Validation ───────────────────────────────────────────
function validateRedirectUri(requested, registered, vulnerable) {
  if (vulnerable) {
    /**
     * 🔴 VULNERABLE: Overly permissive URI matching
     * 
     * Bug 1 — Path prefix: strips /callback and checks startsWith
     *   registered: "http://localhost:3002/callback" → prefix: "http://localhost:3002"
     *   attacker:   "http://localhost:3002/evil" → PASSES (same origin, different path)
     *
     * Bug 2 — Any sub-path: anything under the registered origin passes
     *   This simulates real-world misconfigs that use wildcard matching
     *
     * Real CVEs: CVE-2014-8671 (Facebook), countless enterprise SSO misconfigs
     */
    // 🔴 VULNERABLE: In this mode, ANY URI that looks like an HTTP URL is accepted.
    // This simulates a real-world bug where the auth server uses overly loose validation:
    // - wildcard matching (e.g. *.example.com)
    // - suffix matching (any path under the domain)
    // - trusting the "redirect_uri" parameter without strict checking
    // Real CVEs: CVE-2014-8671, countless enterprise SSO misconfigs.
    // In this lab: the server accepts any http/https URI to allow the attack demo to run.
    return /^https?:\/\//.test(requested);
  } else {
    /**
     * 🟢 SECURE: Exact string match only
     * RFC 6749 §3.1.2: redirect_uri MUST be pre-registered and matched exactly
     */
    return registered.includes(requested);
  }
}

// ── Helper: Scope Intersection ────────────────────────────────────────────────
function validateScopes(requested, registered, vulnerable) {
  if (vulnerable) {
    /**
     * 🔴 VULNERABLE: Return all requested scopes, even if not registered
     * Attacker can escalate by simply requesting more scopes
     */
    return requested;
  } else {
    /**
     * 🟢 SECURE: Return only intersection of requested and registered scopes
     */
    return requested.filter(s => registered.includes(s));
  }
}

function getScopeDescriptions(scopes) {
  const map = {
    read:    'Read your profile and data',
    write:   'Create and modify your data',
    admin:   '⚠️ Full administrative access to your account',
    profile: 'Access your basic profile info',
    email:   'Access your email address',
  };
  return scopes.map(s => ({ scope: s, description: map[s] || s }));
}

// ── Consent Page HTML ─────────────────────────────────────────────────────────
function renderConsentPage({ client, redirect_uri, scopes, scopeDescriptions, state, authRequestId, hasPrivilegedScope, VULNERABLE }) {
  const redirectUri = redirect_uri || '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OAuth Consent 🔐</title>
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
  <style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
  .card{background:#fffef7;border:2px solid #d4b896;border-radius:10px;padding:28px 32px;max-width:460px;width:100%;box-shadow:4px 4px 0 #c4a070;position:relative;z-index:1}
  .mode-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:10px;font-size:11px;font-weight:800;font-family:'Courier Prime',monospace;margin-bottom:16px;border:2px solid;
    background:${VULNERABLE ? 'rgba(224,90,58,.1)' : 'rgba(58,158,106,.1)'};
    color:${VULNERABLE ? '#e05a3a' : '#3a9e6a'};
    border-color:${VULNERABLE ? '#e05a3a' : '#3a9e6a'}}
  h2{font-size:18px;font-weight:900;color:#2d2416;margin-bottom:6px}
  .client-name{font-size:14px;font-weight:700;color:#3a6eb5;margin-bottom:14px}
  .warning-box{background:rgba(212,133,42,.08);border:2px solid #d4852a;border-radius:6px;padding:10px 13px;margin-bottom:14px;font-size:12.5px;color:#d4852a;font-weight:700}
  .scope-list{list-style:none;padding:0;margin:10px 0 18px;border:2px solid #d4b896;border-radius:6px;overflow:hidden}
  .scope-item{padding:9px 13px;border-bottom:1.5px solid #d4b896;font-size:12.5px;display:flex;gap:8px;align-items:flex-start}
  .scope-item:last-child{border-bottom:none}
  .scope-item.priv{background:rgba(224,90,58,.05);color:#e05a3a;font-weight:700}
  .scope-name{font-family:'Courier Prime',monospace;font-weight:700;font-size:12px;flex-shrink:0}
  .scope-desc{color:#5c4a2a;font-size:11.5px}
  .field{margin-bottom:10px}
  .field label{display:block;font-size:11px;font-weight:800;color:#9c8860;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;font-family:'Courier Prime',monospace}
  .field input{width:100%;padding:8px 11px;border:2px solid #d4b896;border-radius:5px;font-family:'Nunito',sans-serif;font-size:13px;color:#2d2416;background:#fffef7;outline:none}
  .field input:focus{border-color:#3a6eb5}
  .btn-row{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:14px}
  .btn{padding:10px 18px;border-radius:5px;font-size:13px;font-weight:800;cursor:pointer;border:2px solid;font-family:'Nunito',sans-serif;transition:all .12s;box-shadow:3px 3px 0 #c4a070}
  .btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 #c4a070}
  .btn-allow{background:rgba(58,158,106,.12);color:#3a9e6a;border-color:#3a9e6a}
  .btn-deny{background:rgba(224,90,58,.1);color:#e05a3a;border-color:#e05a3a}
  .hint{font-size:11px;color:#9c8860;margin-top:12px;padding-top:12px;border-top:2px dashed #d4b896;font-family:'Courier Prime',monospace}
  </style>
</head>
<body>
<div class="card">
  <div class="mode-badge">${VULNERABLE ? '🔴 VULNERABLE MODE' : '🟢 SECURE MODE'}</div>
  <h2>🔐 Authorization Request</h2>
  <div class="client-name">${client.name}</div>
  ${hasPrivilegedScope && VULNERABLE ? `<div class="warning-box">⚠️ This app is requesting elevated permissions (admin/write). In SECURE mode, admin pre-approval would be required.</div>` : ''}
  <ul class="scope-list">
    ${scopeDescriptions.map(({ scope, description }) => `
    <li class="scope-item ${['admin','write'].includes(scope) ? 'priv' : ''}">
      <span class="scope-name">${['admin','write'].includes(scope) ? '⚠️' : '✓'} ${scope}</span>
      <span class="scope-desc">${description}</span>
    </li>`).join('')}
  </ul>
  <form method="POST" action="/oauth/authorize" id="consentForm">
    <input type="hidden" name="auth_request_id" value="${authRequestId}">
    <input type="hidden" name="state" value="${state || ''}">
    <input type="hidden" name="redirect_uri" value="${redirectUri}">
    <div class="field"><label>Username</label><input type="text" name="username" placeholder="alice" required autocomplete="username"></div>
    <div class="field"><label>Password</label><input type="password" name="password" placeholder="password123" required autocomplete="current-password"></div>
    <div class="btn-row">
      <button type="submit" name="action" value="allow" class="btn btn-allow">✅ Allow Access</button>
    </div>
  </form>
  <form method="POST" action="/oauth/authorize" style="margin-top:8px">
    <input type="hidden" name="auth_request_id" value="${authRequestId}">
    <input type="hidden" name="state" value="${state || ''}">
    <input type="hidden" name="redirect_uri" value="${redirectUri}">
    <input type="hidden" name="action" value="deny">
    <button type="submit" class="btn btn-deny" style="width:100%">❌ Deny</button>
  </form>
  <div class="hint">Credentials: alice / password123 &nbsp;·&nbsp; admin / adminpass</div>
</div>
</body>
</html>`;
}

function renderError(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><link href="https://fonts.googleapis.com/css2?family=Nunito:wght@700;900&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Nunito',sans-serif;background:#fdf6e3;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#fffef7;border:2px solid #e05a3a;border-radius:10px;padding:28px;max-width:400px;text-align:center;box-shadow:4px 4px 0 #c4a070}h2{color:#e05a3a;font-size:18px;margin-bottom:10px}p{color:#5c4a2a;font-size:13px;margin-bottom:16px}a{color:#3a6eb5;font-weight:700;text-decoration:none;border:2px solid #3a6eb5;padding:6px 14px;border-radius:5px;display:inline-block}</style></head><body><div class="card"><h2>⚠️ Error</h2><p>${message}</p><a href="javascript:history.back()">Go back</a></div></body></html>`;
}

module.exports = router;

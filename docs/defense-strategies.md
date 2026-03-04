# OAuth Defense Strategies

## Defense-in-Depth Overview

No single control prevents all OAuth attacks. Production systems layer multiple defenses:

```
Layer 1: Protocol Compliance (RFC 6749, RFC 7636, OAuth 2.1)
  └─ Exact redirect URI matching
  └─ PKCE required for all flows
  └─ State parameter for CSRF prevention

Layer 2: Token Security
  └─ Short-lived access tokens (< 1 hour)
  └─ Refresh token rotation
  └─ JWT algorithm whitelist (alg: HS256 or RS256 only)
  └─ HttpOnly, Secure, SameSite cookie storage

Layer 3: Authorization Controls
  └─ Scope intersection enforcement
  └─ Privileged scope approval workflows
  └─ Principle of least privilege by default

Layer 4: Detection & Response
  └─ Audit logging all auth events
  └─ Anomaly detection (rapid refresh, impossible travel)
  └─ Refresh token reuse detection → family revocation
  └─ SIEM integration for real-time alerting
```

## Checklist for Production OAuth

### Authorization Server
- [ ] Exact redirect URI matching (no wildcards, no prefix match)
- [ ] PKCE required (S256 only, not plain) for all public clients
- [ ] State parameter validated on callback
- [ ] Authorization codes expire in ≤ 5 minutes
- [ ] Authorization codes are single-use (mark used on exchange)
- [ ] Scope intersection enforced
- [ ] Privileged scopes require admin approval
- [ ] Comprehensive audit logging

### Token Management
- [ ] Access tokens expire in ≤ 1 hour
- [ ] Refresh tokens expire in ≤ 30 days
- [ ] Refresh token rotation enabled
- [ ] Refresh token reuse detection + family revocation
- [ ] Token revocation endpoint implemented
- [ ] JWT signed with RS256 (asymmetric) in production
- [ ] JWT verified with algorithm whitelist
- [ ] `iss` and `aud` claims validated

### Client Application
- [ ] Tokens stored in HttpOnly, Secure, SameSite=Strict cookies
- [ ] Never store tokens in localStorage or sessionStorage
- [ ] PKCE implemented for all authorization requests
- [ ] State parameter generated per-request (random, unpredictable)
- [ ] Content Security Policy (CSP) to mitigate XSS
- [ ] Subresource Integrity (SRI) for third-party scripts

### Resource Server
- [ ] JWT signature verified (never use decode-only)
- [ ] Algorithm whitelist enforced
- [ ] `iss`, `aud`, `exp` claims validated
- [ ] Scope-based access control on every endpoint
- [ ] Token introspection for non-JWT tokens

## HS256 vs RS256 Recommendation

| | HS256 (Symmetric) | RS256 (Asymmetric) |
|-|-------------------|--------------------|
| Key type | Shared secret | Private/public key pair |
| Who can verify? | Anyone with secret | Anyone with public key |
| Secret distribution | Every service needs secret | Only auth server has private key |
| alg=none risk | High (secret must be kept) | Lower (public key is public) |
| **Recommendation** | Dev/internal only | **Production** |

For production: Use RS256. Auth server signs with private key. Resource servers verify with public key from JWKS endpoint.

## Incident Response for OAuth Compromise

```
1. Identify: Which tokens are affected?
   → Audit log: client_id, user_id, issued_at range

2. Contain: Revoke all tokens for affected users/clients
   → POST /oauth/token/revoke
   → Invalidate entire refresh token families

3. Eradicate: Fix the vulnerability
   → Deploy secure mode configuration
   → Rotate signing keys if JWT secret was compromised

4. Recover: Force re-authentication
   → Notify affected users
   → Require password reset if credentials were exposed

5. Post-mortem: Update detection rules
   → Add monitoring for the specific attack pattern observed
```

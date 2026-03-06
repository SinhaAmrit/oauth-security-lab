# 🔐 OAuth Security Attack Simulation Lab

> Built by [SinhaAmrit](https://github.com/SinhaAmrit)

A self-contained Docker environment for learning OAuth 2.0 vulnerabilities through live simulation. Seven real-world attacks, each with a **VULNERABLE mode** (attack works) and a **SECURE mode** (mitigation active) you can toggle with a single environment variable.

---

## Quick Start

```bash
git clone https://github.com/SinhaAmrit/oauth-security-lab.git
cd oauth-security-lab

# VULNERABLE mode (default — all 7 attacks work)
docker compose up

# SECURE mode (all mitigations active — attacks blocked)
VULNERABLE_MODE=false docker compose up
```

Open **http://localhost:3002** — the home page explains what the lab is and has links to everything.

---

## Custom Domain Deployment

When deploying to your own server, pass the public URLs as environment variables:

```bash
CLIENT_BASE_URL=https://oauth.yourdomain.com \
AUTH_SERVER_PUBLIC=https://oauth.yourdomain.com:3001 \
RESOURCE_SERVER_PUBLIC=https://oauth.yourdomain.com:3003 \
ATTACKER_BASE_URL=https://oauth.yourdomain.com:3004 \
MONITOR_BASE_URL=https://oauth.yourdomain.com:3005 \
docker compose up
```

All URLs in the home page, docs portal, attack guides, and JWT forge tool will update automatically.

---

## Services

| Port | Service | Description |
|------|---------|-------------|
| :3002 | **Client App** | Demo web app. Start OAuth flows here. Main entry point. |
| :3001 | **Auth Server** | Issues authorization codes and JWT access tokens |
| :3003 | **Resource API** | Protected REST API — validates JWTs, enforces scopes |
| :3004 | **Attacker Server** | Captures stolen codes/tokens. JWT forge tool. Phishing page. |
| :3005 | **Monitoring** | Live security event dashboard — detect attacks in real time |

---

## The 7 Attacks

| # | Attack | Vulnerable Behaviour | Secure Mitigation |
|---|--------|----------------------|-------------------|
| 1 | **Redirect URI Manipulation** | Partial URI match allows redirect hijack | Exact URI matching against registered list |
| 2 | **Auth Code Interception** | No PKCE — code exchangeable by attacker | PKCE S256 required; verifier checked server-side |
| 3 | **Token Leakage via XSS** | Token in `localStorage` — readable by injected JS | HttpOnly cookie — inaccessible to JavaScript |
| 4 | **OAuth Consent Abuse** | Malicious app requests admin scopes without review | Privileged scopes require admin pre-approval |
| 5 | **Refresh Token Abuse** | Refresh tokens never expire, no rotation | Short-lived tokens with automatic rotation |
| 6 | **Scope Escalation** | Server grants any scope the client requests | Server enforces intersection with registered scopes |
| 7 | **JWT alg=none** | Server accepts unsigned JWTs | `jwt.verify()` rejects non-HS256/RS256 algorithms |

---

## Architecture

```
Browser
  ├──► :3002  Client App       (Express — OAuth flows, PKCE, XSS demo)
  │       ├──► :3001  Auth Server    (Express — SQLite, JWT, audit log)
  │       └──► :3003  Resource API   (Express — JWT validation, scopes)
  ├──► :3004  Attacker Server   (Express — capture, phishing, JWT forge)
  └──► :3005  Monitoring        (Express — proxies auth-server audit log)
```

---

## Mode Toggle

```bash
VULNERABLE_MODE=false docker compose up
```

The toggle flips all 7 attack mitigations simultaneously.

---

## Files

```
oauth-security-lab/
├── auth-server/            Authorization Server (port 3001)
│   ├── src/
│   │   ├── server.js
│   │   ├── database/db.js
│   │   ├── middleware/audit.js
│   │   └── routes/{auth,token,admin}.js
│   ├── package.json
│   └── Dockerfile
├── client-app/             Client Application (port 3002)
│   ├── src/server.js
│   ├── public/index.html
│   ├── public/docs/        Attack lab portal
│   ├── package.json
│   └── Dockerfile
├── resource-server/        Protected Resource API (port 3003)
├── attacker-server/        Educational Attacker Infrastructure (port 3004)
├── monitoring-dashboard/   Security Event Dashboard (port 3005)
├── docs/                   Markdown reference + browser portal
├── check-integrity.js      Attribution enforcement
├── rebuild.sh              Full Docker teardown + rebuild
└── docker-compose.yml
```

---

## Legal Notice

This lab is for **educational use only**. All attack techniques are demonstrated
in a fully isolated local environment. Do not use these techniques against systems
you do not own or have explicit permission to test.

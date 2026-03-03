/**
 * Monitoring Dashboard Server
 * ============================
 * Aggregates and displays security events from the auth server.
 * Demonstrates how defenders can detect OAuth attacks via monitoring.
 */

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3005;
const AUTH_SERVER = process.env.AUTH_SERVER || 'http://localhost:3001';

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Proxy audit log from auth server
app.get('/api/audit-log', async (req, res) => {
  try {
    const response = await axios.get(`${AUTH_SERVER}/admin/audit-log`);
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tokens', async (req, res) => {
  try {
    const response = await axios.get(`${AUTH_SERVER}/admin/tokens`);
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/mode', async (req, res) => {
  try {
    const response = await axios.get(`${AUTH_SERVER}/admin/mode`);
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve the dashboard
app.get('/', (req, res) => {
  res.send(dashboardHTML());
});

function dashboardHTML() {
  return `<!DOCTYPE html>
<html>
<head>
  <title>OAuth Security Monitoring Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    @import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;700;800;900&family=Courier+Prime:wght@400;700&display=swap');
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Nunito',sans-serif;background:#fdf6e3;color:#2d2416;min-height:100vh}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;
      background-image:repeating-linear-gradient(0deg,transparent,transparent 27px,rgba(180,140,80,0.06) 28px)}
    .header{background:#fffef7;border-bottom:2px solid #d4b896;padding:14px 24px;
      display:flex;align-items:center;justify-content:space-between;position:relative;z-index:1;
      box-shadow:0 2px 0 #d4b896}
    .header h1{font-size:18px;font-weight:900;color:#2d2416}
    .header-right{display:flex;align-items:center;gap:12px}
    .mode-badge{padding:4px 12px;border-radius:10px;font-size:11px;font-weight:800;border:2px solid;font-family:'Courier Prime',monospace}
    .mode-vulnerable{background:rgba(224,90,58,.1);color:#e05a3a;border-color:#e05a3a}
    .mode-secure{background:rgba(58,158,106,.1);color:#3a9e6a;border-color:#3a9e6a}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:20px 24px;position:relative;z-index:1}
    .card{background:#fffef7;border:2px solid #d4b896;border-radius:8px;padding:18px;box-shadow:3px 3px 0 #c4a070}
    .card h3{font-size:10px;font-weight:800;color:#9c8860;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;font-family:'Courier Prime',monospace}
    .card .metric{font-size:34px;font-weight:900;color:#3a6eb5}
    .card .sub{font-size:11px;color:#9c8860;margin-top:4px}
    .section{padding:0 24px 20px;position:relative;z-index:1}
    .section h2{font-size:14px;font-weight:900;color:#2d2416;margin-bottom:12px;padding-bottom:8px;border-bottom:2px dashed #d4b896;display:flex;align-items:center;justify-content:space-between}
    table{width:100%;border-collapse:collapse;background:#fffef7;border:2px solid #d4b896;border-radius:8px;overflow:hidden;box-shadow:3px 3px 0 #c4a070}
    th{background:#fff9e8;padding:10px 12px;text-align:left;font-size:10px;font-weight:800;color:#9c8860;text-transform:uppercase;letter-spacing:.08em;border-bottom:2px solid #d4b896;font-family:'Courier Prime',monospace}
    td{padding:9px 12px;border-bottom:1.5px solid #e8dcc8;font-size:12.5px}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#fff9e8}
    .severity-HIGH{color:#e05a3a;font-weight:800}
    .severity-MEDIUM{color:#d4852a;font-weight:800}
    .severity-INFO{color:#3a6eb5}
    .severity-WARN{color:#d4852a}
    .severity-CRITICAL{color:#cc1a1a;font-weight:900}
    .event-type{font-family:'Courier Prime',monospace;font-size:10.5px;background:#f5f0e5;border:1px solid #d4b896;padding:2px 6px;border-radius:3px;color:#5c4a2a}
    .refresh-btn{background:#fffef7;color:#3a6eb5;border:2px solid #d4b896;padding:5px 14px;
      border-radius:5px;cursor:pointer;font-size:11px;font-weight:800;font-family:'Nunito',sans-serif;
      box-shadow:2px 2px 0 #c4a070;transition:all .12s}
    .refresh-btn:hover{transform:translate(-1px,-1px);box-shadow:3px 3px 0 #c4a070}
    #refreshTimer{color:#9c8860;font-size:11px;font-family:'Courier Prime',monospace}
    .alert-panel{background:rgba(224,90,58,.05);border:2px solid #e05a3a;border-radius:8px;padding:14px;
      margin:0 24px 18px;box-shadow:3px 3px 0 rgba(224,90,58,.2);position:relative;z-index:1}
    .alert-panel h3{color:#e05a3a;margin-bottom:8px;font-size:13px;font-weight:900}
    .alert-item{padding:4px 0;color:#5c4a2a;font-size:12px;font-family:'Courier Prime',monospace}
    .home-link{color:#3a6eb5;font-weight:800;text-decoration:none;font-size:12px;border:1.5px solid #d4b896;padding:3px 10px;border-radius:5px}
    .home-link:hover{border-color:#3a6eb5;background:rgba(58,110,181,.05)}
  </style>
</head>
<body>
  <div class="header">
    <div style="display:flex;align-items:center;gap:12px">
      <a href="http://localhost:3002/" style="font-weight:900;font-size:14px;color:#2d2416;text-decoration:none;background:#e8c840;border:2px solid #2d2416;padding:3px 10px;border-radius:4px;box-shadow:2px 2px 0 #c4a070;transform:rotate(-1deg);display:inline-block">🔐 OAuth Lab</a>
      <a href="http://localhost:3002/lab" class="home-link">📚 Attack Lab</a>
      <a href="http://localhost:3002/login" class="home-link">👤 Client App</a>
      <h1 style="font-size:15px;font-weight:900;color:#2d2416">📊 Security Monitoring</h1>
    </div>
    <div class="header-right">
      <span id="refreshTimer">Auto-refreshing in 10s</span>
      <button class="refresh-btn" onclick="loadAll()">🔄 Refresh</button>
      <div id="modeBadge" class="mode-badge"></div>
    </div>
  </div>

  <!-- Metrics Grid -->
  <div class="grid">
    <div class="card">
      <h3>Total Events</h3>
      <div class="metric" id="totalEvents">—</div>
      <div class="sub">All audit events</div>
    </div>
    <div class="card">
      <h3>High Severity</h3>
      <div class="metric" id="highEvents" style="color:#ff6b6b">—</div>
      <div class="sub">Security alerts</div>
    </div>
    <div class="card">
      <h3>Active Tokens</h3>
      <div class="metric" id="activeTokens">—</div>
      <div class="sub">Access tokens issued</div>
    </div>
    <div class="card">
      <h3>Attack Indicators</h3>
      <div class="metric" id="attackIndicators" style="color:#ffa94d">—</div>
      <div class="sub">Suspicious patterns</div>
    </div>
  </div>

  <!-- Alerts -->
  <div id="alertPanel" class="alert-panel" style="display:none">
    <h3>⚠️ Active Security Alerts</h3>
    <div id="alertList"></div>
  </div>

  <!-- Audit Log -->
  <div class="section">
    <h2>📋 Security Audit Log</h2>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Event Type</th>
          <th>Client</th>
          <th>Severity</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="auditTableBody">
        <tr><td colspan="5" style="text-align:center;color:#666">Loading...</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Active Tokens -->
  <div class="section">
    <h2>🎫 Access Token Registry</h2>
    <table>
      <thead>
        <tr>
          <th>Token ID</th>
          <th>Client</th>
          <th>User</th>
          <th>Scopes</th>
          <th>Expires</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="tokensTableBody">
        <tr><td colspan="6" style="text-align:center;color:#666">Loading...</td></tr>
      </tbody>
    </table>
  </div>

  <div style="height:40px"></div>

  <script>
    let countdown = 10;

    const ATTACK_EVENT_TYPES = [
      'REDIRECT_URI_MANIPULATION_ATTEMPT',
      'PKCE_VERIFICATION_FAILED',
      'INVALID_AUTH_CODE',
      'INVALID_CLIENT_AUTH',
      'PRIVILEGED_SCOPE_REQUEST',
      'INVALID_REFRESH_TOKEN',
      'FAILED_LOGIN',
    ];

    async function loadAll() {
      await Promise.all([loadMode(), loadAuditLog(), loadTokens()]);
      countdown = 10;
    }

    async function loadMode() {
      try {
        const res = await fetch('/api/mode');
        const data = await res.json();
        const badge = document.getElementById('modeBadge');
        badge.textContent = data.mode;
        badge.className = 'mode-badge ' + (data.vulnerable ? 'mode-vulnerable' : 'mode-secure');
      } catch (_) {}
    }

    async function loadAuditLog() {
      try {
        const res = await fetch('/api/audit-log');
        const events = await res.json();

        const attackEvents = events.filter(e => ATTACK_EVENT_TYPES.includes(e.event_type));
        const highEvents = events.filter(e => e.severity === 'HIGH');

        document.getElementById('totalEvents').textContent = events.length;
        document.getElementById('highEvents').textContent = highEvents.length;
        document.getElementById('attackIndicators').textContent = attackEvents.length;

        // Show alert panel if attacks detected
        if (attackEvents.length > 0) {
          document.getElementById('alertPanel').style.display = 'block';
          document.getElementById('alertList').innerHTML = attackEvents.slice(0, 5).map(e =>
            '<div class="alert-item">⚠️ ' + e.event_type + ' detected at ' + new Date(e.timestamp).toLocaleTimeString() + '</div>'
          ).join('');
        }

        const tbody = document.getElementById('auditTableBody');
        tbody.innerHTML = events.map(e => {
          const isAttack = ATTACK_EVENT_TYPES.includes(e.event_type);
          return '<tr' + (isAttack ? ' style="background:#2a1a1a"' : '') + '>' +
            '<td style="color:#888;font-size:12px">' + new Date(e.timestamp).toLocaleString() + '</td>' +
            '<td><span class="event-type">' + e.event_type + '</span></td>' +
            '<td style="color:#aaa">' + (e.client_id || '—') + '</td>' +
            '<td class="severity-' + e.severity + '">' + e.severity + '</td>' +
            '<td style="font-size:12px;color:#777">' + (e.details ? JSON.stringify(e.details).substring(0, 80) + '...' : '—') + '</td>' +
            '</tr>';
        }).join('');
      } catch (err) {
        document.getElementById('auditTableBody').innerHTML =
          '<tr><td colspan="5" style="color:#ff6b6b">Error loading audit log: ' + err.message + '</td></tr>';
      }
    }

    async function loadTokens() {
      try {
        const res = await fetch('/api/tokens');
        const tokens = await res.json();

        document.getElementById('activeTokens').textContent = tokens.filter(t => !t.revoked).length;

        const tbody = document.getElementById('tokensTableBody');
        tbody.innerHTML = tokens.map(t => {
          const expired = new Date(t.expires_at) < new Date();
          const status = t.revoked ? '🚫 Revoked' : expired ? '⏰ Expired' : '✅ Active';
          const scopes = JSON.parse(t.scopes || '[]');
          const hasAdminScope = scopes.includes('admin');
          return '<tr' + (hasAdminScope ? ' style="background:#2a1a1a"' : '') + '>' +
            '<td style="font-family:monospace;font-size:11px;color:#888">' + t.token_id.substring(0,8) + '...</td>' +
            '<td>' + t.client_id + '</td>' +
            '<td>' + (t.username || t.user_id?.substring(0,8) || '—') + '</td>' +
            '<td>' + scopes.map(s => '<span style="background:#1f3a5f;padding:2px 6px;border-radius:3px;margin-right:3px;font-size:11px;color:' + (s==='admin'?'#ff6b6b':'#69b4ff') + '">' + s + '</span>').join('') + '</td>' +
            '<td style="font-size:12px;color:#888">' + new Date(t.expires_at).toLocaleString() + '</td>' +
            '<td>' + status + '</td>' +
            '</tr>';
        }).join('');
      } catch (_) {}
    }

    // Auto-refresh countdown
    setInterval(() => {
      countdown--;
      document.getElementById('refreshTimer').textContent = 'Auto-refreshing in ' + countdown + 's';
      if (countdown <= 0) loadAll();
    }, 1000);

    loadAll();
  </script>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`\n📊 Monitoring Dashboard running on port ${PORT}`);
  console.log(`   Open: http://localhost:${PORT}\n`);
});

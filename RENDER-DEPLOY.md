# Render Deployment — OAuth Security Lab

## What gets deployed

Five separate Web Services, each with its own `.onrender.com` URL:

| Service | Render name | Role |
|---|---|---|
| Client App | `oauth-lab-client` | Entry point — login, dashboard, attack lab portal |
| Auth Server | `oauth-lab-auth` | Authorization server — issues codes and tokens |
| Resource API | `oauth-lab-resource` | Protected API — profile, admin endpoints |
| Attacker C2 | `oauth-lab-attacker` | Capture endpoint, phishing, JWT forge tool |
| Monitoring | `oauth-lab-monitor` | Real-time security event dashboard |

---

## Deploy Steps

### Step 1 — Push to GitHub

```bash
git init                         # if not already a git repo
git add .
git commit -m "feat: render deploy config"
git remote add origin https://github.com/YOUR_USERNAME/oauth-security-lab.git
git push -u origin main
```

Make sure `render.yaml` is at the **root** of the repo.

---

### Step 2 — Connect to Render

1. Go to **https://dashboard.render.com**
2. Click **New** → **Blueprint**
3. Click **Connect a repository** → select your GitHub repo
4. Render detects `render.yaml` and shows a preview of all 5 services
5. Review the service names and click **Apply**

All 5 services start building. First build takes **5–8 minutes** (npm install + Docker layers).

---

### Step 3 — Fix ALLOWED_ORIGINS (one manual step after first deploy)

Render assigns URLs like `https://oauth-lab-client-xxxx.onrender.com` (with a random suffix).

After all services are green:

1. Go to **oauth-lab-resource** → **Environment** in the Render dashboard
2. Find `ALLOWED_ORIGINS` and update it:
   ```
   https://oauth-lab-client-xxxx.onrender.com,https://oauth-lab-attacker-xxxx.onrender.com
   ```
3. Click **Save Changes** → the resource server redeploys automatically (~60 seconds)

---

### Step 4 — Open the lab

Go to **https://oauth-lab-client-xxxx.onrender.com**

Login: `alice` / `password123`

---

## Toggle VULNERABLE / SECURE mode

Update `VULNERABLE_MODE` on `oauth-lab-auth`, `oauth-lab-resource`, and `oauth-lab-client`:
- `"true"` — all 8 attacks active
- `"false"` — all mitigations active

Each service redeploys automatically on save.

---

## Free Tier Behaviour

| Behaviour | Why |
|---|---|
| ~30s cold start | Services sleep after 15 min of inactivity |
| Sessions reset after restart | In-memory stores are process-local |
| DB reseeds on restart | SQLite at `/tmp/oauth.db` is ephemeral — alice/password123 always works |
| 750 hrs/month total | ~150 hrs per service ≈ 5 hrs/day active use across all 5 |

**Tip:** Hit `/health` on each service URL to wake them before demoing.

---

## Why not Vercel?

| Constraint | Impact |
|---|---|
| Serverless only | All 5 Express servers need complete rewrites |
| `better-sqlite3` native C++ addon | Won't compile in Vercel's build sandbox |
| 10s function timeout | Multi-hop OAuth flows time out |
| Stateless functions | In-memory token stores vanish between requests |

Render is the correct free-tier platform for this stack.

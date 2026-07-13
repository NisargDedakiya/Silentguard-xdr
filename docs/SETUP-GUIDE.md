# SilentGuard XDR — Step‑by‑Step Setup Guide (all features working)

This guide takes you from nothing to a fully‑working deployment with **every
feature enabled and verified**. Work through it in order — each step ends with a
quick check so you know it's actually working before moving on.

Legend: 🖥️ = server, 🧑‍💻 = agent (endpoint), 🌐 = dashboard.

---

## Part 0 — Prerequisites

- Python 3.11+, and (optional) Docker + Docker Compose.
- The agent must run **elevated** (Administrator on Windows / root on Linux) for
  network isolation, DNS sinkholing, and hosts‑file domain blocking.
- Pick strong secrets before production: admin token, enrollment token, JWT
  secret.

---

## Part 1 — Bring the stack up

### Option A — Docker Compose (server + dashboard)
```bash
docker compose up --build
# dashboard: http://localhost:3000   server: http://localhost:8000
```

### Option B — Local dev
```bash
# 🖥️ server
cd server && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head                       # create/upgrade the database
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 🌐 dashboard (separate shell)
cd dashboard && npm install && npm run dev  # http://localhost:3000
```

**✅ Check:** `curl http://localhost:8000/api/health` → `{"status":"ok",...}`.

---

## Part 2 — Production hardening (do this before exposing it)

Set these env vars on the **server** (compose `.env` or the process env):

| Variable | Set to | Why |
|---|---|---|
| `SG_ENV` | `production` | Turns off dev conveniences (token exposure) |
| `SG_ADMIN_TOKEN` | long random string | Legacy admin API token |
| `SG_ENROLL_TOKEN` | long random string | One‑time agent enrollment secret |
| `SG_JWT_SECRET` | 32+ random bytes | Independent JWT signing key |
| `SG_HSTS_ENABLED` | `1` | Only when served over TLS |
| `SG_CORS_ORIGINS` | your dashboard origin | Lock down CORS |

**✅ Check:** `GET /api/admin/analytics/compliance-report` (with `X-Admin-Token`)
— the `strong_authentication`, `transport_security`, and `token_exposure`
controls should read **pass**.

---

## Part 3 — Identity & access

### 3.1 Bootstrap an admin user
Set `SG_BOOTSTRAP_ADMIN_EMAIL` and `SG_BOOTSTRAP_ADMIN_PASSWORD` (≥12 chars) and
restart the server. A `super_admin` is created if no users exist.

### 3.2 Create users / roles (RBAC)
```
POST /api/admin/users   { "email": "...", "password": "...", "role": "analyst" }
```
Roles: `super_admin, soc_manager, analyst, threat_hunter, responder, auditor, read_only`.

**✅ Check:** log in as a `read_only` user → `GET /api/admin/detections` = 200,
but `POST /api/admin/detections/{id}/ack` = 403.

### 3.3 MFA (TOTP)
Per user, from an authenticated session:
1. `POST /api/auth/mfa/setup` → scan the `otpauth_uri` QR into an authenticator.
2. `POST /api/auth/mfa/activate {"code":"123456"}`.
3. Thereafter `POST /api/auth/login` requires `"mfa_code"`.

**✅ Check:** login without a code → `401 "MFA code required"`; with the current
code → tokens.

### 3.4 SSO (OIDC) — optional
Register a client at your IdP with redirect `https://<server>/api/auth/sso/callback`, then:
```
SG_OIDC_ENABLED=1
SG_OIDC_ISSUER=https://your-idp.example
SG_OIDC_CLIENT_ID=...      SG_OIDC_CLIENT_SECRET=...
SG_OIDC_REDIRECT_URI=https://<server>/api/auth/sso/callback
SG_OIDC_DEFAULT_ROLE=read_only     SG_OIDC_ALLOWED_DOMAIN=yourcompany.com   # optional
```
**✅ Check:** `GET /api/auth/sso/login` returns an `authorization_url` (503 means
not configured).

---

## Part 4 — Enroll an endpoint (the agent)

On the endpoint, **elevated**:
```bash
# 🧑‍💻 agent
cd agent && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SG_SERVER_URL=https://<server>:8000
export SG_ENROLL_TOKEN=<same as server>
# Windows: run the shell "as Administrator"; Linux: use sudo -E
sudo -E python -m silentguard_agent.main
```
> ⚠️ Do **not** set `SG_DRY_RUN=1` in production — dry‑run only logs actions and
> never edits the hosts file / firewall.

**✅ Check:** the device appears in the dashboard Device Fleet as **online**, and
`GET /api/admin/events` shows `agent`/`process`/`port_watchdog` telemetry.

---

## Part 5 — Detection features

- **Behavioral rules** work out of the box (process monitor feeds them). Trigger
  one: run `powershell -nop -enc SQBFAFgA` on the endpoint → a `powershell_abuse`
  / `encoded_command` detection appears.
- **Threat‑intel IOCs:** `POST /api/admin/intel/iocs {"ioc_type":"domain","value":"bad.example","confidence":90}`.
  Subdomain‑aware: `c2.bad.example` matches.
- **Sigma rules:** `POST /api/admin/intel/rules {"kind":"sigma","name":"...","content":"<YAML>","enabled":true}`
  (`SG_SIGMA_ENABLED=1`, default on). Invalid YAML is rejected.
- **YARA (endpoint):** set `SG_YARA_ENABLED=1`, `SG_YARA_RULES=/path/rules.yar`,
  and `pip install yara-python` on the agent.
- **Suricata (endpoint):** set `SG_SURICATA_ENABLED=1`, `SG_SURICATA_EVE=/var/log/suricata/eve.json`.
- **Auto‑isolate:** `SG_DETECTION_AUTO_ISOLATE=1` isolates the device on a
  critical detection whose rule includes the isolate response.

**✅ Check:** `GET /api/admin/detections` lists the findings; `GET
/api/admin/analytics/mitre-coverage` shows techniques.

---

## Part 6 — Blocking a domain / URL / port / process (make it actually enforce)

1. Add the entry (dashboard **Fleet Blocklist**, or `POST /api/admin/blocklist
   {"kind":"domain","value":"youtube.com"}`). A URL is normalized to its host.
2. Wait for the agent's next check‑in (`SG_CHECKIN_INTERVAL`, default 10s).

For a **domain** to actually be unreachable on the endpoint, all of these must hold:
- The agent runs **elevated** (to edit the hosts file).
- The agent is **not** in dry‑run.
- The browser's **Secure DNS / DoH is OFF** (Chrome/Edge: Settings → Privacy &
  security → Security → "Use secure DNS" = off) — DoH bypasses the hosts file.
- Flush caches after the change: `ipconfig /flushdns` and restart the browser.

Blocking an apex domain also sinkholes `www.`/`m.`/`mobile.` automatically.

**✅ Check:** after the above, the blocked site fails to load; and regardless,
`GET /api/admin/detections` shows a `blocklist_domain` detection for any
subdomain/URL request the endpoint made.

---

## Part 7 — Agent security hardening

- **Signed updates** (recommended): generate an Ed25519 keypair; give the agent
  the public key via `SG_UPDATE_PUBLIC_KEY` (hex/base64). Keep
  `SG_REQUIRE_SIGNED_UPDATES=1` (default). HMAC alternative: `SG_UPDATE_HMAC_KEY`.
- **Anti‑rollback** is automatic once updates are signed (blocks downgrades).
- **Tamper protection:** set `SG_TAMPER_KEY` to a secret so state‑file edits are
  detected → `tamper_detected` critical detection.
- **Certificate pinning:** set `SG_PIN_SHA256` to the server leaf cert's SHA‑256
  (from `openssl x509 -noout -fingerprint -sha256`).

**✅ Check:** edit `~/.silentguard/agent_state.json`, restart the agent → a
`tamper_detected` detection appears and the agent re‑enrolls.

---

## Part 8 — Integrations, AI, compliance

- **SIEM/SOAR/webhook:** `POST /api/admin/integrations
  {"name":"...","kind":"webhook|splunk_hec|syslog|slack|discord|teams","target":"https://...","min_severity":"medium","enabled":true}`.
  Note: SSRF protection blocks loopback/private targets unless allowed.
- **AI assistant:** `SG_AI_ENABLED=1` + `SG_ANTHROPIC_API_KEY=...`, then
  `POST /api/admin/detections/{id}/explain`.
- **Compliance report:** `GET /api/admin/analytics/compliance-report` (auditor+).

---

## Part 9 — Troubleshooting quick table

| Symptom | Cause / fix |
|---|---|
| Blocked site still opens | Agent not elevated / dry‑run / browser DoH on / cache not flushed (Part 6) |
| No detections from endpoint | Agent not running elevated, or telemetry not reaching server (check `/api/admin/events`) |
| MFA login always fails | Device clock skew >30s; re‑sync time |
| SSO returns 503 | One of the `SG_OIDC_*` values is unset |
| Integration rejected | SSRF guard blocked a private/loopback target |
| Agent won't edit hosts | Not elevated — the log says "must run elevated" |

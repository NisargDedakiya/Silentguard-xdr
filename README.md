# SilentGuard XDR

An autonomous endpoint detection & response (EDR/XDR) platform. Employees never
make a security decision — a silent endpoint agent detects and contains threats
automatically, while security admins get fleet-wide visibility and one-click
remote isolation from a central dashboard.

Built from the SilentGuard XDR project proposal (semester MVP scope).

## Architecture

```
┌─────────────────────┐   TLS / JSON telemetry   ┌──────────────────────┐
│  Endpoint Agent     │ ───────────────────────► │  Command Matrix API  │
│  (Python)           │ ◄─────────────────────── │  (FastAPI + SQL)     │
│  · Port watchdog    │   check-in: isolation,   └──────────┬───────────┘
│  · DNS sinkhole     │   commands, blocklists,             │ REST + WebSocket
│  · ARP guard        │   quarantine restores    ┌──────────▼───────────┐
│  · File-drop watch  │                          │  Admin Dashboard     │
│  · USB guard        │                          │  (Next.js + Tailwind │
│  · Quarantine       │                          │   + recharts)        │
│  · Isolation ctrl   │                          └──────────────────────┘
└─────────────────────┘
```

### The three pillars

1. **Automated Host Defense ("The Bouncer")** — `agent/silentguard_agent/monitors/port_watchdog.py`
   polls listening TCP/UDP sockets; unauthorized processes opening suspicious
   ports (e.g. a reverse shell on 4444) or known-bad process names are killed
   automatically. An allowlist of known-safe processes minimizes false positives.
2. **Zero-Touch Network Shield ("The Invisible Fence")** —
   `dns_sinkhole.py` pins known-malicious domains to `0.0.0.0` at the OS level
   (the browser just shows "site unreachable"); `arp_guard.py` pins the gateway
   MAC and blocks any device that starts impersonating the router.
3. **The Command Matrix** — FastAPI backend ingests encrypted JSON telemetry,
   stores the threat timeline, and serves the Next.js dashboard with live
   WebSocket updates, fleet blocklist pushes, and one-click remote isolation.

## Quick start — one command (Docker Compose)

The fastest way to bring up the **server + dashboard + Postgres** for a demo:

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000 (sign in with `silentguard-admin-demo`)
- API: http://localhost:8000
- Postgres is provisioned automatically; data persists in the `pg-data` volume.

Override defaults with env vars (or a `.env` file next to `docker-compose.yml`):
`SG_ADMIN_TOKEN`, `SG_ENROLL_TOKEN`, `POSTGRES_USER/PASSWORD/DB`,
`NEXT_PUBLIC_API_URL`.

**SQLite fallback** (no Postgres):

```bash
DATABASE_URL="sqlite:////data/silentguard.db" docker compose up --build server dashboard
```

The SQLite file lives on the `sqlite-data` volume.

> The **agent runs natively**, not in Docker — it needs host OS access
> (process list, firewall, hosts file). Start it as shown in step 2 below,
> pointing `SG_SERVER_URL` at `http://127.0.0.1:8000`.

## Manual setup (development)

### 1. Backend

```bash
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SG_ADMIN_TOKEN=silentguard-admin-demo    # change in production
export SG_ENROLL_TOKEN=silentguard-enroll-demo  # change in production
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Uses SQLite by default; set `DATABASE_URL=postgresql+psycopg2://...` for PostgreSQL.
In production, terminate TLS 1.3 at nginx or pass `--ssl-keyfile/--ssl-certfile`.

### 2. Agent (on each endpoint)

```bash
cd agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SG_SERVER_URL=http://127.0.0.1:8000
export SG_ENROLL_TOKEN=silentguard-enroll-demo
# SG_DRY_RUN=1 logs containment actions instead of executing them —
# useful for demos without root/admin privileges.
sudo -E python -m silentguard_agent.main
```

The agent enrolls once (credentials cached in `~/.silentguard/agent_state.json`,
mode 0600), then loops: scan → contain → stream telemetry → check in for
isolation commands and blocklist updates. Events are buffered locally while
the server is unreachable.

### 3. Dashboard

```bash
cd dashboard
npm install
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000 npm run dev
```

Open http://localhost:3000 and sign in with the admin token
(`silentguard-admin-demo` by default). You get:

- **Device Fleet** — live online/offline/isolated status + risk badge for every endpoint
- **Threat Timeline** — chronological feed of every detection and automated action,
  each tagged with its MITRE ATT&CK technique (linked to attack.mitre.org)
- **Remote Isolation** — one click restricts a device's network to the management server only
- **Fleet Blocklist** — push malicious domains / process names / ports to all agents
- **Quarantine** — inspect files agents have quarantined and restore them remotely
- **Analytics tab** — events-per-day by severity, top triggered devices, and
  blocklist hit counts (recharts, computed client-side from the events API)

## Demo scenario (matches the proposal's demonstration plan)

1. Start the backend, dashboard, and an agent (in a disposable VM, or with `SG_DRY_RUN=1`).
2. Simulate a malicious payload: `python3 -c "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',4444)); s.listen(); time.sleep(999)"`.
3. Watch the agent kill it and the dashboard timeline update live.
4. Click **Isolate device** — the agent applies firewall rules restricting traffic
   to the management server; the timeline records the containment.
5. Click **Release** to restore normal network access.

> ⚠️ Only test containment behavior on machines/VMs you own. Killing processes
> and rewriting firewall rules requires root/Administrator; use `SG_DRY_RUN=1`
> otherwise.

## Tamper resilience

- **Agent auto-restart** — install the agent as a supervised service so it
  relaunches within seconds if killed:
  - Linux: `deploy/silentguard-agent.service` (systemd, `Restart=always`)
  - Windows: `deploy/SilentGuardAgent-Task.xml` (Task Scheduler, boot trigger + restart-on-failure)
- **Server-side liveness monitor** — a background sweep emits a critical
  `device_unresponsive` event to the timeline when a device's `last_seen`
  exceeds `SG_UNRESPONSIVE_SECONDS` (default 45s) without a clean stop,
  surfacing an agent that was killed and did not restart. The flag clears
  automatically on the next telemetry or check-in.

## File hash reputation + quarantine

When the port watchdog kills a flagged process — or the file-drop monitor spots
a new file in a watched directory (`/tmp`, `~/Downloads`) — the file's SHA-256
is checked against a local reputation table: built-in known-bad hashes (EICAR
by default) extended by a user-maintained `~/.silentguard/reputation.json`
(`{"known_bad": [...], "allowlist": [...]}`). Flagged files are **moved, never
deleted**: renamed to an opaque id inside `~/.silentguard/quarantine/` with all
permissions stripped, so they can be inspected or restored later.
Allowlisted hashes are never quarantined.

- `GET /api/admin/quarantine` — fleet-wide quarantine inventory
- `POST /api/admin/quarantine/{id}/restore` — queues a restore command that the
  agent executes on its next check-in and confirms via telemetry

## USB device monitoring

The `usb_guard` monitor detects USB mass-storage insertion (warning event) and
removal (info event). Backends: `pyudev` when installed, a dependency-free
`/sys/block` poller otherwise on Linux, WMI on Windows. Set
`SG_BLOCK_USB_STORAGE=1` to block newly inserted storage devices outright
(Linux: sysfs de-authorization; Windows: disable USBSTOR) — blocked devices
raise a critical event. Devices present at agent start are baselined silently.

## MITRE ATT&CK technique tagging

Every threat event is tagged with the ATT&CK technique it evidences via a
static `(source, action)` mapping (`server/app/mitre.py`) — e.g.
`port_watchdog/killed → T1059`, `arp_guard → T1557.002`, `usb_guard → T1091`.
The technique id/name/url rides along in the admin API, WebSocket pushes, and
the dashboard timeline tag.

## Admin audit log

Every admin action (isolate, release, blocklist add/remove, quarantine restore)
is recorded in a separate `audit_log` table — actor token fingerprint (SHA-256
prefix, never the token), timestamp, target, and details — committed atomically
with the action itself. Read-only endpoint: `GET /api/admin/audit`.

## Alerting (webhook + email)

Critical-severity events fire best-effort notifications, configured by env vars:

```bash
SG_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX  # Slack or Discord
SG_SMTP_HOST=smtp.example.com SG_SMTP_PORT=587 SG_SMTP_USER=... SG_SMTP_PASSWORD=...
SG_SMTP_FROM=xdr@example.com SG_ALERT_EMAIL_TO=soc@example.com
```

Delivery is fire-and-forget on a worker thread with a 5s timeout; a broken
webhook or SMTP server can never stall telemetry ingestion.

## Device risk score

Each device carries a weighted risk score over a rolling 24h window
(`critical=10`, `warning=3`, `info=0`), linearly decayed by event age, banded
as clear / low / elevated / critical. Shown as a badge in the dashboard device
table and available at `GET /api/admin/devices/{id}/score`. This is the
foundation for the roadmap's Behavioral Detection Engine.

## Testing

```bash
cd server && pip install -r requirements.txt && pytest   # API, WS auth, quarantine, audit, alerting, scoring
cd agent  && pip install -r requirements.txt && pytest   # monitors, quarantine, USB guard — no root needed
```

Test dependencies (pytest, pytest-asyncio, httpx2) ship in
`server/requirements.txt`, so a fresh `pip install -r requirements.txt`
is all that's needed before `pytest -q`.

## Configuration & observability

All backend settings are centralized in `server/app/core/config.py` (typed,
`pydantic-settings`). The server emits structured JSON logs with a per-request
correlation id (`X-Request-ID`), sets secure response headers, and returns a
stable error envelope for unhandled exceptions. See
[`docs/configuration.md`](docs/configuration.md) for the full environment
variable reference. The enterprise upgrade plan lives in
[`docs/ROADMAP.md`](docs/ROADMAP.md); the pre-work audit is
[`docs/AUDIT.md`](docs/AUDIT.md).

## Security design

- Per-device API keys issued at enrollment (`X-Agent-Key`) authenticate all telemetry.
- User accounts with JWT access/refresh tokens gate the dashboard API
  (`/api/auth/*`, `Authorization: Bearer …`), with account lockout, login rate
  limiting, and a password policy — see [`docs/authentication.md`](docs/authentication.md).
  The legacy shared admin token (`X-Admin-Token`) is still accepted for
  backward compatibility. Full RBAC/SSO/MFA remain on the roadmap.
- Shared enrollment token gates agent onboarding.
- The live WebSocket (`/api/ws`) requires the admin token (query param or first
  message) and closes unauthenticated connections with a policy violation.
- Token comparisons use `secrets.compare_digest`; the audit log stores only a
  hash fingerprint of the acting token.
- Offline event buffering (bounded queue) so no data is lost during connectivity gaps.
- Local agent state written with owner-only permissions.
- Quarantine never deletes: files are moved, renamed, and permission-stripped so
  incident responders can inspect or restore them.

## Repository layout

```
agent/       Python endpoint agent (psutil-based monitors, isolation controller)
server/      FastAPI backend — enrollment, telemetry ingestion, admin API, WebSocket hub
dashboard/   Next.js + Tailwind admin dashboard
```

## Prioritized backlog (explicitly deferred — not in this cycle)

Deliberately not built yet: each is a real roadmap item, but too large to
implement safely alongside the current feature set without going shallow on
everything. In priority order:

1. **RBAC / SSO / MFA** — replace the shared admin token with per-user accounts,
   roles, and single sign-on.
2. **Windows Event Log + registry monitoring** — first-class Windows detection
   sources beyond process/port scanning.
3. **Ransomware behavioral detection** — mass-file-modification / entropy
   heuristics with automatic isolation.
4. **Policy management UI** — edit per-fleet detection policies (watched dirs,
   suspicious ports, USB policy) from the dashboard instead of env vars.
5. **Agent auto-update** — signed agent packages with staged rollout.
6. **Scheduled scan engine** — periodic full-disk hash sweeps against the
   reputation table.
7. **Behavioral Detection Engine / AI Security Assistant** — extend the risk
   score into sequence-aware detection with plain-language incident summaries.
8. **Process tree visualization** — parent/child ancestry for each detection.
9. **Multi-tenant organizations** — isolated fleets, per-tenant tokens and data.
10. **SIEM/SOAR integration** — syslog/CEF export, webhook-driven playbooks.
11. **YARA / Suricata integration** — signature scanning of quarantined files
    and network traffic.

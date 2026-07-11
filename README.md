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
│  · DNS sinkhole     │   commands, blocklists              │ REST + WebSocket
│  · ARP guard        │                          ┌──────────▼───────────┐
│  · Isolation ctrl   │                          │  Admin Dashboard     │
└─────────────────────┘                          │  (Next.js + Tailwind)│
                                                 └──────────────────────┘
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

- **Device Fleet** — live online/offline/isolated status for every endpoint
- **Threat Timeline** — chronological feed of every detection and automated action
- **Remote Isolation** — one click restricts a device's network to the management server only
- **Fleet Blocklist** — push malicious domains / process names / ports to all agents

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

## Security design

- Per-device API keys issued at enrollment (`X-Agent-Key`) authenticate all telemetry.
- Shared enrollment token gates onboarding; shared admin token (`X-Admin-Token`)
  gates the dashboard API (RBAC/SSO/MFA are on the enterprise roadmap).
- Offline event buffering (bounded queue) so no data is lost during connectivity gaps.
- Local agent state written with owner-only permissions.

## Repository layout

```
agent/       Python endpoint agent (psutil-based monitors, isolation controller)
server/      FastAPI backend — enrollment, telemetry ingestion, admin API, WebSocket hub
dashboard/   Next.js + Tailwind admin dashboard
```

## Enterprise roadmap (out of MVP scope, per proposal)

Behavioral risk-scoring engine, AI security assistant (MITRE ATT&CK mapping),
threat-intel feeds, RBAC/SSO/MFA, macOS/Linux-optimized agents, SIEM/SOAR
integration, Rust production agent, Kubernetes-scale deployment.

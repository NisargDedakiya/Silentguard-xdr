# SilentGuard XDR — Phase 1 Audit Report

_Baseline commit: `cd45807` · ~4,100 LOC (Python agent + FastAPI server + Next.js dashboard)_

This report is the mandated pre-implementation audit. It describes the codebase
**as it stands today**, names its weaknesses honestly, and feeds the prioritized
build sequence in [`ROADMAP.md`](./ROADMAP.md). Nothing here changes behavior.

---

## 1. Folder structure

```
Silentguard-xdr/
├── agent/                          # Python endpoint agent (runs natively, needs root)
│   ├── silentguard_agent/
│   │   ├── __init__.py             # __version__ = "0.1.0"
│   │   ├── main.py                 # run loop: scan → contain → telemetry → check-in
│   │   ├── config.py               # AgentConfig dataclass (env + JSON state/reputation)
│   │   ├── telemetry.py            # enrollment, buffered flush, check-in (requests)
│   │   ├── isolation.py            # iptables / netsh network isolation
│   │   ├── quarantine.py           # SHA-256 reputation + move-not-delete quarantine
│   │   └── monitors/
│   │       ├── port_watchdog.py    # listening-socket + bad-process kill
│   │       ├── dns_sinkhole.py     # hosts-file domain sinkhole
│   │       ├── arp_guard.py        # gateway ARP-spoof detection
│   │       ├── file_drop.py        # watched-dir new-file hashing
│   │       └── usb_guard.py        # USB mass-storage insert/remove
│   ├── tests/                      # 33 tests, mocked psutil/subprocess
│   └── requirements.txt
├── server/                         # FastAPI backend
│   ├── app/
│   │   ├── main.py                 # app factory, CORS, lifespan monitor task, /api/ws
│   │   ├── database.py             # engine + SessionLocal + Base (create_all)
│   │   ├── models.py               # Device, ThreatEvent, QuarantineItem, AuditLogEntry, BlocklistEntry
│   │   ├── schemas.py              # Pydantic v2 request/response models
│   │   ├── auth.py                 # static admin token + per-device api key
│   │   ├── scoring.py              # rolling-window risk score
│   │   ├── mitre.py                # (source, action) → ATT&CK technique
│   │   ├── alerting.py             # best-effort webhook + SMTP on critical
│   │   ├── monitor.py              # background liveness sweep
│   │   ├── ws.py                   # in-process WebSocket broadcast hub
│   │   └── routers/{agents,admin}.py
│   ├── tests/                      # 46 tests, in-memory SQLite
│   └── requirements.txt
├── dashboard/                      # Next.js 14 (app router, JS not TS)
│   └── app/{page.jsx, analytics.jsx, layout.jsx, globals.css}
├── deploy/                         # systemd unit + Windows Task Scheduler XML
├── docker-compose.yml              # server + dashboard + Postgres
└── README.md
```

**Observation.** Clean, shallow, and readable — appropriate for an MVP. It is
**not** layered for an enterprise platform: routers talk to the ORM directly,
there is no service/repository layer, no domain package, and no shared
`core/` for cross-cutting concerns (config, logging, security). That is the
central refactor theme of the roadmap.

## 2. Dependency graph

**Server** (`fastapi → routers → models/scoring/mitre/alerting → database`).
No cycles. `ws.hub` is a module-level singleton imported by `main`, both
routers, and `monitor` — a shared global that will not survive multi-process
horizontal scaling (see §11).

**Agent** (`main → monitors + isolation + quarantine + telemetry → config`).
`config.py` has a load-order subtlety: `AgentConfig.__post_init__` calls
`load_reputation()`, which is defined later in the same module — fine at import
time, but the module mixes config schema and file I/O.

**Third-party surface** is deliberately tiny: server = fastapi, uvicorn,
sqlalchemy, pydantic, python-multipart (+ test deps); agent = psutil, requests.
No `cryptography`, no `redis`, no auth/JWT library, no migration tool, no
settings library, no observability stack. Every enterprise phase adds
dependencies from zero.

## 3. Endpoint agent architecture

Single-threaded synchronous poll loop (`main.run()`), `poll_interval` 3 s,
`checkin_interval` 10 s. Each iteration runs every monitor's `scan()`/`sync()`
in sequence, then flushes a buffered telemetry deque (`maxlen=5000`) over plain
`requests`. Enrollment persists `{device_id, api_key}` to
`~/.silentguard/agent_state.json` (mode 0600).

**Strengths:** monitors share a uniform `emit()` telemetry contract; dry-run
mode everywhere; offline buffering; graceful SIGINT/SIGTERM.

**Gaps vs. real EDR agents:**
- No async / no per-monitor isolation — one slow monitor stalls the loop.
- No self-protection: the agent cannot detect its own service being killed,
  its config being edited, or its firewall rules being removed (server-side
  liveness is the only tamper signal).
- OS logic is branched inline with `platform.system()` inside each monitor
  rather than behind an OS-adapter interface — cross-platform expansion
  (Phase 11) will multiply these branches.
- Transport is plaintext-capable: `verify_tls` can be disabled, there is no
  mTLS, no message signing, no replay protection, no compression.

## 4. Backend architecture

FastAPI app created at import time; `Base.metadata.create_all` runs on import
(§7). A `lifespan` context starts one asyncio task (`run_monitor_loop`).
Two routers: `/api/agent/*` (agent key auth) and `/api/admin/*` (admin token
auth). WebSocket `/api/ws` for the dashboard live feed.

**Strengths:** dependency-injected DB session; Pydantic response models;
atomic audit writes; alerting is non-blocking.

**Gaps:** no service layer (business logic lives in route handlers), no
migrations, no pagination on list endpoints (`limit` caps only), CORS is
`allow_origins=["*"]`, no rate limiting, no request logging/tracing, no
central error handling, single-process WS hub, and `check_once` /
`list_devices` iterate the whole device table each call.

## 5. Dashboard architecture

Two client components (`page.jsx`, `analytics.jsx`), one API base URL, admin
token held in React state + a ref. Live updates via WS with a 5 s polling
fallback. Recharts analytics computed client-side. **Plain JavaScript, not
TypeScript.** No routing (single page, tab state), no data-fetching library,
no component library, no auth beyond posting the static token, no error
boundaries. Fine for one screen; will not scale to the ~15 dashboards in
Phase 12 without a real app-router structure, TypeScript, and a query layer.

## 6. Database schema (current)

| Table | Key columns | Notes |
|---|---|---|
| `devices` | id (uuid str PK), hostname, platform, api_key (unique), last_seen, isolated, pending_commands (JSON), stopped, unresponsive_alerted | No org_id, no group_id, no inventory fields, `api_key` stored plaintext |
| `threat_events` | id, device_id (FK, idx), timestamp (idx), source, severity, action, summary, details (JSON) | No org_id, no technique column (computed at read), no incident linkage |
| `quarantine_items` | id (agent qid PK), device_id (FK), original_path, sha256, verdict, status, timestamps | Mirrored from telemetry |
| `audit_log` | id, timestamp (idx), actor (token fp), action, target, details (JSON) | Append-only by convention, not enforced |
| `blocklist` | id, kind, value (unique), added_at | Global, no org scoping |

**Weaknesses:** no tenancy column anywhere; no users/roles/sessions tables;
no IOC, policy, device-group, incident, or inventory tables; JSON columns are
schemaless (fine for SQLite, weak for query/index on Postgres at scale);
`api_key` and (future) secrets are plaintext; composite indexes for the hot
paths (events by device+timestamp, events by org+severity+day) are missing.

## 7. Schema management — **critical debt**

`server/app/database.py` uses `Base.metadata.create_all(bind=engine)` at import.
This creates missing tables but **never alters existing ones**. Every schema
change the roadmap requires (org_id backfill, users, IOCs, inventory, incidents)
is impossible to ship to a running Postgres without a migration tool. **Alembic
is a prerequisite for essentially all of Phases 5–9.** This is the single
highest-leverage fix.

## 8. API routes (inventory)

Agent: `POST /api/agent/enroll`, `POST /api/agent/telemetry`,
`GET /api/agent/checkin`.
Admin: `GET /devices`, `POST /devices/{id}/isolate|release`,
`GET /devices/{id}/score`, `GET /events`, `GET /quarantine`,
`POST /quarantine/{id}/restore`, `GET /blocklist`, `POST /blocklist`,
`DELETE /blocklist/{id}`, `GET /audit`. Plus `GET /api/health`.

No versioning prefix (`/api/v1`), no pagination envelope, no OpenAPI tags
grouping beyond the two routers, no consistent error schema.

## 9. WebSocket events

Broadcast types: `device_enrolled`, `threat_event`, `isolation`,
`blocklist_updated`, `quarantine_updated`. The hub is an in-process
`set[WebSocket]` — **not shared across workers**, so any horizontally-scaled
deployment silently drops events for clients connected to other workers. Needs
a Redis (or NATS) pub/sub fan-out (Phase 13).

## 10. Authentication flow — **biggest security weakness**

Two **static shared secrets** from env (`SG_ADMIN_TOKEN`, `SG_ENROLL_TOKEN`)
plus a per-device `api_key`. Comparisons use `secrets.compare_digest` (good),
WS is now token-gated (good), and the admin token is fingerprinted in the audit
log (good). But:

- **No users, no roles, no sessions, no JWT, no MFA, no lockout, no rotation.**
  One leaked admin token = full fleet compromise with no revocation path.
- **No multi-tenancy**, so no isolation between organizations.
- `api_key` is stored and compared in plaintext; enrollment token is shared and
  reusable indefinitely.

This blocks Phase 2 (Auth), Phase 5 (RBAC/multi-tenant), and per-user audit.

## 11. Security weaknesses (ranked)

1. Static shared-token auth; no users/RBAC/tenancy (§10).
2. No migrations — can't evolve schema safely (§7).
3. `CORS allow_origins=["*"]` with credentialed admin calls.
4. No rate limiting anywhere (enrollment, login-to-be, telemetry) → brute-force
   and abuse exposure.
5. Plaintext `api_key` / enrollment token at rest; no secrets manager.
6. No secure-response-headers middleware (HSTS, X-Content-Type-Options, etc.).
7. No structured request logging / correlation IDs → weak forensics on the
   platform itself.
8. Agent transport can run without TLS verification; no mTLS/signing/replay
   protection.
9. `details` JSON is stored verbatim from agents — needs size/shape bounds to
   resist log-flooding.

## 12. Performance bottlenecks

- WS hub is single-process (§9) — hard scaling ceiling.
- `list_devices` still calls `compute_scores` over all in-window events each
  request; fine for hundreds of devices, not 100k (needs a materialized/cached
  risk column refreshed by a worker).
- `check_once` loads all devices every 15 s.
- No connection pooling tuning, no Redis, no async DB driver, no batch-ingest
  path distinct from the per-event broadcast loop.
- Events endpoints have no keyset pagination.

## 13. Missing capabilities vs. the enterprise target

Behavioral detection engine, threat-intel/IOC service, multi-tenancy, RBAC,
policy engine, device groups, full device inventory, process-tree/registry/
network/USB timelines, Windows Event Log + registry + scheduled-task + service
+ FIM monitoring, response actions beyond isolate/quarantine, SIEM/SOAR
exports, cross-platform OS adapters, and ~15 enterprise dashboards. These are
the substance of Phases 3–12 and are **not started** (MITRE tagging and a
basic risk score are the only detection-adjacent pieces present).

## 14. Code duplication

- `_aware(dt)` (naive→UTC) is defined **three times** (`scoring.py`,
  `monitor.py`, `admin.py` inline). → extract to a shared util.
- The event-broadcast dict is hand-built in `agents.py`, `monitor.py`, and
  `admin.py` with slight differences. → single serializer.
- `platform.system()` OS branching repeats across `isolation.py`,
  `dns_sinkhole.py`, `arp_guard.py`, `usb_guard.py`. → OS-adapter interface.
- Per-monitor "baseline first scan, then diff" pattern is duplicated in
  `file_drop`, `usb_guard`, `port_watchdog`. → a small `BaselineDiffMonitor`
  mixin.

## 15. Dead / latent code

Minimal. `EnrollResponse`/`CheckinResponse` unused fields are all consumed.
`allowlisted_hashes` was wired in Phase 1. No obviously unreachable functions.
The commented `scapy`/`redis`/`celery` lines in requirements are intentional
placeholders, not dead code.

## 16. Technical debt (themes)

- No configuration object — env vars read with `os.environ.get` scattered
  across 8+ modules with duplicated defaults (`SG_ADMIN_TOKEN` default appears
  in `auth.py`, `config.py`, compose, tests).
- No logging strategy on the server (agent logs; server is silent).
- No error-handling middleware — unhandled exceptions leak default stack pages.
- Business logic in route handlers (no service layer) → hard to unit-test and
  reuse across REST + WS + workers.
- JS (not TS) dashboard; no shared API client.

## 17. Testing coverage

79 tests total (46 server + 33 agent), all green. **Good breadth** across
happy-path + several failure/negative cases (WS reject, quarantine failure,
alert swallowing, audit of failed actions). **Gaps:** no integration tests
across agent↔server, no load tests, no security/abuse tests, no dashboard
tests, no coverage measurement in CI (there is no CI). Route handlers are
covered via TestClient but the absence of a service layer means logic and
transport are tested together.

---

## Top 10 findings, ranked

1. **Static shared-token auth, no users/RBAC/tenancy** (security, blocks 2/5).
2. **No DB migrations** (`create_all`) — blocks every schema change (7/5–9).
3. **Single-process WS hub + uncached per-request scoring** — scaling ceiling.
4. **No central config / logging / error-handling / security-headers** — the
   cross-cutting foundation every "production-grade" phase assumes.
5. **No service/domain layer** — logic trapped in route handlers.
6. **CORS `*` + no rate limiting** — concrete web-security gaps.
7. **Plaintext credentials at rest**, no secrets management.
8. **Agent transport hardening** (mTLS/signing/replay) absent.
9. **No OS-adapter abstraction** — cross-platform growth multiplies branches.
10. **Duplication** (`_aware`, event serializer, OS branching, baseline-diff).

The roadmap sequences fixes so foundations (4, 2) land before the features that
depend on them (1/5, 3, 6–9), never breaking the 79 green tests.

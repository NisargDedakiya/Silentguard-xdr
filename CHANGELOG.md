# Changelog

All notable changes to SilentGuard XDR. This project is being upgraded from an
MVP toward an enterprise XDR platform following the plan in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## [Unreleased]

### Enterprise upgrade — Phase 1 (audit) + Module M1 (foundation)

- **docs:** Added `docs/AUDIT.md` (full pre-implementation codebase audit) and
  `docs/ROADMAP.md` (16 requested phases re-sequenced into 23 dependency-ordered
  modules).
- **M1 — Configuration foundation:** New `app/core/config.py` centralizes all
  settings into one typed `pydantic-settings` object. Every historical `SG_*`
  environment variable name and default is preserved, so runtime behavior is
  unchanged. `auth.py`, `database.py`, and `monitor.py` now read from it instead
  of scattered `os.environ.get` calls.
- **M1 — Observability:** New `app/core/logging.py` adds structured JSON logging
  (console format optional via `SG_LOG_FORMAT=console`) with a per-request
  correlation id. The server previously emitted no application logs.
- **M1 — Web hardening:** New `app/core/middleware.py` adds request-context
  (correlation id + one structured access log per request), secure response
  headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Cross-Origin-Opener-Policy`, `Permissions-Policy`, opt-in HSTS), and a
  request body-size guard (`SG_MAX_REQUEST_BYTES`, default 5 MiB). CORS origins
  are now configurable via `SG_CORS_ORIGINS` (default `*`, unchanged).
- **M1 — Error handling:** New `app/core/errors.py` installs a catch-all handler
  that logs unhandled exceptions with the correlation id and returns a stable,
  non-leaky JSON envelope instead of a framework stack page. FastAPI's built-in
  `HTTPException`/validation handlers are untouched, so all existing status
  codes and bodies are unchanged.
- **Tests:** +11 server tests (`tests/test_core.py`) covering config, logging,
  middleware, and the error envelope. Full suite: **57 server + 33 agent = 90
  passing**, no regressions.
- **Dependency:** Added `pydantic-settings>=2.0` to `server/requirements.txt`.

- **M2 — Database migrations:** Introduced Alembic (`server/migrations/`,
  `alembic.ini`) with a baseline migration reflecting the current five tables.
  `env.py` reads `DATABASE_URL` from the centralized settings and targets the
  ORM `Base.metadata`. Startup now `create_all`s only for SQLite (the
  zero-config demo); production Postgres is migration-managed. The server Docker
  image runs `alembic upgrade head` before uvicorn. Added `tests/test_migrations.py`
  (+2) asserting migrations match the ORM models and downgrade cleanly. New
  dependency `alembic>=1.13`; docs in `docs/migrations.md`.

- **M3 — Service layer + shared utils (refactor, behavior-preserving):** New
  `app/utils/time.py` (`aware_utc`) replaces three drifted `_aware` copies
  (`scoring.py`, `monitor.py`, `admin.py`). New `app/services/events.py`
  centralizes threat-event serialization (`broadcast_payload`, `event_out`) with
  MITRE tagging attached in one place — previously hand-built in `agents.py`,
  `monitor.py`, and `admin.py`. Removed now-dead imports. Added
  `tests/test_services.py` (+6). WebSocket/REST payloads are byte-identical.

- **M4 — Users + JWT authentication:** Real user accounts replace the single
  shared admin token as the identity model, **backward compatible** — the legacy
  `X-Admin-Token` still authorizes the admin API. New `users` and
  `refresh_tokens` tables (migration `967f09a44a35`), the seven RBAC roles
  (`app/core/roles.py`), PBKDF2 password hashing + HS256 JWTs
  (`app/core/security.py`), and an auth service with account lockout, per-IP
  login rate limiting, a password policy, refresh-token rotation/revocation, and
  optional bootstrap super-admin. New endpoints `POST /api/auth/{login,refresh,
  logout}` and `GET /api/auth/me`. `require_admin` now accepts a JWT **or** the
  legacy token; `get_current_user` requires a JWT. Logins are audit-logged.
  Tests: +12 (`tests/test_auth.py`). New deps `pyjwt>=2.8`, `alembic>=1.13`,
  `pydantic-settings>=2.0`. Docs: `docs/authentication.md`.

- **M5 — RBAC enforcement:** Per-endpoint permission checks across the admin API
  via a role→permission matrix (`app/core/permissions.py`) and a
  `require_permission` dependency returning a `Principal` (audit actor + role).
  Six permissions (`read:fleet`, `read:audit`, `write:isolation`,
  `write:blocklist`, `write:quarantine`, `manage:users`) mapped over the seven
  roles. New user-management endpoints (`GET/POST /api/admin/users`,
  `POST /api/admin/users/{id}/disable`), all audit-logged. Unauthorized callers
  get `403`; the **legacy admin token resolves to super_admin** so existing
  integrations are unaffected. Tests: +10 (`tests/test_rbac.py`). Docs:
  `docs/rbac.md`.

- **M6 — Multi-tenancy:** All domain data is now scoped to an organization.
  New `organizations` table and nullable `org_id` on `devices`, `threat_events`,
  `quarantine_items`, `blocklist`, `audit_log`, `users` (migration
  `3976409257c3`, which creates a default org and **backfills all existing rows**
  into it — verified against a pre-M6 seeded database). Reads/writes are
  org-scoped via `app/services/tenancy.py`; super-admins and the legacy admin
  token are cross-org (unchanged single-admin view). Cross-tenant object access
  returns 404 (no existence leak). Agents enroll into the default org and
  receive only their org's blocklist; blocklist uniqueness is now per-org.
  Tests: +7 (`tests/test_tenancy.py`). Docs: `docs/multi-tenancy.md`.

- **M8 — Behavioral detection engine:** A rule-based engine
  (`app/detection/`) evaluates ingested telemetry and produces org-scoped
  **detections** with a Low/Medium/High/Critical weighted risk model, ATT&CK
  technique, and configurable responses. Seed rules: reverse shell (T1059),
  suspicious listener (T1571), PowerShell abuse (T1059.001), encoded command
  (T1027), LOLBin execution (T1218) — the first two fire on today's telemetry.
  New `detections` table (migration `1e6ea9d784c9`), triage API
  (`GET /api/admin/detections`, `POST …/{id}/ack|resolve`) behind a new
  `write:detections` permission, and a `detection` WebSocket event. Responses:
  `alert` (critical → M5 alerting) always on; `isolate` gated by
  `SG_DETECTION_AUTO_ISOLATE` (off by default). The telemetry response gained an
  additive `detections` count. Tests: +16 (`tests/test_detection.py`). Docs:
  `docs/detection-engine.md`.

**Backward compatibility (M1–M8):** No existing API route or WebSocket event was
removed; the telemetry response is additively extended (`detections` count), and
the admin API keeps accepting the legacy token. The SQLite demo still
auto-creates its schema; production backends run `alembic upgrade head`. Suite:
**106 server + 33 agent = 139 passing.**

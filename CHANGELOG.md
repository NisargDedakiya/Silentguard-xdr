# Changelog

All notable changes to SilentGuard XDR. This project is being upgraded from an
MVP toward an enterprise XDR platform following the plan in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## [Unreleased]

### v1.4 — Compliance & executive reporting

- **New `app/services/compliance.py` + `GET /api/admin/analytics/compliance-report`**
  (`READ_AUDIT`, org-scoped): a single posture report — fleet health, detection
  backlog, threat-intel coverage, and pass/warn/fail control checks with a
  headline score (pass=full, warn=half, fail=none). Five configuration controls
  (JWT secret, HSTS, token exposure, body-size guard, Sigma) plus three
  data-driven controls (all endpoints reporting, no unresolved criticals, intel
  content present), so the report reflects real operational posture.
- **Schema:** `ComplianceReportOut` / `ComplianceControl`. **Tests:**
  `server/tests/test_compliance.py` (structure/score, backlog fail→pass on
  resolve, intel control, RBAC). **Docs:** `docs/compliance-reporting.md`.

### v1.3 — YARA file scanning

- **New `agent/silentguard_agent/monitors/yara_scanner.py`:** scans
  newly-dropped files (the file-drop watch dirs) against a YARA rule set and
  reports/quarantines matches. Optional and dependency-light — inert unless
  `SG_YARA_ENABLED` + `SG_YARA_RULES` are set and `yara-python` is installed;
  every missing piece degrades to a no-op. Baseline-aware, wired into the agent
  poll loop.
- **Server:** new built-in `yara_match` detection rule turns a `source="yara"`
  event into a `critical` detection mapped to T1105, so YARA hits flow through
  triage/alerting/integrations/AI like any detection.
- **Config (agent):** `SG_YARA_ENABLED`, `SG_YARA_RULES`, `SG_YARA_QUARANTINE`.
- **Tests:** `agent/tests/test_yara_scanner.py` (fake compiled rules, no native
  libyara) and a server ingestion test. **Docs:** `docs/yara.md`.

### v1.2 — Durable offline telemetry queue

- **Agent `TelemetryClient` now spools its buffer to disk**
  (`~/.silentguard/telemetry_queue.json`, `0600`), so events captured during a
  connectivity gap survive an agent restart or device reboot — previously the
  in-memory buffer was lost on exit. The spool is rewritten on every `emit`,
  recovered on startup, shrunk after a successful flush, and bounded to
  `MAX_BUFFER` (5000). Persistence is best-effort so telemetry capture never
  fails on a disk error.
- **Config:** `config.load_queue` / `config.save_queue` helpers; spool path
  honors `SG_STATE_DIR`. **Tests:** `agent/tests/test_telemetry_queue.py`.
  **Docs:** `docs/offline-queue.md`.

### v1.3 — Sigma rule evaluation

- **New `app/detection/sigma.py`:** compiles operator-supplied Sigma rules into
  predicates over an `EventContext` and evaluates them in the detection engine.
  Previously Sigma rules could be stored/distributed but never fired. Supported
  subset: selections (mapping + keyword lists), field modifiers `contains` /
  `startswith` / `endswith` / `re` / `all` / equality, `condition` with
  `and` / `or` / `not` / parentheses and `N of them` / `all of them` /
  `1 of prefix*`, `level` → severity, and `tags` → ATT&CK technique. Matching is
  case-insensitive; unmapped fields never match (no false positives).
- **Engine:** `_evaluate_sigma` runs enabled `kind="sigma"` intel rules
  (org-scoped + global) per event, producing `Detection` rows with
  `rule_id="sigma:<id>"`. Compilation is cached by content hash; a broken rule
  is logged and skipped, never dropping telemetry. Gated by `SG_SIGMA_ENABLED`
  (default on, inert until rules exist).
- **Ingestion validation:** `POST /api/admin/intel/rules` now rejects an
  uncompilable Sigma rule with `400` before it can reach the engine.
- **Deps:** `pyyaml>=6.0`. **Tests:** `server/tests/test_sigma.py`.
  **Docs:** `docs/sigma.md`.

### M15a — Signed agent updates

- **New `agent/silentguard_agent/update_verifier.py`:** verifies the signature
  on a `remote_update` manifest (`version`/`url`/`sha256`) before the agent
  honors it, so a spoofed management channel cannot push arbitrary code.
  Supports **Ed25519** (preferred; endpoint holds only the public key) and
  **HMAC-SHA256** (dependency-free fallback). Keys/signatures accept hex or
  base64; the signed message is canonical key-sorted JSON of the manifest.
- **`remote_update` now fails closed:** a manifest without a valid signature (or
  with no trust key configured) is rejected (`update_rejected`); a valid one is
  `update_verified`. A version-only acknowledgement keeps the legacy best-effort
  behavior, flagged `verified: false`. `main.py` passes `config` through.
- **Config (agent):** `SG_UPDATE_PUBLIC_KEY`, `SG_UPDATE_HMAC_KEY`,
  `SG_REQUIRE_SIGNED_UPDATES` (default on). `cryptography>=41` added to agent
  requirements for the Ed25519 path.
- **Tests:** `agent/tests/test_update_verifier.py` — both schemes, tamper and
  wrong-key rejection, fail-closed, and handler integration.
- **Docs:** `docs/signed-updates.md`.

### Stage 6 — AI Security Assistant

- **New service `app/services/ai_assistant.py`:** a Claude-powered triage
  assistant that turns a detection into an analyst briefing — summary, MITRE
  ATT&CK explanation, and prioritized remediation. Prompt is built from the
  detection facts plus the originating telemetry event; the reply is parsed
  defensively (JSON, code-fenced JSON, or plain-text fallback) and adaptive
  thinking blocks are stripped.
- **New endpoint `POST /api/admin/detections/{id}/explain`** (permission
  `READ_FLEET`, org-scoped, audited as `detection_explain`). Returns the
  briefing, or `503` when the assistant is unconfigured / `502` on model error.
- **Config (additive, off by default):** `SG_AI_ENABLED`,
  `SG_ANTHROPIC_API_KEY` (falls back to `ANTHROPIC_API_KEY`), `SG_AI_MODEL`,
  `SG_AI_MAX_TOKENS`, plus `settings.ai_available`. The assistant is inert
  unless explicitly enabled with a key, so existing deployments are unaffected.
- **Best-effort by design:** every SDK failure is caught, logged, and surfaced
  as a typed error; the `anthropic` dependency is imported lazily so it is only
  needed at runtime when the assistant is enabled.
- **Tests:** `server/tests/test_ai_assistant.py` (fake client, no network) —
  parsing, gating, error normalization, and the endpoint 200/404/502/503 paths.
- **Docs:** `docs/ai-assistant.md`.

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

- **M9 — Detection rule packs:** 13 additional rules over the M8 engine
  (no structural change): credential dumping (T1003), LSASS access (T1003.001),
  DLL injection (T1055.001), process hollowing (T1055.012), reflective loading
  (T1620), WMI/scheduled-task/registry/service persistence
  (T1546.003/T1053.005/T1547.001/T1543.003), privilege escalation (T1548),
  lateral movement (T1021), fileless execution (T1055), ransomware behavior
  (T1490). Keyword signatures match over an event "haystack" (summary + raw
  command line + serialized details). Critical rules carry the `isolate`
  response (still gated). Tests: +18 (`tests/test_detection_packs.py`).

- **M10 — Threat intelligence / IOC service:** Org-scoped IOC store
  (`iocs` table: domain/ip/url/sha256/certificate, confidence, source,
  expiration) and YARA/Sigma rule distribution (`intel_rules` table); migration
  `d54bd0f431a1`. New `app/services/threat_intel.py` (upsert, import, expiring
  lookup, prune, indicator extraction, feed-file loader) and
  `/api/admin/intel/*` endpoints behind a new `manage:intel` permission
  (super-admin, SOC manager, threat hunter). The detection engine now extracts
  indicators from every event and raises `ioc_match` detections (severity from
  confidence, ATT&CK by type). Optional startup feed import via
  `SG_INTEL_FEED_FILE`. Tests: +9 (`tests/test_intel.py`). Docs:
  `docs/threat-intel.md`.

- **M13 — Device inventory + posture:** Agents collect a hardware/software/
  services/users snapshot (`silentguard_agent/inventory.py`, every
  `SG_INVENTORY_INTERVAL`s) and POST it to `/api/agent/inventory`. The server
  stores the latest per device (`device_inventory` table, migration
  `cc6ab54ef5b3`) and derives a health/posture summary (disk, agent version,
  isolation). New `GET /api/admin/devices/{id}/inventory` (`read:fleet`,
  org-scoped). Tests: +5 server, +2 agent. Docs: `docs/device-inventory.md`.

- **M14 — Response action framework:** A unified `POST /api/admin/devices/{id}/
  respond` dispatches response actions, each recorded as an immutable
  `ResponseAction` (migration `44af865f5376`) plus an audit entry. Server actions
  (block_domain/ip/hash) apply immediately; agent actions (kill_process,
  delete_file, restore_file, remote_scan, remote_update, isolate/release) queue a
  check-in command correlated by `action_id` and complete when the agent reports
  a result. New `execute:response` permission (responder set),
  `GET /api/admin/responses`, agent `response_handlers.py`, and result ingestion.
  `delete_file` routes through quarantine (recoverable). Tests: +9 server, +6
  agent. Docs: `docs/response-framework.md`.

- **M17 — Visibility & analytics APIs:** New read-only, org-scoped
  `/api/admin/analytics/*` endpoints (`app/services/analytics.py`): fleet
  `summary`, `events-by-day` (threat trends/heatmap), `top-devices` by risk,
  `mitre-coverage` (technique→count), category `timeline`
  (usb/network/registry/process/quarantine), and best-effort `process-tree` from
  pid/ppid. No schema change; aggregation done in Python for SQLite/Postgres
  portability. Tests: +8 (`tests/test_analytics.py`). Docs: `docs/visibility.md`.

- **M18 — Platform integrations & exports:** Configurable per-org outbound
  integrations (`integrations` table, migration `36c93274741b`) forwarding events
  and detections to webhook/Slack/Teams/Discord/Splunk-HEC/syslog-CEF
  destinations above a `min_severity` threshold — best-effort, non-blocking
  (`app/services/integrations.py` with generic/chat/Splunk/CEF formatters).
  Management API `/api/admin/integrations` (+ `/test`) behind a new
  `manage:integrations` permission (super-admin, SOC manager). REST export
  `GET /api/admin/export/events?format=ndjson|cef` for SIEM pull ingestion.
  Dispatch wired into telemetry ingestion. Tests: +9
  (`tests/test_integrations.py`). Docs: `docs/integrations.md`.

- **M16 — Policy engine, device groups & licensing:** New `device_groups` and
  `policies` tables, `devices.group_id`, and `organizations.license_tier`/
  `max_devices` (migration `94382bb5a702`, server-defaulted for existing rows).
  `app/services/policy.py` resolves an effective policy (defaults → org-default →
  group override) delivered in the agent check-in response (`policy`, additive)
  and applied by the agent's new `apply_policy`. Group/policy CRUD + device
  assignment under a new `manage:policy` permission (super-admin, SOC manager);
  `GET /api/admin/devices/{id}/policy` previews the effective policy. Licensing
  placeholder: enrollment returns 402 at the org device cap. Tests: +6 server,
  +3 agent. Docs: `docs/policy-engine.md`.

- **M7 — Password reset + email verification:** New `user_tokens` table and
  `users.email_verified` (migration `056e91da83c2`, server-defaulted). Public
  `/api/auth/password-reset/{request,confirm}` and
  `/api/auth/verify-email/{request,confirm}` endpoints with single-use,
  SHA-256-hashed, expiring tokens; no account enumeration; reset revokes all
  refresh sessions and enforces the password policy. Best-effort email via new
  `app/services/email.py` (reuses `SG_SMTP_*`). Tokens are echoed in responses
  only outside production (or with `SG_EXPOSE_AUTH_TOKENS`). Tests: +8
  (`tests/test_password_reset.py`). Docs: `docs/password-reset.md`.

- **M21 — Security hardening:** SSRF guard (`app/core/ssrf.py`) validates
  admin-configured integration/webhook destinations before any request —
  scheme-restricted, and rejecting loopback/link-local (incl. cloud metadata)/
  multicast/reserved targets always, private ranges optionally
  (`SG_BLOCK_PRIVATE_INTEGRATIONS`); enforced at integration creation. Startup
  now warns on insecure production defaults (demo tokens, unset JWT secret,
  `CORS=*`). New `scripts/generate_sbom.py` (CycloneDX SBOM, stdlib only) and
  dependency-scan guidance. Tests: +8 (`tests/test_security.py`). Docs:
  `docs/security-hardening.md`. (Documents existing SQLi/XSS/CSRF/command-
  injection posture from earlier modules.)

- **M22 — Test tiers + CI:** GitHub Actions workflow (`.github/workflows/ci.yml`)
  running the server suite with an 85% coverage gate + migration-parity check,
  the agent suite, and SBOM generation on every push/PR. Root `Makefile`
  (install/test/coverage/migrate/sbom), registered pytest tier markers
  (unit/api/integration/security), `pytest-cov` added as a test dep. Server line
  coverage ~92%. Docs: `docs/testing.md`.

- **M23 — Documentation automation:** Scripts to export the OpenAPI spec
  (`scripts/export_openapi.py`) and generate DB schema docs from the models
  (`scripts/generate_schema_docs.py` → `docs/schema.md`, 17 tables). New
  `docs/architecture.md` (system diagram + module map), `docs/README.md` (index),
  `docs/deployment.md`, `docs/upgrade-notes.md`; FastAPI app description for
  `/docs`; `make docs` target. Tests: +3 (`tests/test_docs.py`).

**Backward compatibility (M1–M18, plus M7/M21/M22/M23):** No existing API route or
WebSocket event was removed; new endpoints and the check-in `policy` field are
additive, and the admin API keeps accepting the legacy token. The SQLite demo
still auto-creates its schema; production backends run `alembic upgrade head`.
Suite: **188 server + 44 agent = 232 passing (server coverage ~92%).**

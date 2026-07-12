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

**Backward compatibility (M1 + M2):** No API routes, request/response schemas,
or WebSocket events changed. The SQLite demo still auto-creates its schema with
no migration step; only production backends require `alembic upgrade head`,
which the Compose entrypoint runs automatically. Suite: **59 server + 33 agent
= 92 passing.**

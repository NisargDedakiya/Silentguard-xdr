# Upgrade Notes

## Applying an upgrade

1. Pull the new code.
2. Install dependencies: `pip install -r server/requirements.txt`.
3. Apply migrations: `cd server && alembic upgrade head` (Docker Compose runs
   this automatically on server start).
4. Restart the server and (rolling) the agents.

All migrations to date are **additive and non-destructive**: new tables and
nullable/server-defaulted columns only. Existing rows are backfilled in the same
migration (e.g. the multi-tenancy migration creates the default organization and
assigns all existing devices/events/users to it).

## Notable behavioral changes by module

- **M6 (multi-tenancy):** all data is org-scoped. The legacy `X-Admin-Token`
  acts as a cross-org super-admin, so existing single-admin usage is unchanged.
- **M8 (detection):** the `/api/agent/telemetry` response gained an additive
  `detections` count. The agent only checks the HTTP status, so this is
  transparent.
- **M16 (policy):** the agent check-in response gained an additive `policy`
  object the agent applies to its running config.
- **M21 (security):** integration destinations are SSRF-validated at creation;
  loopback/link-local/metadata targets are rejected. Set
  `SG_BLOCK_PRIVATE_INTEGRATIONS=1` to also reject RFC1918 targets.

## Backward compatibility guarantee

No API route, request/response schema field, or WebSocket event has been
**removed or renamed** across the upgrade — only additive changes. The
zero-config SQLite demo continues to work with no migration step; only non-
SQLite backends require `alembic upgrade head`.

## Rolling back

Every migration has a `downgrade()`; `alembic downgrade -1` reverts one step.
Because changes are additive, a rollback drops the new tables/columns without
touching pre-existing data.

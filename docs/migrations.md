# Database Migrations (Module M2)

The backend schema is managed with **Alembic**. This replaces the implicit
`Base.metadata.create_all` as the source of truth for production schema, while
keeping the zero-config SQLite demo working.

## How schema is applied

| Backend | Mechanism |
|---|---|
| SQLite (dev/demo default) | `main.py` calls `create_all` on startup (auto-creates missing tables), so the one-command demo needs no migration step. |
| Postgres / production | Alembic owns the schema. Run `alembic upgrade head`. The server does **not** `create_all` for non-SQLite backends. |

In Docker Compose the server image's entrypoint runs `alembic upgrade head`
before launching uvicorn, so the Postgres schema is created/updated on boot.

## Common commands

Run from the `server/` directory (the app package must be importable). The
database URL comes from `DATABASE_URL` via `app.core.config.settings`.

```bash
# Apply all migrations
alembic upgrade head

# Create a new migration after changing models.py
alembic revision --autogenerate -m "add users table"

# Inspect / move around
alembic current
alembic history
alembic downgrade -1
```

## Conventions

- Every model change ships with a migration in `server/migrations/versions/`.
- Migrations use `render_as_batch=True` so `ALTER`-style changes work on SQLite.
- New columns on existing tables must be **nullable or have a server default**
  and be backfilled in the same migration — never a destructive change (the
  enterprise upgrade adds `org_id`, users, IOCs, inventory, etc. additively).
- `tests/test_migrations.py` asserts that `alembic upgrade head` yields the same
  tables/columns as the ORM models, so history can't silently drift.

## Baseline

`f4070d1d883d_baseline_schema.py` captures the current five tables
(`devices`, `threat_events`, `quarantine_items`, `audit_log`, `blocklist`) and
their indexes. All future migrations descend from it.

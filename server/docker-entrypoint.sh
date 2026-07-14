#!/bin/sh
# Apply database migrations before starting the API server.
#
# For non-SQLite backends (production Postgres) the schema is owned by Alembic;
# `alembic upgrade head` is idempotent and safe to run on every boot. For the
# SQLite fallback the app also auto-creates missing tables, so migrations are a
# no-op belt-and-suspenders there.
set -e

echo "Running database migrations (alembic upgrade head)..."
alembic upgrade head || echo "WARN: alembic upgrade failed; continuing (SQLite fallback auto-creates tables)"

exec uvicorn app.main:app --host 0.0.0.0 --port 8000

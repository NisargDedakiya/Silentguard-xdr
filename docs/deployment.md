# Deployment Guide

## Quick demo (Docker Compose)

```bash
docker compose up --build
```

Server on `:8000`, dashboard on `:3000` (sign in with `silentguard-admin-demo`),
Postgres provisioned automatically. The server image runs `alembic upgrade head`
before starting.

## Production checklist

1. **Secrets** — set independent high-entropy values; the server logs warnings
   on startup if any demo default remains:
   - `SG_ADMIN_TOKEN`, `SG_ENROLL_TOKEN`, `SG_JWT_SECRET`
2. **Environment** — `SG_ENV=production` (enables the secret checks; disables
   dev token exposure).
3. **Database** — `DATABASE_URL=postgresql+psycopg2://…`; run
   `alembic upgrade head` (the Compose entrypoint does this automatically).
4. **CORS** — set `SG_CORS_ORIGINS` to your dashboard origin(s), not `*`.
5. **TLS** — terminate TLS at a reverse proxy (nginx) or pass uvicorn
   `--ssl-*`; set `SG_HSTS_ENABLED=1`.
6. **Bootstrap admin** — set `SG_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` for the
   first super-admin, then create further users via `/api/admin/users`.
7. **Alerting/integrations** — configure `SG_SMTP_*` and/or add integrations;
   set `SG_BLOCK_PRIVATE_INTEGRATIONS=1` if you do not use internal SIEM targets.
8. **Logging** — `SG_LOG_FORMAT=json` (default) for aggregation; each line
   carries a request correlation id.

## Agent deployment

The agent runs **natively** (needs process/firewall/hosts access), not in
Docker. Install as a supervised service so it restarts if killed:

- Linux: `deploy/silentguard-agent.service` (systemd, `Restart=always`)
- Windows: `deploy/SilentGuardAgent-Task.xml` (Task Scheduler)

Set `SG_SERVER_URL`, `SG_ENROLL_TOKEN`; use `SG_DRY_RUN=1` for demos without
root. See the README for the full agent environment reference.

## Scaling note

The current WebSocket hub and login rate-limiter are in-process. Horizontal
scaling to many workers/nodes (Redis fan-out + queues, async workers) is the
subject of roadmap module **M20** and is not yet implemented.

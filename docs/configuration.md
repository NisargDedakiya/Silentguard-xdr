# Configuration & Observability (Module M1)

All backend settings live in one typed object: `server/app/core/config.py`
(`Settings`, built on `pydantic-settings`). Read them via
`from app.core.config import settings`. Every variable below is read from the
process environment; the historical `SG_*` names and defaults are preserved.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SG_ADMIN_TOKEN` | `silentguard-admin-demo` | Shared admin/dashboard token (M4 replaces with users/JWT) |
| `SG_ENROLL_TOKEN` | `silentguard-enroll-demo` | Shared agent enrollment token |
| `DATABASE_URL` | `sqlite:///./silentguard.db` | SQLAlchemy DSN; use `postgresql+psycopg2://…` in production |
| `SG_ENV` | `development` | `production` flips `settings.is_production` |
| `SG_UNRESPONSIVE_SECONDS` | `45` | Liveness threshold for `device_unresponsive` |
| `SG_MONITOR_INTERVAL` | `15` | Liveness sweep interval |
| `SG_LOG_LEVEL` | `INFO` | Root log level |
| `SG_LOG_FORMAT` | `json` | `json` (aggregation) or `console` (readable dev) |
| `SG_CORS_ORIGINS` | `*` | Comma-separated allowed origins; set explicitly in production |
| `SG_HSTS_ENABLED` | `false` | Emit `Strict-Transport-Security` (only meaningful over TLS) |
| `SG_MAX_REQUEST_BYTES` | `5242880` | Reject larger request bodies (0 disables) |

## Logging

`configure_logging()` runs at startup. Each log line carries a `request_id`
correlation id (from the inbound `X-Request-ID` header, or generated). One
structured access log is emitted per request with method, path, status, and
duration. Example (JSON format):

```json
{"ts":"…","level":"INFO","logger":"silentguard.http","message":"request",
 "request_id":"23a1575b…","method":"GET","path":"/api/health","status":200,"duration_ms":18.1}
```

Emit structured fields from any module with the standard logging `extra=`:

```python
from app.core.logging import get_logger
log = get_logger("silentguard.mymodule")
log.info("did a thing", extra={"device_id": device.id, "count": 3})
```

## Security response headers

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy:
same-origin`, and a restrictive `Permissions-Policy`. HSTS is opt-in via
`SG_HSTS_ENABLED=1` for TLS deployments.

## Error envelope

Unhandled exceptions return a stable body without leaking internals:

```json
{"error": {"type": "internal_error", "detail": "An internal error occurred.",
           "request_id": "…"}}
```

The correlation id ties the response back to the logged stack trace.
`HTTPException` responses (e.g. `{"detail": "Invalid admin token"}` on 401)
are unchanged.

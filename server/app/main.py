"""SilentGuard XDR — Command Matrix backend.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000
For TLS 1.3 in production, terminate TLS at the reverse proxy (nginx) or pass
--ssl-keyfile/--ssl-certfile to uvicorn.
"""
import asyncio
import contextlib
import secrets

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .auth import ADMIN_TOKEN
from .core.config import settings
from .core.errors import register_error_handlers
from .core.logging import configure_logging, get_logger
from .core.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecureHeadersMiddleware,
)
from .database import Base, SessionLocal, engine
from .monitor import run_monitor_loop
from .routers import (
    admin,
    agents,
    analytics as analytics_router,
    auth as auth_router,
    detections as detections_router,
    integrations as integrations_router,
    intel as intel_router,
    responses as responses_router,
    users as users_router,
)
from .services.auth_service import maybe_bootstrap_admin
from .services.tenancy import ensure_default_org
from .ws import hub

configure_logging(settings.log_level, settings.log_format)
log = get_logger("silentguard.main")

# Schema management:
#   * SQLite (dev/demo default): auto-create missing tables for zero-config
#     startup, exactly as before — the one-command demo keeps working.
#   * Other backends (production Postgres): schema is owned by Alembic; run
#     `alembic upgrade head`. We do NOT create_all there so migrations remain
#     the single source of truth. See docs/migrations.md.
if settings.database_url.startswith("sqlite"):
    Base.metadata.create_all(bind=engine)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("service starting", extra={"environment": settings.environment})
    with contextlib.suppress(Exception):
        db = SessionLocal()
        try:
            ensure_default_org(db)
            maybe_bootstrap_admin(db)
            if settings.intel_feed_file:
                from .models import DEFAULT_ORG_ID
                from .services import threat_intel
                entries = threat_intel.load_feed_file(settings.intel_feed_file)
                if entries:
                    threat_intel.import_iocs(db, DEFAULT_ORG_ID, entries, "startup-feed")
        finally:
            db.close()
    task = asyncio.create_task(run_monitor_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        log.info("service stopped")


app = FastAPI(title="SilentGuard XDR", version="0.1.0", lifespan=lifespan)

# Middleware runs in reverse registration order for requests; register the
# request-context (correlation id + access log) last so it wraps everything.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(SecureHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestContextMiddleware)

register_error_handlers(app)

app.include_router(auth_router.router)
app.include_router(users_router.router)
app.include_router(detections_router.router)
app.include_router(intel_router.router)
app.include_router(responses_router.router)
app.include_router(analytics_router.router)
app.include_router(integrations_router.router)
app.include_router(agents.router)
app.include_router(admin.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "silentguard-xdr"}


WS_AUTH_TIMEOUT_SECONDS = 10
WS_POLICY_VIOLATION = 1008


@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query(default="")):
    """Live event stream for the dashboard.

    Requires the admin token, supplied either as a `?token=` query parameter
    or as the first text message after connecting. Invalid or missing tokens
    get a policy-violation close before any events are streamed.
    """
    await ws.accept()
    supplied = token
    if not supplied:
        try:
            supplied = await asyncio.wait_for(ws.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS)
        except (asyncio.TimeoutError, WebSocketDisconnect):
            with contextlib.suppress(RuntimeError):
                await ws.close(code=WS_POLICY_VIOLATION)
            return
    if not secrets.compare_digest(supplied, ADMIN_TOKEN):
        await ws.close(code=WS_POLICY_VIOLATION)
        return
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from client
    except WebSocketDisconnect:
        await hub.disconnect(ws)

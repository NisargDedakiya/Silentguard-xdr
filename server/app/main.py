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
from .database import Base, engine
from .monitor import run_monitor_loop
from .routers import admin, agents
from .ws import hub

Base.metadata.create_all(bind=engine)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(run_monitor_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="SilentGuard XDR", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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

"""SilentGuard XDR — Command Matrix backend.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000
For TLS 1.3 in production, terminate TLS at the reverse proxy (nginx) or pass
--ssl-keyfile/--ssl-certfile to uvicorn.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .routers import admin, agents
from .ws import hub

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SilentGuard XDR", version="0.1.0")

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


@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket):
    """Live event stream for the dashboard."""
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive pings from client
    except WebSocketDisconnect:
        await hub.disconnect(ws)

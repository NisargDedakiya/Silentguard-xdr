"""Agent-facing endpoints: enrollment, telemetry ingestion, check-in."""
import datetime
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import ENROLL_TOKEN, require_agent
from ..database import get_db
from ..models import BlocklistEntry, Device, ThreatEvent, utcnow
from ..ws import hub

router = APIRouter(prefix="/api/agent", tags=["agent"])


@router.post("/enroll", response_model=schemas.EnrollResponse)
async def enroll(req: schemas.EnrollRequest, db: Session = Depends(get_db)):
    if not secrets.compare_digest(req.enroll_token, ENROLL_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid enrollment token")
    device = Device(
        id=str(uuid.uuid4()),
        hostname=req.hostname,
        platform=req.platform,
        agent_version=req.agent_version,
    )
    db.add(device)
    db.add(
        ThreatEvent(
            device_id=device.id,
            source="agent",
            severity="info",
            action="enrolled",
            summary=f"Device {req.hostname} enrolled",
        )
    )
    db.commit()
    await hub.broadcast({"type": "device_enrolled", "device_id": device.id, "hostname": device.hostname})
    return schemas.EnrollResponse(device_id=device.id, api_key=device.api_key)


@router.post("/telemetry")
async def telemetry(
    batch: schemas.TelemetryBatch,
    device: Device = Depends(require_agent),
    db: Session = Depends(get_db),
):
    device.last_seen = utcnow()
    # Any telemetry means the agent is alive again → clear an unresponsive flag.
    device.unresponsive_alerted = False
    stored = []
    for ev in batch.events:
        if ev.source == "agent" and ev.action == "stopped":
            device.stopped = True
        elif ev.source == "agent" and ev.action == "started":
            device.stopped = False

        row = ThreatEvent(
            device_id=device.id,
            timestamp=ev.timestamp or utcnow(),
            source=ev.source,
            severity=ev.severity,
            action=ev.action,
            summary=ev.summary,
            details=ev.details,
        )
        db.add(row)
        stored.append(row)
    db.commit()
    for row in stored:
        await hub.broadcast(
            {
                "type": "threat_event",
                "id": row.id,
                "device_id": device.id,
                "hostname": device.hostname,
                "timestamp": row.timestamp,
                "source": row.source,
                "severity": row.severity,
                "action": row.action,
                "summary": row.summary,
                "details": row.details,
            }
        )
    return {"accepted": len(stored)}


@router.get("/checkin", response_model=schemas.CheckinResponse)
async def checkin(device: Device = Depends(require_agent), db: Session = Depends(get_db)):
    """Heartbeat: agent polls for isolation state, queued commands and the
    current fleet blocklist."""
    device.last_seen = utcnow()
    device.unresponsive_alerted = False
    commands = list(device.pending_commands or [])
    device.pending_commands = []
    entries = db.query(BlocklistEntry).all()
    blocklist: dict[str, list[str]] = {"domain": [], "process": [], "port": []}
    for e in entries:
        blocklist.setdefault(e.kind, []).append(e.value)
    db.commit()
    return schemas.CheckinResponse(isolated=device.isolated, commands=commands, blocklist=blocklist)

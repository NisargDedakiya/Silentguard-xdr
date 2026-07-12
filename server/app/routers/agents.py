"""Agent-facing endpoints: enrollment, telemetry ingestion, check-in."""
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import alerting, schemas
from ..auth import ENROLL_TOKEN, require_agent
from ..database import get_db
from ..models import BlocklistEntry, Device, QuarantineItem, ThreatEvent, utcnow
from ..services import events
from ..ws import hub


def _sync_quarantine(db: Session, device: Device, ev: schemas.TelemetryEvent) -> None:
    """Mirror agent quarantine events into the fleet-wide quarantine table."""
    details = ev.details or {}
    qid = details.get("id")
    if not qid:
        return
    if ev.action == "quarantined":
        if db.get(QuarantineItem, qid) is None:
            db.add(
                QuarantineItem(
                    id=qid,
                    device_id=device.id,
                    original_path=details.get("original_path", ""),
                    sha256=details.get("sha256") or "",
                    reason=details.get("reason", ""),
                    verdict=details.get("verdict", "unknown"),
                    status="quarantined",
                )
            )
    elif ev.action in ("restored", "restore_failed"):
        item = db.get(QuarantineItem, qid)
        if item is not None:
            if ev.action == "restored":
                item.status = "restored"
                item.restored_at = utcnow()
            else:
                item.status = "quarantined"  # restore failed → still quarantined

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
        if ev.source in ("quarantine", "file_drop"):
            _sync_quarantine(db, device, ev)

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
        payload = events.broadcast_payload(row, device.hostname)
        await hub.broadcast(payload)
        await alerting.notify_critical(payload)
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

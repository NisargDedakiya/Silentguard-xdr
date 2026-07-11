"""Admin/dashboard endpoints: fleet view, threat timeline, remote isolation,
blocklist management."""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import require_admin
from ..database import get_db
from ..models import BlocklistEntry, Device, ThreatEvent, utcnow
from ..scoring import compute_score, compute_scores
from ..ws import hub

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])

ONLINE_WINDOW = datetime.timedelta(seconds=60)


def _device_out(d: Device, score: dict) -> schemas.DeviceOut:
    last_seen = d.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)
    return schemas.DeviceOut(
        id=d.id,
        hostname=d.hostname,
        platform=d.platform,
        agent_version=d.agent_version,
        enrolled_at=d.enrolled_at,
        last_seen=d.last_seen,
        isolated=d.isolated,
        online=(utcnow() - last_seen) < ONLINE_WINDOW,
        risk_score=score["score"],
        risk_band=score["band"],
    )


@router.get("/devices", response_model=list[schemas.DeviceOut])
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.enrolled_at).all()
    scores = compute_scores(db, [d.id for d in devices])
    return [_device_out(d, scores[d.id]) for d in devices]


@router.get("/events", response_model=list[schemas.EventOut])
def list_events(limit: int = 100, device_id: str | None = None, db: Session = Depends(get_db)):
    q = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc(), ThreatEvent.id.desc())
    if device_id:
        q = q.filter(ThreatEvent.device_id == device_id)
    rows = q.limit(min(limit, 500)).all()
    return [
        schemas.EventOut(
            id=r.id,
            device_id=r.device_id,
            hostname=r.device.hostname if r.device else "",
            timestamp=r.timestamp,
            source=r.source,
            severity=r.severity,
            action=r.action,
            summary=r.summary,
            details=r.details or {},
        )
        for r in rows
    ]


async def _set_isolation(device_id: str, isolated: bool, db: Session):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    device.isolated = isolated
    cmds = list(device.pending_commands or [])
    cmds.append({"command": "isolate" if isolated else "release"})
    device.pending_commands = cmds
    action = "isolation_requested" if isolated else "isolation_released"
    db.add(
        ThreatEvent(
            device_id=device.id,
            source="isolation",
            severity="critical" if isolated else "info",
            action=action,
            summary=f"Admin {'isolated' if isolated else 'released'} device {device.hostname}",
        )
    )
    db.commit()
    await hub.broadcast({"type": "isolation", "device_id": device.id, "isolated": isolated})
    return {"device_id": device.id, "isolated": isolated}


@router.post("/devices/{device_id}/isolate")
async def isolate_device(device_id: str, db: Session = Depends(get_db)):
    return await _set_isolation(device_id, True, db)


@router.post("/devices/{device_id}/release")
async def release_device(device_id: str, db: Session = Depends(get_db)):
    return await _set_isolation(device_id, False, db)


@router.get("/devices/{device_id}/score")
def device_score(device_id: str, db: Session = Depends(get_db)):
    if db.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return compute_score(db, device_id)


@router.get("/blocklist")
def get_blocklist(db: Session = Depends(get_db)):
    return [
        {"id": e.id, "kind": e.kind, "value": e.value, "added_at": e.added_at}
        for e in db.query(BlocklistEntry).order_by(BlocklistEntry.added_at.desc()).all()
    ]


@router.post("/blocklist")
async def add_blocklist(entry: schemas.BlocklistAdd, db: Session = Depends(get_db)):
    if entry.kind not in ("domain", "process", "port"):
        raise HTTPException(status_code=400, detail="kind must be domain, process or port")
    exists = db.query(BlocklistEntry).filter(BlocklistEntry.value == entry.value).first()
    if exists:
        raise HTTPException(status_code=409, detail="Entry already exists")
    row = BlocklistEntry(kind=entry.kind, value=entry.value)
    db.add(row)
    db.commit()
    await hub.broadcast({"type": "blocklist_updated", "kind": entry.kind, "value": entry.value})
    return {"id": row.id, "kind": row.kind, "value": row.value}


@router.delete("/blocklist/{entry_id}")
def delete_blocklist(entry_id: int, db: Session = Depends(get_db)):
    row = db.get(BlocklistEntry, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(row)
    db.commit()
    return {"deleted": entry_id}

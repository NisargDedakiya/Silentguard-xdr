"""Admin/dashboard endpoints: fleet view, threat timeline, remote isolation,
blocklist management."""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import alerting, schemas
from ..auth import require_admin
from ..database import get_db
from ..mitre import technique_for
from ..models import AuditLogEntry, BlocklistEntry, Device, QuarantineItem, ThreatEvent, utcnow
from ..scoring import compute_score, compute_scores
from ..ws import hub

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])

ONLINE_WINDOW = datetime.timedelta(seconds=60)


def _audit(db: Session, actor: str, action: str, target: str, details: dict | None = None) -> None:
    """Queue an audit row; committed atomically with the action it records."""
    db.add(AuditLogEntry(actor=actor, action=action, target=target, details=details or {}))


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
            mitre=technique_for(r.source, r.action),
        )
        for r in rows
    ]


async def _set_isolation(device_id: str, isolated: bool, db: Session, actor: str):
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
    _audit(db, actor, "isolate" if isolated else "release", device.id,
           {"hostname": device.hostname})
    db.commit()
    await hub.broadcast({"type": "isolation", "device_id": device.id, "isolated": isolated})
    if isolated:
        await alerting.notify_critical(
            {
                "severity": "critical",
                "summary": f"Device {device.hostname} isolated by admin",
                "hostname": device.hostname,
                "source": "isolation",
                "action": action,
            }
        )
    return {"device_id": device.id, "isolated": isolated}


@router.post("/devices/{device_id}/isolate")
async def isolate_device(device_id: str, db: Session = Depends(get_db),
                         actor: str = Depends(require_admin)):
    return await _set_isolation(device_id, True, db, actor)


@router.post("/devices/{device_id}/release")
async def release_device(device_id: str, db: Session = Depends(get_db),
                         actor: str = Depends(require_admin)):
    return await _set_isolation(device_id, False, db, actor)


@router.get("/devices/{device_id}/score")
def device_score(device_id: str, db: Session = Depends(get_db)):
    if db.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return compute_score(db, device_id)


@router.get("/quarantine", response_model=list[schemas.QuarantineOut])
def list_quarantine(device_id: str | None = None, db: Session = Depends(get_db)):
    q = db.query(QuarantineItem).order_by(QuarantineItem.quarantined_at.desc())
    if device_id:
        q = q.filter(QuarantineItem.device_id == device_id)
    items = q.all()
    hostnames = {
        d.id: d.hostname
        for d in db.query(Device).filter(Device.id.in_({i.device_id for i in items})).all()
    }
    return [
        schemas.QuarantineOut(
            id=i.id,
            device_id=i.device_id,
            hostname=hostnames.get(i.device_id, ""),
            original_path=i.original_path,
            sha256=i.sha256,
            reason=i.reason,
            verdict=i.verdict,
            status=i.status,
            quarantined_at=i.quarantined_at,
            restored_at=i.restored_at,
        )
        for i in items
    ]


@router.post("/quarantine/{item_id}/restore")
async def restore_quarantine(item_id: str, db: Session = Depends(get_db),
                             actor: str = Depends(require_admin)):
    """Queue a restore command; the agent executes it on next check-in."""
    item = db.get(QuarantineItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    if item.status == "restored":
        raise HTTPException(status_code=409, detail="Item already restored")
    device = db.get(Device, item.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    cmds = list(device.pending_commands or [])
    cmds.append({"command": "restore_quarantine", "id": item.id})
    device.pending_commands = cmds
    item.status = "restore_requested"
    db.add(
        ThreatEvent(
            device_id=device.id,
            source="quarantine",
            severity="info",
            action="restore_requested",
            summary=f"Admin requested restore of {item.original_path} on {device.hostname}",
            details={"id": item.id, "sha256": item.sha256},
        )
    )
    _audit(db, actor, "quarantine_restore", item.id,
           {"device_id": device.id, "original_path": item.original_path, "sha256": item.sha256})
    db.commit()
    await hub.broadcast({"type": "quarantine_updated", "id": item.id, "status": item.status})
    return {"id": item.id, "status": item.status}


@router.get("/blocklist")
def get_blocklist(db: Session = Depends(get_db)):
    return [
        {"id": e.id, "kind": e.kind, "value": e.value, "added_at": e.added_at}
        for e in db.query(BlocklistEntry).order_by(BlocklistEntry.added_at.desc()).all()
    ]


@router.post("/blocklist")
async def add_blocklist(entry: schemas.BlocklistAdd, db: Session = Depends(get_db),
                        actor: str = Depends(require_admin)):
    if entry.kind not in ("domain", "process", "port"):
        raise HTTPException(status_code=400, detail="kind must be domain, process or port")
    exists = db.query(BlocklistEntry).filter(BlocklistEntry.value == entry.value).first()
    if exists:
        raise HTTPException(status_code=409, detail="Entry already exists")
    row = BlocklistEntry(kind=entry.kind, value=entry.value)
    db.add(row)
    _audit(db, actor, "blocklist_add", entry.value, {"kind": entry.kind})
    db.commit()
    await hub.broadcast({"type": "blocklist_updated", "kind": entry.kind, "value": entry.value})
    return {"id": row.id, "kind": row.kind, "value": row.value}


@router.delete("/blocklist/{entry_id}")
def delete_blocklist(entry_id: int, db: Session = Depends(get_db),
                     actor: str = Depends(require_admin)):
    row = db.get(BlocklistEntry, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(row)
    _audit(db, actor, "blocklist_remove", row.value, {"kind": row.kind, "entry_id": entry_id})
    db.commit()
    return {"deleted": entry_id}


@router.get("/audit", response_model=list[schemas.AuditOut])
def list_audit(limit: int = 100, db: Session = Depends(get_db)):
    """Read-only audit trail of admin actions, newest first."""
    rows = (
        db.query(AuditLogEntry)
        .order_by(AuditLogEntry.timestamp.desc(), AuditLogEntry.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [
        schemas.AuditOut(
            id=r.id,
            timestamp=r.timestamp,
            actor=r.actor,
            action=r.action,
            target=r.target,
            details=r.details or {},
        )
        for r in rows
    ]

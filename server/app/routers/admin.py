"""Admin/dashboard endpoints: fleet view, threat timeline, remote isolation,
blocklist management."""
import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import alerting, schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import (
    AuditLogEntry,
    BlocklistEntry,
    Device,
    DeviceInventory,
    QuarantineItem,
    ThreatEvent,
    utcnow,
)
from ..scoring import compute_score, compute_scores
from ..services import events
from ..services.tenancy import owning_org, scope_query
from ..utils.time import aware_utc
from ..ws import hub

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Reusable permission dependencies (each also enforces authentication).
ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ReadAudit = Depends(require_permission(Permission.READ_AUDIT))
WriteIsolation = Depends(require_permission(Permission.WRITE_ISOLATION))
WriteBlocklist = Depends(require_permission(Permission.WRITE_BLOCKLIST))
WriteQuarantine = Depends(require_permission(Permission.WRITE_QUARANTINE))

ONLINE_WINDOW = datetime.timedelta(seconds=60)


def _audit(db: Session, actor: str, action: str, target: str,
           details: dict | None = None, org_id: str | None = None) -> None:
    """Queue an audit row; committed atomically with the action it records."""
    db.add(AuditLogEntry(actor=actor, action=action, target=target,
                         details=details or {}, org_id=org_id))


def _device_out(d: Device, score: dict) -> schemas.DeviceOut:
    last_seen = aware_utc(d.last_seen)
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
def list_devices(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = scope_query(db.query(Device), Device.org_id, principal).order_by(Device.enrolled_at)
    devices = q.all()
    scores = compute_scores(db, [d.id for d in devices])
    return [_device_out(d, scores[d.id]) for d in devices]


@router.get("/events", response_model=list[schemas.EventOut])
def list_events(limit: int = 100, device_id: str | None = None,
                db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc(), ThreatEvent.id.desc())
    q = scope_query(q, ThreatEvent.org_id, principal)
    if device_id:
        q = q.filter(ThreatEvent.device_id == device_id)
    rows = q.limit(min(limit, 500)).all()
    return [events.event_out(r, r.device.hostname if r.device else "") for r in rows]


def _get_device_scoped(db: Session, device_id: str, principal: Principal) -> Device:
    """Fetch a device, enforcing that a non-cross-org caller stays in its own
    tenant (a cross-tenant id is treated as not-found, not forbidden)."""
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if not principal.cross_org and device.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


async def _set_isolation(device_id: str, isolated: bool, db: Session, principal: Principal):
    device = _get_device_scoped(db, device_id, principal)
    device.isolated = isolated
    cmds = list(device.pending_commands or [])
    cmds.append({"command": "isolate" if isolated else "release"})
    device.pending_commands = cmds
    action = "isolation_requested" if isolated else "isolation_released"
    db.add(
        ThreatEvent(
            device_id=device.id,
            org_id=device.org_id,
            source="isolation",
            severity="critical" if isolated else "info",
            action=action,
            summary=f"Admin {'isolated' if isolated else 'released'} device {device.hostname}",
        )
    )
    _audit(db, principal.actor, "isolate" if isolated else "release", device.id,
           {"hostname": device.hostname}, org_id=device.org_id)
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
                         principal: Principal = WriteIsolation):
    return await _set_isolation(device_id, True, db, principal)


@router.post("/devices/{device_id}/release")
async def release_device(device_id: str, db: Session = Depends(get_db),
                         principal: Principal = WriteIsolation):
    return await _set_isolation(device_id, False, db, principal)


@router.get("/devices/{device_id}/score")
def device_score(device_id: str, db: Session = Depends(get_db), principal: Principal = ReadFleet):
    _get_device_scoped(db, device_id, principal)
    return compute_score(db, device_id)


@router.get("/devices/{device_id}/inventory", response_model=schemas.InventoryOut)
def device_inventory(device_id: str, db: Session = Depends(get_db),
                     principal: Principal = ReadFleet):
    device = _get_device_scoped(db, device_id, principal)
    inv = db.get(DeviceInventory, device_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="No inventory reported yet")
    return schemas.InventoryOut(
        device_id=inv.device_id, hostname=device.hostname, os_version=inv.os_version,
        kernel=inv.kernel, cpu_model=inv.cpu_model, cpu_count=inv.cpu_count,
        ram_total_mb=inv.ram_total_mb, disk_total_gb=inv.disk_total_gb,
        disk_free_gb=inv.disk_free_gb, installed_software=inv.installed_software or [],
        running_services=inv.running_services or [], logged_in_users=inv.logged_in_users or [],
        health=inv.health, posture=inv.posture or {}, updated_at=inv.updated_at,
    )


@router.get("/quarantine", response_model=list[schemas.QuarantineOut])
def list_quarantine(device_id: str | None = None, db: Session = Depends(get_db),
                    principal: Principal = ReadFleet):
    q = db.query(QuarantineItem).order_by(QuarantineItem.quarantined_at.desc())
    q = scope_query(q, QuarantineItem.org_id, principal)
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
                             principal: Principal = WriteQuarantine):
    """Queue a restore command; the agent executes it on next check-in."""
    actor = principal.actor
    item = db.get(QuarantineItem, item_id)
    if item is None or (not principal.cross_org and item.org_id != principal.org_id):
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
            org_id=device.org_id,
            source="quarantine",
            severity="info",
            action="restore_requested",
            summary=f"Admin requested restore of {item.original_path} on {device.hostname}",
            details={"id": item.id, "sha256": item.sha256},
        )
    )
    _audit(db, actor, "quarantine_restore", item.id,
           {"device_id": device.id, "original_path": item.original_path, "sha256": item.sha256},
           org_id=item.org_id)
    db.commit()
    await hub.broadcast({"type": "quarantine_updated", "id": item.id, "status": item.status})
    return {"id": item.id, "status": item.status}


@router.get("/blocklist")
def get_blocklist(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = scope_query(db.query(BlocklistEntry), BlocklistEntry.org_id, principal)
    return [
        {"id": e.id, "kind": e.kind, "value": e.value, "added_at": e.added_at}
        for e in q.order_by(BlocklistEntry.added_at.desc()).all()
    ]


@router.post("/blocklist")
async def add_blocklist(entry: schemas.BlocklistAdd, db: Session = Depends(get_db),
                        principal: Principal = WriteBlocklist):
    actor = principal.actor
    org_id = owning_org(principal)
    if entry.kind not in ("domain", "process", "port"):
        raise HTTPException(status_code=400, detail="kind must be domain, process or port")
    value = entry.value.strip()
    if entry.kind == "domain":
        # Reduce a domain or URL to its bare host so blocking covers subdomains
        # consistently (https://evil.example.com/x -> evil.example.com).
        from ..core.netmatch import extract_host
        value = extract_host(value) or value.lower()
        if not value:
            raise HTTPException(status_code=400, detail="invalid domain")
    entry.value = value
    exists = db.query(BlocklistEntry).filter(
        BlocklistEntry.value == entry.value, BlocklistEntry.org_id == org_id
    ).first()
    if exists:
        raise HTTPException(status_code=409, detail="Entry already exists")
    row = BlocklistEntry(kind=entry.kind, value=entry.value, org_id=org_id)
    db.add(row)
    _audit(db, actor, "blocklist_add", entry.value, {"kind": entry.kind}, org_id=org_id)
    db.commit()
    await hub.broadcast({"type": "blocklist_updated", "kind": entry.kind, "value": entry.value})
    return {"id": row.id, "kind": row.kind, "value": row.value}


@router.delete("/blocklist/{entry_id}")
def delete_blocklist(entry_id: int, db: Session = Depends(get_db),
                     principal: Principal = WriteBlocklist):
    row = db.get(BlocklistEntry, entry_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(row)
    _audit(db, principal.actor, "blocklist_remove", row.value,
           {"kind": row.kind, "entry_id": entry_id}, org_id=row.org_id)
    db.commit()
    return {"deleted": entry_id}


@router.get("/entitlements")
def get_entitlements(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    """The caller org's plan and feature entitlements — clients use this to show
    the right UI and which features are unlocked (Individual/Team/Enterprise)."""
    from ..core import plans
    return plans.entitlements_for(db, owning_org(principal))


@router.get("/audit", response_model=list[schemas.AuditOut])
def list_audit(limit: int = 100, db: Session = Depends(get_db), principal: Principal = ReadAudit):
    """Read-only audit trail of admin actions, newest first."""
    q = scope_query(db.query(AuditLogEntry), AuditLogEntry.org_id, principal)
    rows = (
        q.order_by(AuditLogEntry.timestamp.desc(), AuditLogEntry.id.desc())
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

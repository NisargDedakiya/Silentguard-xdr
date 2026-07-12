"""Detection triage endpoints (M8): list findings and acknowledge/resolve them."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import AuditLogEntry, Detection, Device
from ..services.tenancy import scope_query

router = APIRouter(prefix="/api/admin/detections", tags=["detections"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
WriteDetections = Depends(require_permission(Permission.WRITE_DETECTIONS))


@router.get("", response_model=list[schemas.DetectionOut])
def list_detections(limit: int = 100, device_id: str | None = None,
                    status: str | None = None, severity: str | None = None,
                    db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = scope_query(db.query(Detection), Detection.org_id, principal)
    if device_id:
        q = q.filter(Detection.device_id == device_id)
    if status:
        q = q.filter(Detection.status == status)
    if severity:
        q = q.filter(Detection.severity == severity)
    rows = q.order_by(Detection.created_at.desc(), Detection.id.desc()).limit(min(limit, 500)).all()
    hostnames = {
        d.id: d.hostname
        for d in db.query(Device).filter(Device.id.in_({r.device_id for r in rows})).all()
    }
    return [
        schemas.DetectionOut(
            id=r.id, device_id=r.device_id, hostname=hostnames.get(r.device_id, ""),
            rule_id=r.rule_id, name=r.name, severity=r.severity, risk_score=r.risk_score,
            technique_id=r.technique_id, technique_name=r.technique_name,
            status=r.status, created_at=r.created_at, details=r.details or {},
        )
        for r in rows
    ]


def _get_scoped(db: Session, detection_id: int, principal: Principal) -> Detection:
    det = db.get(Detection, detection_id)
    if det is None or (not principal.cross_org and det.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Detection not found")
    return det


def _transition(db: Session, detection_id: int, principal: Principal,
                new_status: str, action: str) -> Detection:
    det = _get_scoped(db, detection_id, principal)
    det.status = new_status
    db.add(AuditLogEntry(actor=principal.actor, action=action,
                         target=str(det.id), details={"rule_id": det.rule_id},
                         org_id=det.org_id))
    db.commit()
    return det


@router.post("/{detection_id}/ack", response_model=schemas.DetectionOut)
def acknowledge(detection_id: int, db: Session = Depends(get_db),
                principal: Principal = WriteDetections):
    det = _transition(db, detection_id, principal, "acknowledged", "detection_ack")
    return schemas.DetectionOut(
        id=det.id, device_id=det.device_id, rule_id=det.rule_id, name=det.name,
        severity=det.severity, risk_score=det.risk_score, technique_id=det.technique_id,
        technique_name=det.technique_name, status=det.status, created_at=det.created_at,
        details=det.details or {},
    )


@router.post("/{detection_id}/resolve", response_model=schemas.DetectionOut)
def resolve(detection_id: int, db: Session = Depends(get_db),
            principal: Principal = WriteDetections):
    det = _transition(db, detection_id, principal, "resolved", "detection_resolve")
    return schemas.DetectionOut(
        id=det.id, device_id=det.device_id, rule_id=det.rule_id, name=det.name,
        severity=det.severity, risk_score=det.risk_score, technique_id=det.technique_id,
        technique_name=det.technique_name, status=det.status, created_at=det.created_at,
        details=det.details or {},
    )

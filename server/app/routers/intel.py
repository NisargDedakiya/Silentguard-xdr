"""Threat-intelligence endpoints (M10): IOC store + YARA/Sigma distribution."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import IOC, AuditLogEntry, IntelRule
from ..services import threat_intel
from ..services.tenancy import owning_org, scope_query

router = APIRouter(prefix="/api/admin/intel", tags=["intel"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ManageIntel = Depends(require_permission(Permission.MANAGE_INTEL))


# -- IOCs -----------------------------------------------------------------
@router.get("/iocs", response_model=list[schemas.IOCOut])
def list_iocs(ioc_type: str | None = None, limit: int = 200,
              db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = scope_query(db.query(IOC), IOC.org_id, principal)
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)
    return q.order_by(IOC.created_at.desc()).limit(min(limit, 1000)).all()


@router.post("/iocs", response_model=schemas.IOCOut, status_code=201)
def create_ioc(body: schemas.IOCCreate, db: Session = Depends(get_db),
               principal: Principal = ManageIntel):
    org_id = owning_org(principal)
    try:
        row = threat_intel.upsert_ioc(
            db, org_id, body.ioc_type, body.value, confidence=body.confidence,
            source=body.source, description=body.description, expires_at=body.expires_at)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    db.add(AuditLogEntry(actor=principal.actor, action="ioc_add",
                         target=f"{body.ioc_type}:{body.value}", org_id=org_id, details={}))
    db.commit()
    db.refresh(row)
    return row


@router.post("/iocs/import")
def import_iocs(body: schemas.IOCImport, db: Session = Depends(get_db),
                principal: Principal = ManageIntel):
    org_id = owning_org(principal)
    count = threat_intel.import_iocs(db, org_id, body.iocs, body.source)
    db.add(AuditLogEntry(actor=principal.actor, action="ioc_import",
                         target=body.source, org_id=org_id, details={"count": count}))
    db.commit()
    return {"imported": count}


@router.delete("/iocs/{ioc_id}")
def delete_ioc(ioc_id: int, db: Session = Depends(get_db), principal: Principal = ManageIntel):
    row = db.get(IOC, ioc_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(row)
    db.add(AuditLogEntry(actor=principal.actor, action="ioc_remove",
                         target=f"{row.ioc_type}:{row.value}", org_id=row.org_id, details={}))
    db.commit()
    return {"deleted": ioc_id}


# -- YARA / Sigma rules ---------------------------------------------------
@router.get("/rules", response_model=list[schemas.IntelRuleOut])
def list_rules(kind: str | None = None, enabled_only: bool = False,
               db: Session = Depends(get_db), principal: Principal = ReadFleet):
    q = scope_query(db.query(IntelRule), IntelRule.org_id, principal)
    if kind:
        q = q.filter(IntelRule.kind == kind)
    if enabled_only:
        q = q.filter(IntelRule.enabled.is_(True))
    return q.order_by(IntelRule.created_at.desc()).all()


@router.post("/rules", response_model=schemas.IntelRuleOut, status_code=201)
def create_rule(body: schemas.IntelRuleCreate, db: Session = Depends(get_db),
                principal: Principal = ManageIntel):
    if body.kind not in ("yara", "sigma"):
        raise HTTPException(status_code=400, detail="kind must be yara or sigma")
    if body.kind == "sigma":
        from ..detection import sigma
        try:
            sigma.validate_sigma(body.content)
        except sigma.SigmaError as exc:
            raise HTTPException(status_code=400, detail=f"invalid Sigma rule: {exc}")
    row = IntelRule(org_id=owning_org(principal), kind=body.kind, name=body.name,
                    content=body.content, enabled=body.enabled)
    db.add(row)
    db.add(AuditLogEntry(actor=principal.actor, action="intel_rule_add",
                         target=f"{body.kind}:{body.name}", org_id=row.org_id, details={}))
    db.commit()
    db.refresh(row)
    return row


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db), principal: Principal = ManageIntel):
    row = db.get(IntelRule, rule_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(row)
    db.commit()
    return {"deleted": rule_id}

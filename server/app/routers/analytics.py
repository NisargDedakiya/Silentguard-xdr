"""Visibility & analytics endpoints (M17). All read-only, org-scoped."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..services import analytics, compliance

router = APIRouter(prefix="/api/admin/analytics", tags=["analytics"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ReadAudit = Depends(require_permission(Permission.READ_AUDIT))


@router.get("/summary")
def get_summary(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    return analytics.summary(db, principal)


@router.get("/events-by-day")
def get_events_by_day(days: int = 14, db: Session = Depends(get_db),
                      principal: Principal = ReadFleet):
    return analytics.events_by_day(db, principal, days)


@router.get("/top-devices")
def get_top_devices(limit: int = 10, db: Session = Depends(get_db),
                    principal: Principal = ReadFleet):
    return analytics.top_devices(db, principal, limit)


@router.get("/mitre-coverage")
def get_mitre_coverage(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    return analytics.mitre_coverage(db, principal)


@router.get("/compliance-report", response_model=schemas.ComplianceReportOut)
def get_compliance_report(days: int = 30, db: Session = Depends(get_db),
                          principal: Principal = ReadAudit):
    """Executive/compliance posture report (v1.4): fleet health, detection
    backlog, threat-intel coverage, and pass/warn/fail control checks with a
    headline score. Requires the audit-read permission."""
    from ..core import plans
    from ..services.tenancy import owning_org
    if not plans.feature_enabled(db, owning_org(principal), "compliance_reports"):
        raise HTTPException(status_code=402,
                            detail="Compliance reporting requires the Team or Enterprise plan")
    return compliance.build_compliance_report(db, principal, days)


@router.get("/timeline")
def get_timeline(category: str, limit: int = 100, db: Session = Depends(get_db),
                 principal: Principal = ReadFleet):
    try:
        return analytics.timeline(db, principal, category, limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/process-tree")
def get_process_tree(device_id: str, db: Session = Depends(get_db),
                     principal: Principal = ReadFleet):
    return analytics.process_tree(db, principal, device_id)

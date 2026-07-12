"""Visibility & analytics endpoints (M17). All read-only, org-scoped."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..services import analytics

router = APIRouter(prefix="/api/admin/analytics", tags=["analytics"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))


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

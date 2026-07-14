"""Individual / home mode — a simplified 'is my device protected?' view.

For the Individual plan (and anyone who wants the at-a-glance picture), this
collapses the full SOC console into one friendly summary: how many devices, are
they protected, any active threats, and the plan. It is org-scoped like every
other endpoint, so a home user sees only their own devices.
"""
import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..core import plans
from ..database import get_db
from ..models import Detection, Device
from ..services.tenancy import owning_org, scope_query
from ..utils.time import aware_utc

router = APIRouter(prefix="/api/home", tags=["home"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))


@router.get("/summary")
def home_summary(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    devices = scope_query(db.query(Device), Device.org_id, principal).all()
    now = datetime.datetime.now(datetime.timezone.utc)
    online = sum(1 for d in devices if (now - aware_utc(d.last_seen)).total_seconds() < 120)
    isolated = sum(1 for d in devices if d.isolated)
    open_critical = (
        scope_query(db.query(Detection), Detection.org_id, principal)
        .filter(Detection.severity == "critical",
                Detection.status.in_(("new", "acknowledged")))
        .count()
    )
    ent = plans.entitlements_for(db, owning_org(principal))
    protected = open_critical == 0 and isolated == 0
    return {
        "plan": ent["plan"],
        "plan_label": ent.get("label", ent["plan"].title()),
        "status": "protected" if protected else "attention",
        "devices": len(devices),
        "online": online,
        "isolated": isolated,
        "open_critical": open_critical,
        "device_limit": ent["max_devices"],   # 0 = unlimited
    }

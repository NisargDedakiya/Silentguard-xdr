"""Device group + policy management (M16)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import AuditLogEntry, Device, DeviceGroup, Policy
from ..services.policy import resolve_effective_policy
from ..services.tenancy import owning_org, scope_query

router = APIRouter(prefix="/api/admin", tags=["policies"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ManagePolicy = Depends(require_permission(Permission.MANAGE_POLICY))


# -- device groups --------------------------------------------------------
@router.get("/groups", response_model=list[schemas.DeviceGroupOut])
def list_groups(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    return scope_query(db.query(DeviceGroup), DeviceGroup.org_id, principal).all()


@router.post("/groups", response_model=schemas.DeviceGroupOut, status_code=201)
def create_group(body: schemas.DeviceGroupCreate, db: Session = Depends(get_db),
                 principal: Principal = ManagePolicy):
    org_id = owning_org(principal)
    from ..core import plans
    if not plans.feature_enabled(db, org_id, "device_groups"):
        raise HTTPException(status_code=402,
                            detail="Device groups require the Team or Enterprise plan")
    current = db.query(DeviceGroup).filter(DeviceGroup.org_id == org_id).count()
    if not plans.within_limit(db, org_id, "max_groups", current):
        raise HTTPException(status_code=402, detail="Group limit reached for this plan")
    if db.query(DeviceGroup).filter(DeviceGroup.org_id == org_id,
                                    DeviceGroup.name == body.name).first():
        raise HTTPException(status_code=409, detail="Group already exists")
    row = DeviceGroup(org_id=org_id, name=body.name, description=body.description)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db),
                 principal: Principal = ManagePolicy):
    row = db.get(DeviceGroup, group_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Group not found")
    # Detach devices and delete the group's policies.
    for dev in db.query(Device).filter(Device.group_id == group_id).all():
        dev.group_id = None
    for pol in db.query(Policy).filter(Policy.group_id == group_id).all():
        db.delete(pol)
    db.delete(row)
    db.commit()
    return {"deleted": group_id}


@router.post("/devices/{device_id}/group")
def assign_group(device_id: str, body: schemas.GroupAssign, db: Session = Depends(get_db),
                 principal: Principal = ManagePolicy):
    device = db.get(Device, device_id)
    if device is None or (not principal.cross_org and device.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Device not found")
    if body.group_id is not None:
        group = db.get(DeviceGroup, body.group_id)
        if group is None or group.org_id != device.org_id:
            raise HTTPException(status_code=400, detail="Group not in device's organization")
    device.group_id = body.group_id
    db.add(AuditLogEntry(actor=principal.actor, action="device_group_assign",
                         target=device_id, org_id=device.org_id,
                         details={"group_id": body.group_id}))
    db.commit()
    return {"device_id": device_id, "group_id": body.group_id}


# -- policies -------------------------------------------------------------
@router.get("/policies", response_model=list[schemas.PolicyOut])
def list_policies(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    return scope_query(db.query(Policy), Policy.org_id, principal).order_by(Policy.id).all()


@router.post("/policies", response_model=schemas.PolicyOut, status_code=201)
def create_policy(body: schemas.PolicyCreate, db: Session = Depends(get_db),
                  principal: Principal = ManagePolicy):
    org_id = owning_org(principal)
    if body.group_id is not None:
        group = db.get(DeviceGroup, body.group_id)
        if group is None or group.org_id != org_id:
            raise HTTPException(status_code=400, detail="Group not in your organization")
    row = Policy(org_id=org_id, name=body.name, group_id=body.group_id,
                 settings=body.settings, enabled=body.enabled)
    db.add(row)
    db.add(AuditLogEntry(actor=principal.actor, action="policy_create",
                         target=body.name, org_id=org_id, details={"group_id": body.group_id}))
    db.commit()
    db.refresh(row)
    return row


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db),
                  principal: Principal = ManagePolicy):
    row = db.get(Policy, policy_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(row)
    db.commit()
    return {"deleted": policy_id}


@router.get("/devices/{device_id}/policy")
def effective_policy(device_id: str, db: Session = Depends(get_db),
                     principal: Principal = ReadFleet):
    device = db.get(Device, device_id)
    if device is None or (not principal.cross_org and device.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Device not found")
    return resolve_effective_policy(db, device)

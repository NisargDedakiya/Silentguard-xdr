"""Organization management (Enterprise / Groups / Individuals).

Super-admin surface to administer tenants: create organizations, set their plan
(individual / team / enterprise), adjust caps, and deactivate them. Each org is
an isolated tenant; a member's data is scoped to their org, while a super-admin
sees and manages all of them.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..core.plans import PLAN_NAMES
from ..database import get_db
from ..models import AuditLogEntry, Device, Organization, User

router = APIRouter(prefix="/api/admin/organizations", tags=["organizations"])

ManageOrgs = Depends(require_permission(Permission.MANAGE_ORGS))


def _out(db: Session, org: Organization) -> schemas.OrganizationOut:
    return schemas.OrganizationOut(
        id=org.id, name=org.name, slug=org.slug, plan=org.plan,
        max_devices=org.max_devices, is_active=org.is_active,
        device_count=db.query(Device).filter(Device.org_id == org.id).count(),
        user_count=db.query(User).filter(User.org_id == org.id).count(),
        created_at=org.created_at,
    )


@router.get("", response_model=list[schemas.OrganizationOut])
def list_orgs(db: Session = Depends(get_db), principal: Principal = ManageOrgs):
    rows = db.query(Organization).order_by(Organization.created_at).all()
    return [_out(db, o) for o in rows]


@router.post("", response_model=schemas.OrganizationOut, status_code=201)
def create_org(body: schemas.OrganizationCreate, db: Session = Depends(get_db),
               principal: Principal = ManageOrgs):
    if body.plan not in PLAN_NAMES:
        raise HTTPException(status_code=400, detail=f"plan must be one of {list(PLAN_NAMES)}")
    slug = body.slug.strip().lower()
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise HTTPException(status_code=409, detail="An organization with that slug exists")
    org = Organization(name=body.name.strip(), slug=slug, plan=body.plan,
                       max_devices=max(0, body.max_devices))
    db.add(org)
    db.add(AuditLogEntry(actor=principal.actor, action="org_create", target=slug,
                         details={"plan": body.plan}, org_id=org.id))
    db.commit()
    db.refresh(org)
    return _out(db, org)


@router.get("/{org_id}", response_model=schemas.OrganizationOut)
def get_org(org_id: str, db: Session = Depends(get_db), principal: Principal = ManageOrgs):
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _out(db, org)


@router.patch("/{org_id}", response_model=schemas.OrganizationOut)
def update_org(org_id: str, body: schemas.OrganizationUpdate,
               db: Session = Depends(get_db), principal: Principal = ManageOrgs):
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if body.plan is not None:
        if body.plan not in PLAN_NAMES:
            raise HTTPException(status_code=400, detail=f"plan must be one of {list(PLAN_NAMES)}")
        org.plan = body.plan
    if body.name is not None:
        org.name = body.name.strip()
    if body.max_devices is not None:
        org.max_devices = max(0, body.max_devices)
    if body.is_active is not None:
        org.is_active = body.is_active
    db.add(AuditLogEntry(actor=principal.actor, action="org_update", target=org.slug,
                         details={"plan": org.plan, "is_active": org.is_active}, org_id=org.id))
    db.commit()
    db.refresh(org)
    return _out(db, org)

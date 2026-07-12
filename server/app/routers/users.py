"""User management endpoints (M5). Restricted to the MANAGE_USERS permission
(super-admin, or the legacy admin token)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import AuditLogEntry, User
from ..services import auth_service

router = APIRouter(prefix="/api/admin/users", tags=["users"])

ManageUsers = Depends(require_permission(Permission.MANAGE_USERS))


@router.get("", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), _: Principal = ManageUsers):
    return db.query(User).order_by(User.created_at).all()


@router.post("", response_model=schemas.UserOut, status_code=201)
def create_user(body: schemas.UserCreate, db: Session = Depends(get_db),
                principal: Principal = ManageUsers):
    try:
        user = auth_service.create_user(db, body.email, body.password, body.role)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    db.add(AuditLogEntry(actor=principal.actor, action="user_create",
                         target=user.email, details={"role": user.role}))
    db.commit()
    return user


@router.post("/{user_id}/disable", response_model=schemas.UserOut)
def disable_user(user_id: str, db: Session = Depends(get_db),
                 principal: Principal = ManageUsers):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    db.add(AuditLogEntry(actor=principal.actor, action="user_disable",
                         target=user.email, details={}))
    db.commit()
    return user

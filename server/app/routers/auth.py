"""Authentication endpoints: login, refresh, logout, current user (M4)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import get_current_user
from ..database import get_db
from ..models import AuditLogEntry, User
from ..services import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _audit(db: Session, actor: str, action: str, target: str, org_id: str | None = None) -> None:
    db.add(AuditLogEntry(actor=actor, action=action, target=target, details={}, org_id=org_id))
    db.commit()


@router.post("/login", response_model=schemas.TokenResponse)
def login(body: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    try:
        user = auth_service.authenticate(db, body.email, body.password, _client_key(request))
        tokens = auth_service.issue_tokens(db, user)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    _audit(db, f"user:{user.id}", "login", user.email, org_id=user.org_id)
    return tokens


@router.post("/refresh", response_model=schemas.TokenResponse)
def refresh(body: schemas.RefreshRequest, db: Session = Depends(get_db)):
    try:
        return auth_service.refresh_tokens(db, body.refresh_token)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/logout")
def logout(body: schemas.RefreshRequest, db: Session = Depends(get_db)):
    auth_service.revoke_refresh_token(db, body.refresh_token)
    return {"status": "logged_out"}


@router.get("/me", response_model=schemas.UserOut)
def me(user: User = Depends(get_current_user)):
    return user

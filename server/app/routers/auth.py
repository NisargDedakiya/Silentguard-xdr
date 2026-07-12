"""Authentication endpoints: login, refresh, logout, current user (M4)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import get_current_user
from ..core.config import settings
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


@router.post("/password-reset/request")
def password_reset_request(body: schemas.PasswordResetRequest, request: Request,
                           db: Session = Depends(get_db)):
    """Always returns 200 (no account enumeration). A token is emailed when the
    address exists; outside production the raw token is echoed for convenience."""
    if auth_service._rate_limited(_client_key(request)):
        raise HTTPException(status_code=429, detail="Too many requests")
    raw = auth_service.request_password_reset(db, body.email)
    resp = {"status": "if the email exists, a reset link has been sent"}
    if raw and settings.should_expose_tokens:
        resp["token"] = raw
    return resp


@router.post("/password-reset/confirm")
def password_reset_confirm(body: schemas.PasswordResetConfirm, db: Session = Depends(get_db)):
    try:
        ok = auth_service.reset_password(db, body.token, body.new_password)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    return {"status": "password_updated"}


@router.post("/verify-email/request")
def verify_email_request(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    raw = auth_service.request_email_verification(db, user)
    resp = {"status": "verification email sent"}
    if settings.should_expose_tokens:
        resp["token"] = raw
    return resp


@router.post("/verify-email/confirm")
def verify_email_confirm(body: schemas.EmailVerifyRequest, db: Session = Depends(get_db)):
    if not auth_service.verify_email(db, body.token):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    return {"status": "email_verified"}

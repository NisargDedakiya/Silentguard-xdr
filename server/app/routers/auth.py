"""Authentication endpoints: login, refresh, logout, current user (M4)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import get_current_user
from ..core.config import settings
from ..database import get_db
from ..models import AuditLogEntry, User
from ..services import auth_service, sso

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
        auth_service.enforce_mfa(user, body.mfa_code)
        tokens = auth_service.issue_tokens(db, user)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    _audit(db, f"user:{user.id}", "login", user.email, org_id=user.org_id)
    return tokens


@router.get("/sso/login", response_model=schemas.SsoLoginResponse)
def sso_login():
    """Begin OIDC SSO: returns the IdP authorization URL to redirect the user to."""
    if not sso.is_available():
        raise HTTPException(status_code=503, detail="SSO is not configured")
    try:
        return schemas.SsoLoginResponse(authorization_url=sso.begin_login())
    except sso.SSOError as exc:
        raise HTTPException(status_code=502, detail=f"SSO error: {exc}")


@router.get("/sso/callback", response_model=schemas.TokenResponse)
def sso_callback(code: str, state: str, db: Session = Depends(get_db)):
    """OIDC redirect target: exchange the code and issue SilentGuard tokens."""
    if not sso.is_available():
        raise HTTPException(status_code=503, detail="SSO is not configured")
    try:
        tokens = sso.login(db, code, state)
    except sso.SSOError as exc:
        raise HTTPException(status_code=401, detail=f"SSO login failed: {exc}")
    _audit(db, "sso", "sso_login", code[:8])
    return tokens


@router.get("/mfa/status", response_model=schemas.MfaStatus)
def mfa_status(user: User = Depends(get_current_user)):
    return schemas.MfaStatus(enabled=user.mfa_enabled)


@router.post("/mfa/setup", response_model=schemas.MfaSetupResponse)
def mfa_setup(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Begin TOTP enrolment: returns the secret + otpauth URI to load into an
    authenticator. MFA is not enforced until confirmed via /mfa/activate."""
    return auth_service.mfa_begin_setup(db, user)


@router.post("/mfa/activate", response_model=schemas.MfaStatus)
def mfa_activate(body: schemas.MfaCodeRequest, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    try:
        auth_service.mfa_activate(db, user, body.code)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    _audit(db, f"user:{user.id}", "mfa_enable", user.email, org_id=user.org_id)
    return schemas.MfaStatus(enabled=True)


@router.post("/mfa/disable", response_model=schemas.MfaStatus)
def mfa_disable(body: schemas.MfaCodeRequest, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    try:
        auth_service.mfa_disable(db, user, body.code)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    _audit(db, f"user:{user.id}", "mfa_disable", user.email, org_id=user.org_id)
    return schemas.MfaStatus(enabled=False)


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

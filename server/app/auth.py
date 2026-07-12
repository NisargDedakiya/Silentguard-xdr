"""Authentication helpers.

Agents authenticate with a per-device API key issued at enrollment
(X-Agent-Key header). Admin/dashboard requests authenticate with EITHER a JWT
access token (``Authorization: Bearer <token>``, M4) OR the legacy shared admin
token (``X-Admin-Token`` header). The legacy path is retained for backward
compatibility while deployments migrate to user accounts.
"""
import hashlib
import secrets
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .core.config import settings
from .core.permissions import Permission, has_permission
from .core.roles import Role
from .core.security import TokenError, decode_token
from .database import get_db
from .models import Device, User

# Re-exported at module level for backward compatibility (tests and callers
# import these names directly). Values come from the centralized settings.
ENROLL_TOKEN = settings.enroll_token
ADMIN_TOKEN = settings.admin_token


def token_fingerprint(token: str) -> str:
    """Short, non-reversible identifier for the acting credential — safe to
    store in audit logs without leaking the token itself."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def _bearer_token(authorization: str) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of an admin request: an audit actor string, the
    role used for RBAC checks, and the tenant scope. A JWT resolves to the
    user's role/org; the legacy admin token resolves to a cross-org SUPER_ADMIN
    for backward compatibility (sees every organization)."""

    actor: str
    role: Role
    user_id: str | None = None
    org_id: str | None = None
    cross_org: bool = False


def current_principal(
    x_admin_token: str = Header(default=""),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Principal:
    """Authenticate an admin caller (JWT or legacy token) and return a Principal.
    Raises 401 when neither credential is valid."""
    bearer = _bearer_token(authorization)
    if bearer:
        try:
            payload = decode_token(bearer, expected_type="access")
        except TokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = db.get(User, payload.get("sub", ""))
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User is no longer active")
        try:
            role = Role(user.role)
        except ValueError:
            role = Role.READ_ONLY
        # Super-admins operate across all organizations; other roles are scoped
        # to their own org.
        return Principal(actor=f"user:{user.id}", role=role, user_id=user.id,
                         org_id=user.org_id, cross_org=(role == Role.SUPER_ADMIN))

    if ADMIN_TOKEN and secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        return Principal(actor=token_fingerprint(x_admin_token), role=Role.SUPER_ADMIN,
                         cross_org=True)

    raise HTTPException(status_code=401, detail="Invalid admin token")


def require_permission(permission: Permission):
    """Return a dependency that authenticates the caller and enforces `permission`,
    returning the Principal (so handlers can read `.actor` for auditing)."""

    def _dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not has_permission(principal.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{principal.role.value}' lacks permission '{permission.value}'",
            )
        return principal

    return _dependency


def require_admin(
    x_admin_token: str = Header(default=""),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> str:
    """Authorize an admin request and return an actor fingerprint for auditing.

    Accepts a JWT access token first (identifying a real user), then falls back
    to the legacy static admin token. Returns ``user:<id>`` for JWT callers or
    the token fingerprint for legacy callers.
    """
    bearer = _bearer_token(authorization)
    if bearer:
        try:
            payload = decode_token(bearer, expected_type="access")
        except TokenError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = db.get(User, payload.get("sub", ""))
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User is no longer active")
        return f"user:{user.id}"

    if ADMIN_TOKEN and secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        return token_fingerprint(x_admin_token)

    raise HTTPException(status_code=401, detail="Invalid admin token")


def get_current_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> User:
    """Require a valid JWT access token and return the User (no legacy-token
    fallback — endpoints that need a real identity use this)."""
    bearer = _bearer_token(authorization)
    if not bearer:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = decode_token(bearer, expected_type="access")
    except TokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, payload.get("sub", ""))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User is no longer active")
    return user


def require_agent(
    x_agent_key: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Device:
    device = db.query(Device).filter(Device.api_key == x_agent_key).first()
    if device is None:
        raise HTTPException(status_code=401, detail="Invalid agent key")
    return device

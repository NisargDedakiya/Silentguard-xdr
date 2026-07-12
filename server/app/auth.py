"""Authentication helpers.

Agents authenticate with a per-device API key issued at enrollment
(X-Agent-Key header). Admin/dashboard requests authenticate with EITHER a JWT
access token (``Authorization: Bearer <token>``, M4) OR the legacy shared admin
token (``X-Admin-Token`` header). The legacy path is retained for backward
compatibility while deployments migrate to user accounts.
"""
import hashlib
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .core.config import settings
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

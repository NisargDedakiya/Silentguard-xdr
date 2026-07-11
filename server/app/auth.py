"""Authentication helpers.

Agents authenticate with a per-device API key issued at enrollment
(X-Agent-Key header). Admin/dashboard requests authenticate with a shared
admin token (X-Admin-Token header). Both are simple bearer-style secrets for
the MVP; the enterprise roadmap replaces the admin token with RBAC/SSO/MFA.
"""
import hashlib
import os
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .database import get_db
from .models import Device

ENROLL_TOKEN = os.environ.get("SG_ENROLL_TOKEN", "silentguard-enroll-demo")
ADMIN_TOKEN = os.environ.get("SG_ADMIN_TOKEN", "silentguard-admin-demo")


def token_fingerprint(token: str) -> str:
    """Short, non-reversible identifier for the acting credential — safe to
    store in audit logs without leaking the token itself."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def require_admin(x_admin_token: str = Header(default="")) -> str:
    if not secrets.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid admin token")
    return token_fingerprint(x_admin_token)


def require_agent(
    x_agent_key: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Device:
    device = db.query(Device).filter(Device.api_key == x_agent_key).first()
    if device is None:
        raise HTTPException(status_code=401, detail="Invalid agent key")
    return device

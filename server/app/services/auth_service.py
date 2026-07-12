"""Authentication service: user creation, login (with lockout + rate limit),
token issuance/refresh/revocation.

Business logic lives here (not in the router) so it is unit-testable and
reusable from a CLI or bootstrap path. Rate limiting is a best-effort in-process
sliding window; it moves to Redis in M20 for multi-worker correctness.
"""
import collections
import datetime
import threading

from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.logging import get_logger
from ..core.roles import Role
from ..core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from ..models import RefreshToken, User, utcnow
from ..utils.time import aware_utc

log = get_logger("silentguard.auth")


class AuthError(Exception):
    """Domain error with an HTTP-friendly status code."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


# -- rate limiting --------------------------------------------------------
_attempts: dict[str, "collections.deque[float]"] = collections.defaultdict(collections.deque)
_attempts_lock = threading.Lock()


def _rate_limited(key: str) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    window = settings.login_rate_window_seconds
    with _attempts_lock:
        dq = _attempts[key]
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= settings.login_rate_limit:
            return True
        dq.append(now)
        return False


def reset_rate_limit() -> None:
    """Test helper: clear the in-process rate-limit state."""
    with _attempts_lock:
        _attempts.clear()


# -- password policy ------------------------------------------------------
def validate_password(password: str) -> None:
    if len(password) < settings.password_min_length:
        raise AuthError(400, f"Password must be at least {settings.password_min_length} characters")
    if password.lower() == password or password.upper() == password or password.isalpha():
        raise AuthError(400, "Password must mix upper/lower case and include a non-letter")


def create_user(db: Session, email: str, password: str, role: str = Role.READ_ONLY.value) -> User:
    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise AuthError(409, "A user with that email already exists")
    if role not in {r.value for r in Role}:
        raise AuthError(400, f"Unknown role '{role}'")
    validate_password(password)
    user = User(email=email, hashed_password=hash_password(password), role=role)
    db.add(user)
    db.commit()
    log.info("user created", extra={"email": email, "role": role})
    return user


# -- login ----------------------------------------------------------------
def authenticate(db: Session, email: str, password: str, client_key: str = "") -> User:
    if _rate_limited(client_key or email):
        raise AuthError(429, "Too many login attempts; slow down")
    email = email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    now = utcnow()

    # Generic failure for unknown users (no account enumeration).
    if user is None:
        raise AuthError(401, "Invalid credentials")
    if not user.is_active:
        raise AuthError(403, "Account is disabled")
    if user.locked_until and aware_utc(user.locked_until) > now:
        raise AuthError(423, "Account is temporarily locked")

    if not verify_password(password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_max_attempts:
            user.locked_until = now + datetime.timedelta(seconds=settings.login_lockout_seconds)
            user.failed_login_count = 0
            log.warning("account locked", extra={"email": email})
        db.commit()
        raise AuthError(401, "Invalid credentials")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()
    return user


# -- tokens ---------------------------------------------------------------
def issue_tokens(db: Session, user: User) -> dict:
    access = create_access_token(subject=user.id, role=user.role, extra={"email": user.email})
    refresh, jti, expires_at = create_refresh_token(subject=user.id)
    db.add(RefreshToken(jti=jti, user_id=user.id, expires_at=expires_at))
    db.commit()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_ttl_seconds,
    }


def refresh_tokens(db: Session, refresh_token: str) -> dict:
    from ..core.security import TokenError

    try:
        payload = decode_token(refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise AuthError(401, "Invalid refresh token") from exc
    record = db.get(RefreshToken, payload.get("jti", ""))
    if record is None or record.revoked:
        raise AuthError(401, "Refresh token is not recognized")
    if aware_utc(record.expires_at) <= utcnow():
        raise AuthError(401, "Refresh token has expired")
    user = db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise AuthError(401, "User is no longer active")
    # Rotate: revoke the old session, issue a fresh pair.
    record.revoked = True
    db.commit()
    return issue_tokens(db, user)


def revoke_refresh_token(db: Session, refresh_token: str) -> None:
    from ..core.security import TokenError

    try:
        payload = decode_token(refresh_token, expected_type="refresh")
    except TokenError:
        return  # logout is idempotent; nothing to revoke
    record = db.get(RefreshToken, payload.get("jti", ""))
    if record is not None and not record.revoked:
        record.revoked = True
        db.commit()


def maybe_bootstrap_admin(db: Session) -> None:
    """Create a super-admin from env on first run if there are no users."""
    if not (settings.bootstrap_admin_email and settings.bootstrap_admin_password):
        return
    if db.query(User).count() > 0:
        return
    try:
        create_user(db, settings.bootstrap_admin_email,
                    settings.bootstrap_admin_password, Role.SUPER_ADMIN.value)
        log.info("bootstrapped super-admin", extra={"email": settings.bootstrap_admin_email})
    except AuthError as exc:
        log.warning("bootstrap admin skipped: %s", exc.detail)

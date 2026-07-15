"""Authentication service: user creation, login (with lockout + rate limit),
token issuance/refresh/revocation.

Business logic lives here (not in the router) so it is unit-testable and
reusable from a CLI or bootstrap path. Rate limiting is a best-effort in-process
sliding window; it moves to Redis in M20 for multi-worker correctness.
"""
import collections
import datetime
import hashlib
import secrets
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
from ..models import DEFAULT_ORG_ID, RefreshToken, User, UserToken, utcnow
from ..services import email as email_service
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


def create_user(db: Session, email: str, password: str, role: str = Role.READ_ONLY.value,
                org_id: str = DEFAULT_ORG_ID) -> User:
    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise AuthError(409, "A user with that email already exists")
    if role not in {r.value for r in Role}:
        raise AuthError(400, f"Unknown role '{role}'")
    validate_password(password)
    user = User(email=email, hashed_password=hash_password(password), role=role, org_id=org_id)
    db.add(user)
    db.commit()
    log.info("user created", extra={"email": email, "role": role, "org_id": org_id})
    return user


# -- self-service signup + invitations (SaaS team model) ------------------
def _unique_slug(db: Session, name: str) -> str:
    from ..models import Organization

    base = "".join(c if c.isalnum() else "-" for c in name.strip().lower()).strip("-") or "org"
    base = base[:48]
    slug = base
    i = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        i += 1
        slug = f"{base}-{i}"
    return slug


def signup(db: Session, email: str, password: str, org_name: str,
           plan: str = "individual") -> User:
    """Self-service registration: create a new organization and its OWNER.

    Only self-serve plans (individual/team) are allowed; enterprise is sales-led.
    """
    from ..models import Organization

    plan = plan if plan in ("individual", "team") else "individual"
    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise AuthError(409, "A user with that email already exists")
    validate_password(password)
    org = Organization(name=(org_name.strip() or email), slug=_unique_slug(db, org_name or email),
                       plan=plan)
    db.add(org)
    db.flush()  # assign org.id
    user = User(email=email, hashed_password=hash_password(password),
                role=Role.OWNER.value, org_id=org.id, email_verified=False)
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info("signup", extra={"email": email, "org": org.slug, "plan": plan})
    return user


def invite_member(db: Session, org_id: str, email: str, role: str) -> tuple[User, str]:
    """Invite a teammate to an org: create a pending (inactive) member and issue a
    single-use invite token. The member activates by setting a password."""
    email = email.strip().lower()
    if role not in {r.value for r in Role}:
        raise AuthError(400, f"Unknown role '{role}'")
    if db.query(User).filter(User.email == email).first():
        raise AuthError(409, "A user with that email already exists")
    user = User(email=email, hashed_password=hash_password(secrets.token_urlsafe(24)),
                role=role, org_id=org_id, is_active=False)
    db.add(user)
    db.commit()
    db.refresh(user)
    raw = _issue_token(db, user, "invite", 7 * 86400)
    email_service.send_email(email, "You're invited to SilentGuard",
                             f"Accept your invite with this token: {raw}")
    return user, raw


def accept_invite(db: Session, raw: str, password: str) -> User:
    """Activate an invited member by setting their password."""
    user = _consume_token(db, raw, "invite")
    if user is None:
        raise AuthError(400, "Invalid or expired invitation")
    validate_password(password)
    user.hashed_password = hash_password(password)
    user.is_active = True
    user.email_verified = True
    db.commit()
    db.refresh(user)
    log.info("invite accepted", extra={"email": user.email})
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


# -- multi-factor authentication (TOTP) -----------------------------------
def mfa_begin_setup(db: Session, user: User) -> dict:
    """Generate (or reuse a pending) TOTP secret and return the enrolment data.
    The secret is stored but not enforced until confirmed via mfa_activate."""
    from ..core.totp import generate_secret, provisioning_uri

    if not user.mfa_secret or user.mfa_enabled:
        # New secret for a fresh setup; re-enrolling issues a new one too.
        user.mfa_secret = generate_secret()
        user.mfa_enabled = False
        db.commit()
    return {
        "secret": user.mfa_secret,
        "otpauth_uri": provisioning_uri(user.mfa_secret, user.email),
    }


def mfa_activate(db: Session, user: User, code: str) -> None:
    """Confirm a pending TOTP secret with a valid code and enable MFA."""
    from ..core.totp import verify

    if not user.mfa_secret:
        raise AuthError(400, "No MFA setup in progress")
    if not verify(user.mfa_secret, code):
        raise AuthError(401, "Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    log.info("mfa enabled", extra={"email": user.email})


def mfa_disable(db: Session, user: User, code: str) -> None:
    """Disable MFA after verifying a current code (so a stolen session alone
    cannot turn it off)."""
    from ..core.totp import verify

    if not user.mfa_enabled or not user.mfa_secret:
        raise AuthError(400, "MFA is not enabled")
    if not verify(user.mfa_secret, code):
        raise AuthError(401, "Invalid MFA code")
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    log.info("mfa disabled", extra={"email": user.email})


def enforce_mfa(user: User, code: str | None) -> None:
    """At login: if the user has MFA enabled, require a valid TOTP code.
    Raises AuthError(401) with a distinct detail when the code is missing so the
    client can prompt for it."""
    from ..core.totp import verify

    if not user.mfa_enabled:
        return
    if not code:
        raise AuthError(401, "MFA code required")
    if not verify(user.mfa_secret or "", code):
        raise AuthError(401, "Invalid MFA code")


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


# -- email verification + password reset (M7) -----------------------------
def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _issue_token(db: Session, user: User, purpose: str, ttl_seconds: int) -> str:
    raw = secrets.token_urlsafe(32)
    # Invalidate any outstanding unused tokens of the same purpose.
    for old in db.query(UserToken).filter(
            UserToken.user_id == user.id, UserToken.purpose == purpose,
            UserToken.used_at.is_(None)).all():
        old.used_at = utcnow()
    db.add(UserToken(user_id=user.id, purpose=purpose, token_hash=_hash_token(raw),
                     expires_at=utcnow() + datetime.timedelta(seconds=ttl_seconds)))
    db.commit()
    return raw


def _consume_token(db: Session, raw: str, purpose: str) -> User | None:
    row = (
        db.query(UserToken)
        .filter(UserToken.token_hash == _hash_token(raw), UserToken.purpose == purpose,
                UserToken.used_at.is_(None))
        .first()
    )
    if row is None or aware_utc(row.expires_at) <= utcnow():
        return None
    row.used_at = utcnow()
    return db.get(User, row.user_id)


def request_email_verification(db: Session, user: User) -> str:
    raw = _issue_token(db, user, "email_verify", settings.verify_token_ttl_seconds)
    email_service.send_email(user.email, "Verify your SilentGuard account",
                             f"Your email verification token: {raw}")
    return raw


def verify_email(db: Session, raw: str) -> bool:
    user = _consume_token(db, raw, "email_verify")
    if user is None:
        return False
    user.email_verified = True
    db.commit()
    return True


def request_password_reset(db: Session, email: str) -> str | None:
    """Issue a reset token. Returns the raw token (for non-prod exposure) or
    None if the email is unknown — callers must not reveal which."""
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if user is None:
        return None
    raw = _issue_token(db, user, "password_reset", settings.reset_token_ttl_seconds)
    email_service.send_email(user.email, "SilentGuard password reset",
                             f"Your password reset token: {raw}")
    return raw


def reset_password(db: Session, raw: str, new_password: str) -> bool:
    validate_password(new_password)
    user = _consume_token(db, raw, "password_reset")
    if user is None:
        return False
    user.hashed_password = hash_password(new_password)
    user.failed_login_count = 0
    user.locked_until = None
    # Revoke all refresh sessions on password change.
    for rt in db.query(RefreshToken).filter(RefreshToken.user_id == user.id,
                                            RefreshToken.revoked.is_(False)).all():
        rt.revoked = True
    db.commit()
    return True


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

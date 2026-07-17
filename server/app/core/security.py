"""Password hashing and JWT token primitives.

Password hashing uses PBKDF2-HMAC-SHA256 from the standard library — no build
dependency, FIPS-friendly, and production-acceptable. The ``PasswordHasher``
interface is deliberately small so argon2/bcrypt can be dropped in later
without touching call sites (roadmap M4 note).

JWTs are HS256, signed with ``settings.effective_jwt_secret``. Access tokens are
short-lived; refresh tokens carry a ``jti`` so individual sessions can be
revoked server-side (see ``models.RefreshToken``).
"""
import datetime
import hashlib
import hmac
import secrets
import uuid

import jwt

from .config import settings

# -- password hashing -----------------------------------------------------
_PBKDF2_ROUNDS = 210_000
_PBKDF2_ALGO = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    """Return a self-describing hash string: ``algo$rounds$salt$hash`` (hex)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS
    ).hex()
    return f"{_PBKDF2_ALGO}${_PBKDF2_ROUNDS}${salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification against an encoded hash. False on any
    malformed input rather than raising."""
    try:
        algo, rounds_s, salt, expected = encoded.split("$")
        if algo != _PBKDF2_ALGO:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(rounds_s)
        ).hex()
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(candidate, expected)


# -- account keys (admin / invite) ----------------------------------------
def generate_admin_key() -> str:
    """A high-entropy admin key handed to a buyer to log into the dashboard."""
    return "sgk_" + secrets.token_urlsafe(24)


def generate_invite_key() -> str:
    """A shorter, shareable join key members use to join a group/enterprise."""
    return "join_" + secrets.token_urlsafe(9)


def hash_key(key: str) -> str:
    """Keys are already high-entropy, so a fast SHA-256 hash is sufficient."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_key(key: str, hashed: str) -> bool:
    return bool(hashed) and hmac.compare_digest(hash_key(key), hashed)


# -- JWT tokens -----------------------------------------------------------
class TokenError(Exception):
    """Raised when a token is missing/expired/invalid."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def create_access_token(subject: str, role: str, extra: dict | None = None) -> str:
    now = _now()
    payload = {
        "sub": subject,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        **(extra or {}),
    }
    return jwt.encode(payload, settings.effective_jwt_secret, algorithm="HS256")


def create_refresh_token(subject: str) -> tuple[str, str, datetime.datetime]:
    """Return (encoded_token, jti, expires_at). The jti is persisted so the
    session can be revoked."""
    now = _now()
    jti = uuid.uuid4().hex
    expires_at = now + datetime.timedelta(seconds=settings.refresh_token_ttl_seconds)
    payload = {
        "sub": subject,
        "type": "refresh",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.effective_jwt_secret, algorithm="HS256")
    return token, jti, expires_at


def decode_token(token: str, expected_type: str | None = None) -> dict:
    try:
        payload = jwt.decode(token, settings.effective_jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if expected_type is not None and payload.get("type") != expected_type:
        raise TokenError(f"expected {expected_type} token")
    return payload

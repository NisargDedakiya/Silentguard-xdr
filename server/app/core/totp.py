"""RFC 6238 TOTP / RFC 4226 HOTP (v1.4 MFA).

A dependency-free time-based one-time-password implementation so multi-factor
authentication needs no third-party library. Secrets are base32 (compatible with
Google Authenticator, Authy, 1Password, etc.); codes are 6 digits over a 30s
period using HMAC-SHA1, the near-universal authenticator default.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

PERIOD = 30
DIGITS = 6
ISSUER = "SilentGuard XDR"


def generate_secret(num_bytes: int = 20) -> str:
    """A new random base32 secret (no padding), ready for a provisioning URI."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def _pad(secret_b32: str) -> str:
    return secret_b32 + "=" * (-len(secret_b32) % 8)


def _hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    key = base64.b32decode(_pad(secret_b32.upper()))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret_b32: str, at: float | None = None,
         period: int = PERIOD, digits: int = DIGITS) -> str:
    """The current TOTP code for ``secret_b32``."""
    at = time.time() if at is None else at
    return _hotp(secret_b32, int(at // period), digits)


def verify(secret_b32: str, code: str, at: float | None = None,
           period: int = PERIOD, digits: int = DIGITS, window: int = 1) -> bool:
    """Constant-time verify ``code``, tolerating +/- ``window`` steps of clock
    skew (default one 30s step either side). Fails closed on an empty secret so a
    missing/null secret can never be satisfied by a computed code."""
    if not secret_b32 or not code or not str(code).strip().isdigit():
        return False
    code = str(code).strip()
    at = time.time() if at is None else at
    counter = int(at // period)
    for delta in range(-window, window + 1):
        step = counter + delta
        if step < 0:
            continue
        if hmac.compare_digest(_hotp(secret_b32, step, digits), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = ISSUER) -> str:
    """An ``otpauth://`` URI to hand to an authenticator app (e.g. as a QR)."""
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode({
        "secret": secret_b32, "issuer": issuer,
        "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"

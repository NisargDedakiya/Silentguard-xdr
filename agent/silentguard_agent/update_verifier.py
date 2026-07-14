"""Signed agent-update verification (M15a).

An update command may carry a manifest — ``version``, ``url``, ``sha256`` — and
a ``signature`` over that manifest. Before the agent honors a real update it
verifies the signature against a trust key provisioned out of band, so a
compromised or spoofed management channel cannot push arbitrary code.

Two schemes are supported:

- **Ed25519** (preferred, asymmetric): the server signs with a private key; the
  agent is provisioned with only the public key (``SG_UPDATE_PUBLIC_KEY``). The
  signing key never touches the endpoint. Requires the ``cryptography`` package.
- **HMAC-SHA256** (symmetric, dependency-free fallback): a shared secret
  (``SG_UPDATE_HMAC_KEY``) for environments without an asymmetric-key pipeline.

Keys and signatures may be supplied as hex or base64. The signed message is a
canonical, key-sorted JSON of the manifest fields so the server and agent agree
byte-for-byte regardless of field ordering.
"""
import base64
import binascii
import hashlib
import hmac
import json
import logging

log = logging.getLogger("silentguard.update")

# Fields covered by the signature. Anything outside this set (action_id, etc.)
# is transport metadata and is deliberately excluded. ``allow_rollback`` is
# signed so an attacker cannot replay an old signed manifest with a forged
# rollback override (v1.4 anti-rollback).
_SIGNED_FIELDS = ("version", "url", "sha256", "allow_rollback")


def canonical_manifest(cmd: dict) -> bytes:
    """Deterministic byte representation of the signable manifest fields."""
    payload = {k: str(cmd.get(k, "")) for k in _SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# -- version comparison / anti-rollback -----------------------------------
def parse_version(value: str) -> tuple[int, ...]:
    """Best-effort numeric version tuple, e.g. ``1.2.0-rc1`` -> ``(1, 2, 0)``."""
    parts = []
    for chunk in str(value).split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _padded(a: tuple, b: tuple) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def is_numeric_version(value: str) -> bool:
    return any(ch.isdigit() for ch in str(value))


def version_gt(target: str, floor: str) -> bool:
    a, b = _padded(parse_version(target), parse_version(floor))
    return a > b


def is_rollback(target: str, floor: str) -> bool:
    """True when ``target`` is an older version than the accepted ``floor``."""
    a, b = _padded(parse_version(target), parse_version(floor))
    return a < b


def _decode_bytes(value: str) -> bytes:
    """Decode a hex or base64 string to raw bytes."""
    value = value.strip()
    try:
        return bytes.fromhex(value)
    except ValueError:
        return base64.b64decode(value, validate=True)


def _verify_ed25519(public_key: str, signature: str, message: bytes) -> tuple[bool, str]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, "cryptography package not installed for ed25519 verification"
    try:
        key = Ed25519PublicKey.from_public_bytes(_decode_bytes(public_key))
        key.verify(_decode_bytes(signature), message)
        return True, "ed25519 signature ok"
    except InvalidSignature:
        return False, "invalid ed25519 signature"
    except (ValueError, binascii.Error) as exc:
        return False, f"ed25519 verification error: {exc}"


def _verify_hmac(secret: str, signature: str, message: bytes) -> tuple[bool, str]:
    expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    provided = signature.strip().lower()
    if provided.startswith("sha256="):
        provided = provided[7:]
    if hmac.compare_digest(expected, provided):
        return True, "hmac signature ok"
    return False, "invalid hmac signature"


def verify_update(cmd: dict, config) -> tuple[bool, str]:
    """Verify an update manifest's signature. Fails closed: an unsigned command
    or an unconfigured trust key is rejected."""
    signature = cmd.get("signature", "")
    if not signature:
        return False, "missing signature"
    message = canonical_manifest(cmd)
    if getattr(config, "update_public_key", ""):
        return _verify_ed25519(config.update_public_key, signature, message)
    if getattr(config, "update_hmac_key", ""):
        return _verify_hmac(config.update_hmac_key, signature, message)
    return False, "no update trust key configured"

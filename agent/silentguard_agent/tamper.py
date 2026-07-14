"""Agent state tamper protection (v1.4).

The agent's state file holds its device identity and API key. If an attacker can
edit that file — to hijack the enrolled identity, redirect the agent, or swap in
a stolen key — the endpoint's trust is compromised. This module HMAC-signs the
state so an offline edit is detected on the next load: a tampered file fails
verification, the stored credentials are discarded (forcing a safe re-enrol), and
a ``tamper`` event is reported so the SOC sees the defense-evasion attempt.

The integrity key comes from ``SG_TAMPER_KEY`` when set (recommended: a secret
provisioned out of band). With no key configured it is derived from stable
machine attributes — this still detects casual field edits, but a determined
local attacker who can guess the derivation is not stopped; document that a real
deployment sets ``SG_TAMPER_KEY``.
"""
import hashlib
import hmac
import json

_INTEGRITY_FIELD = "_integrity"


def _payload_bytes(state: dict) -> bytes:
    payload = {k: state[k] for k in sorted(state) if k != _INTEGRITY_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_mac(state: dict, key: str) -> str:
    return hmac.new(key.encode(), _payload_bytes(state), hashlib.sha256).hexdigest()


def sign(state: dict, key: str) -> dict:
    """Return a copy of ``state`` with an integrity MAC attached."""
    signed = {k: v for k, v in state.items() if k != _INTEGRITY_FIELD}
    signed[_INTEGRITY_FIELD] = compute_mac(signed, key)
    return signed


def is_authentic(state: dict, key: str) -> bool:
    """Whether ``state`` carries a valid integrity MAC for ``key``."""
    provided = state.get(_INTEGRITY_FIELD)
    if not provided:
        return False
    return hmac.compare_digest(str(provided), compute_mac(state, key))


def has_credentials(state: dict) -> bool:
    return bool(state.get("device_id") and state.get("api_key"))

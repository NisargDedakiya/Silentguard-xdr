"""Tests for signed agent updates (M15a)."""
import hashlib
import hmac

import pytest

from silentguard_agent import config as cfg
from silentguard_agent import response_handlers as handlers
from silentguard_agent.update_verifier import canonical_manifest, verify_update


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    """Keep the anti-rollback floor writes off the real filesystem."""
    monkeypatch.setattr(cfg, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "STATE_FILE", tmp_path / "agent_state.json")
    monkeypatch.delenv("SG_TAMPER_KEY", raising=False)


class _Tel:
    def __init__(self):
        self.events = []

    def emit(self, source, action, summary, severity="info", details=None):
        self.events.append({"action": action, "severity": severity, "details": details or {}})

    def by_action(self, action):
        return [e for e in self.events if e["action"] == action]


def _reports():
    calls = []

    def report(action_id, status, **extra):
        calls.append({"action_id": action_id, "status": status, **extra})

    return report, calls


def _hmac_sign(secret, cmd):
    return hmac.new(secret.encode(), canonical_manifest(cmd), hashlib.sha256).hexdigest()


# -- verifier unit tests --------------------------------------------------
def test_missing_signature_rejected(config):
    ok, reason = verify_update({"version": "1.0", "url": "http://x/pkg"}, config)
    assert ok is False and "missing signature" in reason


def test_no_trust_key_fails_closed(config):
    config.update_public_key = ""
    config.update_hmac_key = ""
    ok, reason = verify_update({"version": "1.0", "signature": "deadbeef"}, config)
    assert ok is False and "no update trust key" in reason


def test_hmac_valid_signature_accepted(config):
    config.update_public_key = ""
    config.update_hmac_key = "s3cr3t-shared-key"
    cmd = {"version": "1.2.0", "url": "https://updates/pkg.tar", "sha256": "abc123"}
    cmd["signature"] = _hmac_sign(config.update_hmac_key, cmd)
    ok, reason = verify_update(cmd, config)
    assert ok is True and "hmac" in reason


def test_hmac_tampered_manifest_rejected(config):
    config.update_public_key = ""
    config.update_hmac_key = "s3cr3t-shared-key"
    cmd = {"version": "1.2.0", "url": "https://updates/pkg.tar", "sha256": "abc123"}
    cmd["signature"] = _hmac_sign(config.update_hmac_key, cmd)
    cmd["url"] = "https://evil/pkg.tar"  # tamper after signing
    ok, reason = verify_update(cmd, config)
    assert ok is False and "invalid hmac" in reason


def test_hmac_accepts_sha256_prefix(config):
    config.update_public_key = ""
    config.update_hmac_key = "key"
    cmd = {"version": "2.0", "url": "u", "sha256": "h"}
    cmd["signature"] = "sha256=" + _hmac_sign(config.update_hmac_key, cmd)
    ok, _ = verify_update(cmd, config)
    assert ok is True


def test_ed25519_roundtrip(config):
    ed = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519")
    private = ed.Ed25519PrivateKey.generate()
    public = private.public_key()
    from cryptography.hazmat.primitives import serialization
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    config.update_hmac_key = ""
    config.update_public_key = pub_raw.hex()
    cmd = {"version": "3.1.0", "url": "https://u/pkg", "sha256": "ff00"}
    cmd["signature"] = private.sign(canonical_manifest(cmd)).hex()
    ok, reason = verify_update(cmd, config)
    assert ok is True and "ed25519" in reason


def test_ed25519_wrong_key_rejected(config):
    ed = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives import serialization
    signer = ed.Ed25519PrivateKey.generate()
    other_pub = ed.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    config.update_hmac_key = ""
    config.update_public_key = other_pub.hex()
    cmd = {"version": "3.1.0", "url": "u", "sha256": "ff00"}
    cmd["signature"] = signer.sign(canonical_manifest(cmd)).hex()
    ok, reason = verify_update(cmd, config)
    assert ok is False and "invalid ed25519" in reason


# -- handler integration --------------------------------------------------
def test_remote_update_manifest_requires_valid_signature(config):
    config.update_public_key = ""
    config.update_hmac_key = "key"
    tel = _Tel()
    report, calls = _reports()
    # Manifest with a bad signature must be rejected, not acknowledged.
    handlers.remote_update(
        {"action_id": 1, "version": "9.9", "url": "http://x/pkg", "signature": "bad"},
        tel, config, report)
    assert calls[0]["status"] == "failed"
    assert tel.by_action("update_rejected")
    assert not tel.by_action("update_verified")


def test_remote_update_verified_manifest_acknowledged(config):
    config.update_public_key = ""
    config.update_hmac_key = "key"
    cmd = {"action_id": 2, "version": "9.9", "url": "http://x/pkg", "sha256": "aa"}
    cmd["signature"] = _hmac_sign(config.update_hmac_key, cmd)
    tel = _Tel()
    report, calls = _reports()
    handlers.remote_update(cmd, tel, config, report)
    assert calls[0]["status"] == "ok" and calls[0]["verified"] is True
    assert tel.by_action("update_verified")


def test_remote_update_unsigned_manifest_rejected(config):
    # A manifest with url but no signature fails closed.
    config.update_hmac_key = "key"
    tel = _Tel()
    report, calls = _reports()
    handlers.remote_update(
        {"action_id": 3, "version": "9.9", "url": "http://x/pkg"}, tel, config, report)
    assert calls[0]["status"] == "failed"

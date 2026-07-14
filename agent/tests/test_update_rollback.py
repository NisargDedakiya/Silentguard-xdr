"""Anti-rollback protection for signed updates (v1.4)."""
import hashlib
import hmac

import pytest

from silentguard_agent import config as cfg
from silentguard_agent import response_handlers as handlers
from silentguard_agent import update_verifier as uv
from silentguard_agent.update_verifier import canonical_manifest


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "STATE_FILE", tmp_path / "agent_state.json")
    monkeypatch.setenv("SG_TAMPER_KEY", "k")


class _Tel:
    def __init__(self):
        self.events = []

    def emit(self, source, action, summary, severity="info", details=None):
        self.events.append({"action": action, "details": details or {}})

    def by_action(self, action):
        return [e for e in self.events if e["action"] == action]


def _reports():
    calls = []
    return (lambda aid, status, **x: calls.append({"status": status, **x})), calls


def _signed(config, version, allow_rollback=""):
    cmd = {"version": version, "url": "https://u/pkg", "sha256": "aa",
           "allow_rollback": allow_rollback}
    cmd["signature"] = hmac.new(config.update_hmac_key.encode(),
                                canonical_manifest(cmd), hashlib.sha256).hexdigest()
    return cmd


# -- version helpers ------------------------------------------------------
def test_version_parsing_and_compare():
    assert uv.parse_version("1.2.0") == (1, 2, 0)
    assert uv.parse_version("2.0.1-rc3") == (2, 0, 1)
    assert uv.version_gt("1.3.0", "1.2.9")
    assert uv.is_rollback("1.1.0", "1.2.0")
    assert not uv.is_rollback("1.2.0", "1.2.0")  # equal is not a rollback
    assert not uv.is_rollback("1.2", "1.2.0")    # 1.2 == 1.2.0


# -- handler behavior -----------------------------------------------------
def _cfg():
    c = cfg.AgentConfig()
    c.update_public_key = ""
    c.update_hmac_key = "key"
    return c


def test_accepting_update_sets_floor(config=None):
    c = _cfg()
    tel, (report, calls) = _Tel(), _reports()
    handlers.remote_update({"action_id": 1, **_signed(c, "1.2.0")}, tel, c, report)
    assert calls[0]["status"] == "ok"
    assert cfg.get_update_floor() == "1.2.0"


def test_signed_downgrade_is_blocked():
    c = _cfg()
    cfg.set_update_floor("1.2.0")
    tel, (report, calls) = _Tel(), _reports()
    handlers.remote_update({"action_id": 2, **_signed(c, "1.1.0")}, tel, c, report)
    assert calls[0]["status"] == "failed"
    assert calls[0]["error"] == "rollback_blocked"
    assert tel.by_action("update_rejected")
    assert cfg.get_update_floor() == "1.2.0"  # floor unchanged


def test_signed_rollback_allowed_when_flagged():
    c = _cfg()
    cfg.set_update_floor("1.2.0")
    tel, (report, calls) = _Tel(), _reports()
    handlers.remote_update({"action_id": 3, **_signed(c, "1.1.0", allow_rollback="true")},
                           tel, c, report)
    assert calls[0]["status"] == "ok" and calls[0]["verified"] is True


def test_forged_rollback_flag_is_rejected():
    """allow_rollback is signed: adding it to a manifest signed without it
    invalidates the signature."""
    c = _cfg()
    cfg.set_update_floor("1.2.0")
    cmd = _signed(c, "1.1.0")            # signed WITHOUT allow_rollback
    cmd["allow_rollback"] = "true"        # attacker appends it post-signing
    tel, (report, calls) = _Tel(), _reports()
    handlers.remote_update({"action_id": 4, **cmd}, tel, c, report)
    assert calls[0]["status"] == "failed"  # signature no longer valid


def test_newer_version_advances_floor():
    c = _cfg()
    cfg.set_update_floor("1.2.0")
    tel, (report, calls) = _Tel(), _reports()
    handlers.remote_update({"action_id": 5, **_signed(c, "1.5.0")}, tel, c, report)
    assert calls[0]["status"] == "ok"
    assert cfg.get_update_floor() == "1.5.0"

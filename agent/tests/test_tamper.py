"""Agent state tamper-protection tests (v1.4)."""
import json

import pytest

from silentguard_agent import config as cfg
from silentguard_agent import tamper
from silentguard_agent.config import AgentConfig
from silentguard_agent.telemetry import TelemetryClient

KEY = "unit-test-key"
CREDS = {"device_id": "dev-1", "api_key": "secret-key"}


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "STATE_FILE", tmp_path / "agent_state.json")
    monkeypatch.setattr(cfg, "QUEUE_FILE", tmp_path / "telemetry_queue.json")
    monkeypatch.setenv("SG_TAMPER_KEY", KEY)
    return tmp_path


# -- core -----------------------------------------------------------------
def test_sign_and_verify_roundtrip():
    signed = tamper.sign(CREDS, KEY)
    assert tamper.is_authentic(signed, KEY)


def test_field_edit_is_detected():
    signed = tamper.sign(CREDS, KEY)
    signed["api_key"] = "attacker-key"
    assert not tamper.is_authentic(signed, KEY)


def test_missing_mac_is_not_authentic():
    assert not tamper.is_authentic(dict(CREDS), KEY)


def test_wrong_key_is_not_authentic():
    signed = tamper.sign(CREDS, KEY)
    assert not tamper.is_authentic(signed, "other-key")


# -- integration through config + telemetry -------------------------------
def test_save_state_signs_file(state_dir):
    cfg.save_state(dict(CREDS))
    on_disk = json.loads((state_dir / "agent_state.json").read_text())
    assert "_integrity" in on_disk
    assert tamper.is_authentic(on_disk, KEY)


def test_enrolled_agent_accepts_authentic_state(state_dir):
    cfg.save_state(dict(CREDS))
    client = TelemetryClient(AgentConfig())
    client.ensure_enrolled()
    assert client.device_id == "dev-1" and client.api_key == "secret-key"
    assert not any(e["action"] == "tamper" for e in client.buffer)


def test_tampered_state_is_rejected_and_reported(state_dir, monkeypatch):
    cfg.save_state(dict(CREDS))
    # Attacker edits the api_key directly on disk.
    path = state_dir / "agent_state.json"
    doc = json.loads(path.read_text())
    doc["api_key"] = "attacker-key"
    path.write_text(json.dumps(doc))

    client = TelemetryClient(AgentConfig())
    # Re-enrolment will try to reach the server; force it to fail fast.
    import requests
    monkeypatch.setattr(requests.Session, "post",
                        lambda self, *a, **k: (_ for _ in ()).throw(requests.ConnectionError()))
    try:
        client.ensure_enrolled()
    except requests.ConnectionError:
        pass
    # Tampered credentials must not be trusted, and a tamper event is buffered.
    assert client.api_key != "attacker-key"
    assert any(e["action"] == "tamper" and e["severity"] == "critical"
               for e in client.buffer)

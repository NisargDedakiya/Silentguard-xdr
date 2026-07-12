"""Tests for the durable offline telemetry queue (v1.2)."""
import json

import pytest
import requests

from silentguard_agent import config as cfg
from silentguard_agent.telemetry import TelemetryClient


@pytest.fixture()
def spool(tmp_path, monkeypatch):
    """Point the spool file at a temp path for the duration of the test."""
    queue_file = tmp_path / "telemetry_queue.json"
    monkeypatch.setattr(cfg, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "QUEUE_FILE", queue_file)
    return queue_file


def _client():
    c = TelemetryClient(cfg.AgentConfig())
    c.api_key = "test-key"
    return c


def test_emit_persists_to_disk(spool):
    c = _client()
    c.emit("agent", "started", "hello")
    assert spool.exists()
    saved = json.loads(spool.read_text())
    assert len(saved) == 1 and saved[0]["action"] == "started"


def test_events_survive_restart_while_offline(spool, monkeypatch):
    # First agent instance emits while the server is unreachable.
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("down")))
    c1 = _client()
    c1.emit("port_watchdog", "killed", "killed nc", details={"port": 4444})
    c1.flush()  # fails, events stay spooled
    assert len(c1.buffer) == 1

    # A brand-new instance (simulated restart) recovers the spooled event.
    c2 = _client()
    assert len(c2.buffer) == 1
    assert c2.buffer[0]["action"] == "killed"


def test_successful_flush_clears_spool(spool, monkeypatch):
    class _Resp:
        def raise_for_status(self):
            return None

    sent = {}

    def fake_post(url, json=None, **kwargs):
        sent["events"] = json["events"]
        return _Resp()

    monkeypatch.setattr(requests, "post", fake_post)
    c = _client()
    c.emit("agent", "heartbeat", "ok")
    c.emit("agent", "heartbeat", "ok2")
    c.flush()
    assert sent["events"] and len(sent["events"]) == 2
    assert c.buffer == c.buffer.__class__(maxlen=5000)  # empty
    assert json.loads(spool.read_text()) == []  # spool shrunk to empty


def test_recovery_is_bounded(spool):
    from silentguard_agent.telemetry import MAX_BUFFER
    cfg.save_queue([{"action": "x", "i": i} for i in range(MAX_BUFFER + 100)])
    c = _client()
    assert len(c.buffer) == MAX_BUFFER

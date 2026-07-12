"""Tests for the AI Security Assistant (Stage 6).

No real API calls: a fake Anthropic client is injected into the service, and the
endpoint tests stub the service function. This exercises prompt construction,
JSON/plain-text parsing, availability gating, and error normalization.
"""
import json

import pytest

from app.core.config import settings
from app.services import ai_assistant
from tests.conftest import ADMIN_HEADERS


# -- fakes ----------------------------------------------------------------
class FakeBlock:
    def __init__(self, text, block_type="text"):
        self.type = block_type
        self.text = text


class FakeResponse:
    def __init__(self, blocks):
        self.content = blocks


class FakeMessages:
    def __init__(self, blocks, record):
        self._blocks = blocks
        self._record = record

    def create(self, **kwargs):
        self._record.update(kwargs)
        return FakeResponse(self._blocks)


class FakeClient:
    def __init__(self, blocks, record):
        self.messages = FakeMessages(blocks, record)


class BoomClient:
    class messages:  # noqa: N801 - mimic the SDK attribute
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("api down")


def _text_client(text, record):
    return FakeClient([FakeBlock(text)], record)


def _detection():
    from types import SimpleNamespace
    return SimpleNamespace(
        id=1, rule_id="reverse_shell", name="Reverse Shell",
        severity="critical", risk_score=90, technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        details={"port": 4444, "process": "nc"},
    )


@pytest.fixture()
def _enabled(monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    yield


# -- service unit tests ---------------------------------------------------
def test_explain_detection_parses_json(_enabled):
    record = {}
    payload = json.dumps({
        "summary": "A reverse shell listener on port 4444 was killed.",
        "mitre_explanation": "T1059 covers command interpreters used for C2.",
        "remediation": ["Isolate the host", "Rotate credentials"],
        "confidence": "high",
    })
    result = ai_assistant.explain_detection(_detection(), None,
                                            client=_text_client(payload, record))
    assert result["summary"].startswith("A reverse shell")
    assert result["remediation"] == ["Isolate the host", "Rotate credentials"]
    assert result["confidence"] == "high"
    assert result["model"]  # a model string was chosen
    assert result["generated_at"]
    # The prompt carried the detection facts to the model.
    assert "reverse_shell" in record["messages"][0]["content"]
    assert record["model"] == result["model"]


def test_explain_detection_includes_event_context(_enabled):
    from types import SimpleNamespace
    record = {}
    event = SimpleNamespace(source="port_watchdog", action="killed", severity="critical",
                            summary="killed nc listener", details={"pid": 900})
    ai_assistant.explain_detection(_detection(), event,
                                   client=_text_client("{}", record))
    prompt = record["messages"][0]["content"]
    assert "port_watchdog" in prompt and "killed nc listener" in prompt


def test_explain_detection_strips_code_fence(_enabled):
    payload = "```json\n" + json.dumps({"summary": "s", "remediation": ["a"]}) + "\n```"
    result = ai_assistant.explain_detection(_detection(), None,
                                            client=_text_client(payload, {}))
    assert result["summary"] == "s"
    assert result["remediation"] == ["a"]
    assert result["confidence"] == "medium"  # defaulted


def test_explain_detection_non_json_falls_back_to_text(_enabled):
    result = ai_assistant.explain_detection(_detection(), None,
                                            client=_text_client("plain answer", {}))
    assert result["summary"] == "plain answer"
    assert result["remediation"] == []
    assert result["confidence"] == "low"


def test_explain_detection_skips_thinking_blocks(_enabled):
    blocks = [FakeBlock("secret reasoning", "thinking"),
              FakeBlock(json.dumps({"summary": "done"}), "text")]
    result = ai_assistant.explain_detection(_detection(), None,
                                            client=FakeClient(blocks, {}))
    assert result["summary"] == "done"


def test_explain_detection_raises_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", False)
    with pytest.raises(ai_assistant.AIAssistantUnavailable):
        ai_assistant.explain_detection(_detection(), None, client=_text_client("{}", {}))


def test_explain_detection_wraps_sdk_errors(_enabled):
    with pytest.raises(ai_assistant.AIAssistantError):
        ai_assistant.explain_detection(_detection(), None, client=BoomClient())


def test_is_available_reflects_settings(monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai_assistant.is_available() is False
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    assert ai_assistant.is_available() is True


# -- endpoint tests -------------------------------------------------------
def _make_detection(client, enrolled_device) -> int:
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "port_watchdog", "action": "killed", "severity": "critical",
         "summary": "killed listener", "details": {"port": 4444, "process": "nc"}},
    ]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    return dets[0]["id"]


def test_explain_endpoint_503_when_disabled(client, enrolled_device, monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", False)
    det_id = _make_detection(client, enrolled_device)
    r = client.post(f"/api/admin/detections/{det_id}/explain", headers=ADMIN_HEADERS)
    assert r.status_code == 503


def test_explain_endpoint_success(client, enrolled_device, monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def fake_explain(detection, event=None, *, client=None):
        return {"summary": "s", "mitre_explanation": "m", "remediation": ["r1", "r2"],
                "confidence": "high", "model": "test-model",
                "generated_at": "2026-01-01T00:00:00+00:00"}

    monkeypatch.setattr(ai_assistant, "explain_detection", fake_explain)
    det_id = _make_detection(client, enrolled_device)
    r = client.post(f"/api/admin/detections/{det_id}/explain", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["detection_id"] == det_id
    assert body["remediation"] == ["r1", "r2"]
    assert body["model"] == "test-model"
    # The explanation is audited.
    audit = client.get("/api/admin/audit", headers=ADMIN_HEADERS).json()
    assert any(a["action"] == "detection_explain" for a in audit)


def test_explain_endpoint_502_on_model_error(client, enrolled_device, monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")

    def boom(detection, event=None, *, client=None):
        raise ai_assistant.AIAssistantError("rate limited")

    monkeypatch.setattr(ai_assistant, "explain_detection", boom)
    det_id = _make_detection(client, enrolled_device)
    r = client.post(f"/api/admin/detections/{det_id}/explain", headers=ADMIN_HEADERS)
    assert r.status_code == 502


def test_explain_endpoint_404_for_unknown_detection(client, monkeypatch):
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    r = client.post("/api/admin/detections/99999/explain", headers=ADMIN_HEADERS)
    assert r.status_code == 404

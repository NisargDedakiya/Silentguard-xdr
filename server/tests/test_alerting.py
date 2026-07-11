"""Alerting tests — no real network I/O; webhook/SMTP layers are patched."""
import json
import time
from unittest.mock import patch

import pytest

from app import alerting


@pytest.fixture()
def webhook_env(monkeypatch):
    monkeypatch.setenv("SG_ALERT_WEBHOOK_URL", "https://hooks.example/T000/B000")
    monkeypatch.delenv("SG_SMTP_HOST", raising=False)


def _event(severity="critical"):
    return {
        "severity": severity,
        "summary": "Reverse shell killed",
        "hostname": "vm-1",
        "source": "port_watchdog",
        "action": "killed",
        "mitre": {"id": "T1059", "name": "Command and Scripting Interpreter"},
    }


def test_format_message_includes_context():
    msg = alerting.format_message(_event())
    assert "Reverse shell killed" in msg
    assert "vm-1" in msg
    assert "T1059" in msg


async def test_non_critical_events_are_ignored(webhook_env):
    assert await alerting.notify_critical(_event(severity="warning")) is None


async def test_no_config_means_noop(monkeypatch):
    monkeypatch.delenv("SG_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SG_SMTP_HOST", raising=False)
    assert await alerting.notify_critical(_event()) is None


async def test_critical_event_fires_webhook(webhook_env):
    sent = {}

    def fake_urlopen(req, timeout=None):
        sent["url"] = req.full_url
        sent["body"] = json.loads(req.data)

    with patch.object(alerting.urllib.request, "urlopen", fake_urlopen):
        task = await alerting.notify_critical(_event())
        assert task is not None
        await task
    assert sent["url"] == "https://hooks.example/T000/B000"
    assert "Reverse shell killed" in sent["body"]["text"]
    assert sent["body"]["content"] == sent["body"]["text"]  # Discord compatibility


async def test_webhook_failure_is_swallowed(webhook_env):
    def boom(req, timeout=None):
        raise OSError("connection refused")

    with patch.object(alerting.urllib.request, "urlopen", boom):
        task = await alerting.notify_critical(_event())
        await task  # must not raise


async def test_email_dispatch(monkeypatch):
    monkeypatch.delenv("SG_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("SG_SMTP_HOST", "smtp.example")
    monkeypatch.setenv("SG_SMTP_FROM", "xdr@example.com")
    monkeypatch.setenv("SG_ALERT_EMAIL_TO", "soc@example.com")

    sent = {}

    def fake_send_email(settings, message):
        sent["to"] = settings["email_to"]
        sent["message"] = message

    with patch.object(alerting, "_send_email", fake_send_email):
        task = await alerting.notify_critical(_event())
        assert task is not None
        await task
    assert sent["to"] == "soc@example.com"
    assert "Reverse shell killed" in sent["message"]


async def test_ingestion_triggers_alert(client, enrolled_device, webhook_env):
    """End-to-end: a critical telemetry event schedules a webhook alert."""
    calls = []
    with patch.object(alerting, "_dispatch", lambda s, m: calls.append(m)):
        client.post(
            "/api/agent/telemetry",
            json={
                "events": [
                    {"source": "port_watchdog", "action": "killed",
                     "severity": "critical", "summary": "boom"},
                    {"source": "agent", "action": "note",
                     "severity": "info", "summary": "quiet"},
                ]
            },
            headers=enrolled_device["headers"],
        )
        # Delivery is fire-and-forget on the app's event loop; give it a beat.
        deadline = time.monotonic() + 2
        while not calls and time.monotonic() < deadline:
            time.sleep(0.01)
    assert len(calls) == 1
    assert "boom" in calls[0]

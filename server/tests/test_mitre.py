"""MITRE ATT&CK tagging tests."""
from app.mitre import technique_for
from tests.conftest import ADMIN_HEADERS


def test_exact_mapping():
    t = technique_for("port_watchdog", "killed")
    assert t["id"] == "T1059"
    assert "attack.mitre.org/techniques/T1059" in t["url"]


def test_wildcard_fallback():
    assert technique_for("dns_sinkhole", "blocked")["id"] == "T1071.004"
    assert technique_for("dns_sinkhole", "some_future_action")["id"] == "T1071.004"
    assert technique_for("usb_guard", "usb_inserted")["id"] == "T1091"


def test_unmapped_returns_none():
    assert technique_for("agent", "started") is None
    assert technique_for("nonexistent", "x") is None


def test_events_api_includes_mitre_tag(client, enrolled_device):
    client.post(
        "/api/agent/telemetry",
        json={
            "events": [
                {
                    "source": "port_watchdog",
                    "action": "killed",
                    "severity": "critical",
                    "summary": "killed reverse shell",
                },
                {"source": "agent", "action": "heartbeat", "summary": "hb"},
            ]
        },
        headers=enrolled_device["headers"],
    )
    events = client.get("/api/admin/events", headers=ADMIN_HEADERS).json()
    by_action = {e["action"]: e for e in events}
    assert by_action["killed"]["mitre"]["id"] == "T1059"
    assert by_action["killed"]["mitre"]["name"] == "Command and Scripting Interpreter"
    assert by_action["heartbeat"]["mitre"] is None

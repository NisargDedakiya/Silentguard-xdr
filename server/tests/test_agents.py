"""Tests for agent-facing endpoints: enroll, telemetry, checkin."""
from app.auth import ENROLL_TOKEN

from .conftest import ADMIN_HEADERS


def test_enroll_rejects_bad_token(client):
    resp = client.post(
        "/api/agent/enroll",
        json={"enroll_token": "wrong-token", "hostname": "x"},
    )
    assert resp.status_code == 401


def test_enroll_returns_credentials_and_creates_device(client):
    resp = client.post(
        "/api/agent/enroll",
        json={"enroll_token": ENROLL_TOKEN, "hostname": "vm1", "platform": "Linux"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["device_id"]
    assert len(data["api_key"]) == 64

    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    assert [d["hostname"] for d in devices] == ["vm1"]
    assert devices[0]["isolated"] is False

    # Enrollment itself lands in the timeline
    events = client.get("/api/admin/events", headers=ADMIN_HEADERS).json()
    assert any(e["action"] == "enrolled" for e in events)


def test_telemetry_requires_valid_agent_key(client):
    resp = client.post(
        "/api/agent/telemetry",
        json={"events": []},
        headers={"X-Agent-Key": "bogus"},
    )
    assert resp.status_code == 401


def test_telemetry_stores_events(client, enrolled_device):
    resp = client.post(
        "/api/agent/telemetry",
        headers=enrolled_device["headers"],
        json={
            "events": [
                {
                    "source": "port_watchdog",
                    "severity": "critical",
                    "action": "killed",
                    "summary": "Unauthorized listener 'nc' on port 4444 terminated",
                    "details": {"pid": 123, "port": 4444},
                },
                {"source": "agent", "action": "started", "summary": "agent online"},
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 2
    assert body["detections"] == 1  # the port_watchdog kill triggers the reverse-shell rule

    events = client.get("/api/admin/events", headers=ADMIN_HEADERS).json()
    critical = [e for e in events if e["severity"] == "critical"]
    assert critical and critical[0]["details"]["port"] == 4444
    assert critical[0]["hostname"] == "test-vm"


def test_checkin_returns_state_and_drains_commands(client, enrolled_device):
    device_id = enrolled_device["device_id"]

    state = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    assert state["isolated"] is False
    assert state["commands"] == []
    assert set(state["blocklist"]) >= {"domain", "process", "port"}

    # Isolate from the admin side, then the agent picks up the command once.
    client.post(f"/api/admin/devices/{device_id}/isolate", headers=ADMIN_HEADERS)
    state = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    assert state["isolated"] is True
    assert {"command": "isolate"} in state["commands"]

    # Commands are drained after delivery
    state = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    assert state["commands"] == []
    assert state["isolated"] is True


def test_checkin_delivers_fleet_blocklist(client, enrolled_device):
    client.post(
        "/api/admin/blocklist",
        headers=ADMIN_HEADERS,
        json={"kind": "domain", "value": "evil.example"},
    )
    state = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    assert "evil.example" in state["blocklist"]["domain"]

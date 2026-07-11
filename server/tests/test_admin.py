"""Tests for admin endpoints: device list, isolate/release, blocklist CRUD."""
from .conftest import ADMIN_HEADERS


def test_admin_endpoints_require_token(client):
    assert client.get("/api/admin/devices").status_code == 401
    assert client.get("/api/admin/events", headers={"X-Admin-Token": "nope"}).status_code == 401


def test_device_list_online_flag(client, enrolled_device):
    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    assert len(devices) == 1
    d = devices[0]
    assert d["id"] == enrolled_device["device_id"]
    assert d["online"] is True  # just enrolled → last_seen is now


def test_isolate_and_release_cycle(client, enrolled_device):
    device_id = enrolled_device["device_id"]

    resp = client.post(f"/api/admin/devices/{device_id}/isolate", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["isolated"] is True
    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    assert devices[0]["isolated"] is True

    resp = client.post(f"/api/admin/devices/{device_id}/release", headers=ADMIN_HEADERS)
    assert resp.json()["isolated"] is False

    events = client.get("/api/admin/events", headers=ADMIN_HEADERS).json()
    actions = [e["action"] for e in events if e["source"] == "isolation"]
    assert "isolation_requested" in actions and "isolation_released" in actions


def test_isolate_unknown_device_404(client):
    resp = client.post("/api/admin/devices/nope/isolate", headers=ADMIN_HEADERS)
    assert resp.status_code == 404


def test_blocklist_crud(client):
    # create
    resp = client.post(
        "/api/admin/blocklist",
        headers=ADMIN_HEADERS,
        json={"kind": "process", "value": "mimikatz.exe"},
    )
    assert resp.status_code == 200
    entry_id = resp.json()["id"]

    # duplicate rejected
    resp = client.post(
        "/api/admin/blocklist",
        headers=ADMIN_HEADERS,
        json={"kind": "process", "value": "mimikatz.exe"},
    )
    assert resp.status_code == 409

    # invalid kind rejected
    resp = client.post(
        "/api/admin/blocklist",
        headers=ADMIN_HEADERS,
        json={"kind": "ip", "value": "1.2.3.4"},
    )
    assert resp.status_code == 400

    # read
    entries = client.get("/api/admin/blocklist", headers=ADMIN_HEADERS).json()
    assert [e["value"] for e in entries] == ["mimikatz.exe"]

    # delete
    assert client.delete(f"/api/admin/blocklist/{entry_id}", headers=ADMIN_HEADERS).status_code == 200
    assert client.get("/api/admin/blocklist", headers=ADMIN_HEADERS).json() == []
    assert client.delete(f"/api/admin/blocklist/{entry_id}", headers=ADMIN_HEADERS).status_code == 404


def test_events_filter_by_device(client, enrolled_device):
    client.post(
        "/api/agent/telemetry",
        headers=enrolled_device["headers"],
        json={"events": [{"source": "arp_guard", "severity": "critical",
                          "action": "dropped", "summary": "spoof"}]},
    )
    events = client.get(
        f"/api/admin/events?device_id={enrolled_device['device_id']}",
        headers=ADMIN_HEADERS,
    ).json()
    assert events and all(e["device_id"] == enrolled_device["device_id"] for e in events)
    events = client.get("/api/admin/events?device_id=other", headers=ADMIN_HEADERS).json()
    assert events == []

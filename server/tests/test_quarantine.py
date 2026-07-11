"""Quarantine fleet-view tests: telemetry ingestion populates the table,
admin can list and request restores, agent picks up the command and
confirms the restore."""
from tests.conftest import ADMIN_HEADERS


def _quarantine_event(qid="q-1", path="/tmp/evil.bin", action="quarantined"):
    return {
        "source": "quarantine",
        "action": action,
        "severity": "critical",
        "summary": "test quarantine",
        "details": {
            "id": qid,
            "original_path": path,
            "sha256": "ab" * 32,
            "reason": "test",
            "verdict": "known_bad",
        },
    }


def test_quarantine_lifecycle(client, enrolled_device):
    headers = enrolled_device["headers"]

    # 1. Agent reports a quarantined file → appears in the admin list
    r = client.post("/api/agent/telemetry", json={"events": [_quarantine_event()]}, headers=headers)
    assert r.status_code == 200
    items = client.get("/api/admin/quarantine", headers=ADMIN_HEADERS).json()
    assert len(items) == 1
    assert items[0]["id"] == "q-1"
    assert items[0]["status"] == "quarantined"
    assert items[0]["hostname"] == "test-vm"
    assert items[0]["verdict"] == "known_bad"

    # 2. Admin requests restore → command queued for the agent
    r = client.post("/api/admin/quarantine/q-1/restore", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "restore_requested"
    checkin = client.get("/api/agent/checkin", headers=headers).json()
    assert {"command": "restore_quarantine", "id": "q-1"} in checkin["commands"]

    # 3. Agent confirms the restore → item marked restored
    client.post(
        "/api/agent/telemetry",
        json={"events": [_quarantine_event(action="restored")]},
        headers=headers,
    )
    items = client.get("/api/admin/quarantine", headers=ADMIN_HEADERS).json()
    assert items[0]["status"] == "restored"
    assert items[0]["restored_at"] is not None

    # 4. Restoring an already-restored item is rejected
    r = client.post("/api/admin/quarantine/q-1/restore", headers=ADMIN_HEADERS)
    assert r.status_code == 409


def test_restore_unknown_item_404(client):
    r = client.post("/api/admin/quarantine/nope/restore", headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_quarantine_requires_admin(client):
    assert client.get("/api/admin/quarantine").status_code == 401


def test_duplicate_quarantine_event_is_idempotent(client, enrolled_device):
    headers = enrolled_device["headers"]
    client.post("/api/agent/telemetry", json={"events": [_quarantine_event()]}, headers=headers)
    client.post("/api/agent/telemetry", json={"events": [_quarantine_event()]}, headers=headers)
    items = client.get("/api/admin/quarantine", headers=ADMIN_HEADERS).json()
    assert len(items) == 1

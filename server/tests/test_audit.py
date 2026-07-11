"""Audit log tests: every admin action is recorded with an actor fingerprint."""
from app.auth import ADMIN_TOKEN, token_fingerprint
from tests.conftest import ADMIN_HEADERS


def test_admin_actions_are_audited(client, enrolled_device):
    device_id = enrolled_device["device_id"]

    client.post(f"/api/admin/devices/{device_id}/isolate", headers=ADMIN_HEADERS)
    client.post(f"/api/admin/devices/{device_id}/release", headers=ADMIN_HEADERS)
    r = client.post(
        "/api/admin/blocklist",
        json={"kind": "domain", "value": "evil.example"},
        headers=ADMIN_HEADERS,
    )
    entry_id = r.json()["id"]
    client.delete(f"/api/admin/blocklist/{entry_id}", headers=ADMIN_HEADERS)

    audit = client.get("/api/admin/audit", headers=ADMIN_HEADERS).json()
    actions = [a["action"] for a in audit]
    # Newest first
    assert actions == ["blocklist_remove", "blocklist_add", "release", "isolate"]

    fp = token_fingerprint(ADMIN_TOKEN)
    assert all(a["actor"] == fp for a in audit)
    assert audit[0]["target"] == "evil.example"
    assert audit[-1]["target"] == device_id
    assert audit[-1]["details"]["hostname"] == "test-vm"


def test_quarantine_restore_is_audited(client, enrolled_device):
    client.post(
        "/api/agent/telemetry",
        json={
            "events": [
                {
                    "source": "quarantine",
                    "action": "quarantined",
                    "severity": "critical",
                    "summary": "q",
                    "details": {"id": "q-9", "original_path": "/tmp/x", "sha256": "ff" * 32},
                }
            ]
        },
        headers=enrolled_device["headers"],
    )
    client.post("/api/admin/quarantine/q-9/restore", headers=ADMIN_HEADERS)
    audit = client.get("/api/admin/audit", headers=ADMIN_HEADERS).json()
    assert audit[0]["action"] == "quarantine_restore"
    assert audit[0]["target"] == "q-9"
    assert audit[0]["details"]["original_path"] == "/tmp/x"


def test_audit_requires_admin(client):
    assert client.get("/api/admin/audit").status_code == 401


def test_failed_actions_not_audited(client):
    client.post("/api/admin/devices/nope/isolate", headers=ADMIN_HEADERS)  # 404
    audit = client.get("/api/admin/audit", headers=ADMIN_HEADERS).json()
    assert audit == []

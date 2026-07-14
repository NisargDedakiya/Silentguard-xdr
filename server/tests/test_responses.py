"""Tests for M14: response action framework."""
import pytest

from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _respond(client, device_id, action, params=None, headers=ADMIN_HEADERS):
    return client.post(f"/api/admin/devices/{device_id}/respond",
                       json={"action": action, "params": params or {}}, headers=headers)


def test_server_action_block_domain_completes_immediately(client, enrolled_device):
    r = _respond(client, enrolled_device["device_id"], "block_domain", {"value": "evil.example"})
    assert r.status_code == 201
    assert r.json()["status"] == "completed"
    # It landed in the blocklist
    bl = client.get("/api/admin/blocklist", headers=ADMIN_HEADERS).json()
    assert any(e["value"] == "evil.example" for e in bl)


def test_block_hash_creates_ioc(client, enrolled_device):
    _respond(client, enrolled_device["device_id"], "block_hash", {"value": "deadbeef"})
    iocs = client.get("/api/admin/intel/iocs?ioc_type=sha256", headers=ADMIN_HEADERS).json()
    assert any(i["value"] == "deadbeef" for i in iocs)


def test_agent_action_queues_command_and_completes_on_result(client, enrolled_device):
    r = _respond(client, enrolled_device["device_id"], "kill_process", {"pid": 1234})
    assert r.status_code == 201
    action = r.json()
    assert action["status"] == "queued"

    # Agent picks up the queued command on check-in
    checkin = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    cmd = next(c for c in checkin["commands"] if c["command"] == "kill_process")
    assert cmd["action_id"] == action["id"]

    # Agent reports the result
    client.post("/api/agent/telemetry", json={"events": [{
        "source": "response", "action": "result", "severity": "info", "summary": "done",
        "details": {"action_id": action["id"], "status": "ok", "killed": [1234]},
    }]}, headers=enrolled_device["headers"])

    responses = client.get("/api/admin/responses", headers=ADMIN_HEADERS).json()
    done = next(a for a in responses if a["id"] == action["id"])
    assert done["status"] == "completed"
    assert done["result"]["killed"] == [1234]


def test_unknown_action_rejected(client, enrolled_device):
    r = _respond(client, enrolled_device["device_id"], "nuke_from_orbit")
    assert r.status_code == 400


def test_block_domain_requires_value(client, enrolled_device):
    assert _respond(client, enrolled_device["device_id"], "block_domain", {}).status_code == 400


def test_respond_on_unknown_device_404(client):
    assert _respond(client, "nope", "remote_scan").status_code == 404


def test_read_only_cannot_respond(client, enrolled_device, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    tok = client.post("/api/auth/login", json={"email": "ro@x.com", "password": GOOD_PW}).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert _respond(client, enrolled_device["device_id"], "remote_scan", headers=h).status_code == 403


def test_responder_can_respond(client, enrolled_device, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "resp@x.com", GOOD_PW, Role.RESPONDER.value)
    db.close()
    tok = client.post("/api/auth/login", json={"email": "resp@x.com", "password": GOOD_PW}).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert _respond(client, enrolled_device["device_id"], "remote_scan", headers=h).status_code == 201


def test_response_is_audited(client, enrolled_device):
    _respond(client, enrolled_device["device_id"], "remote_scan")
    audit = client.get("/api/admin/audit", headers=ADMIN_HEADERS).json()
    assert any(a["action"] == "response:remote_scan" for a in audit)

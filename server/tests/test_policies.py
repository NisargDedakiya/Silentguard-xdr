"""Tests for M16: device groups, policy engine, licensing."""
import pytest

from app.core.roles import Role
from app.models import DEFAULT_ORG_ID, Organization
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS, ENROLL_TOKEN

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _group(client, name="engineering"):
    return client.post("/api/admin/groups", json={"name": name}, headers=ADMIN_HEADERS)


def test_group_crud_and_conflict(client):
    r = _group(client)
    assert r.status_code == 201
    assert _group(client).status_code == 409  # duplicate name
    gid = r.json()["id"]
    assert any(g["id"] == gid for g in client.get("/api/admin/groups",
                                                  headers=ADMIN_HEADERS).json())
    assert client.delete(f"/api/admin/groups/{gid}", headers=ADMIN_HEADERS).status_code == 200


def test_effective_policy_org_default_then_group_override(client, enrolled_device):
    device_id = enrolled_device["device_id"]
    # Org-default policy blocks port 9999 and enables USB blocking
    client.post("/api/admin/policies", json={
        "name": "org-default", "group_id": None,
        "settings": {"suspicious_ports": [9999], "block_usb_storage": True}},
        headers=ADMIN_HEADERS)
    eff = client.get(f"/api/admin/devices/{device_id}/policy", headers=ADMIN_HEADERS).json()
    assert 9999 in eff["suspicious_ports"]
    assert eff["block_usb_storage"] is True

    # Group policy overrides USB blocking off for the device's group
    gid = _group(client, "kiosks").json()["id"]
    client.post(f"/api/admin/devices/{device_id}/group",
                json={"group_id": gid}, headers=ADMIN_HEADERS)
    client.post("/api/admin/policies", json={
        "name": "kiosk", "group_id": gid, "settings": {"block_usb_storage": False}},
        headers=ADMIN_HEADERS)
    eff2 = client.get(f"/api/admin/devices/{device_id}/policy", headers=ADMIN_HEADERS).json()
    assert eff2["block_usb_storage"] is False  # group overrides org default
    assert 9999 in eff2["suspicious_ports"]     # inherited from org default


def test_checkin_includes_policy(client, enrolled_device):
    client.post("/api/admin/policies", json={
        "name": "d", "settings": {"blocked_domains": ["evil.example"]}}, headers=ADMIN_HEADERS)
    r = client.get("/api/agent/checkin", headers=enrolled_device["headers"]).json()
    assert "policy" in r
    assert "evil.example" in r["policy"]["blocked_domains"]


def test_assign_group_from_other_org_rejected(client, enrolled_device, db_session_factory):
    db = db_session_factory()
    from app.models import DeviceGroup
    db.add(DeviceGroup(id=999, org_id="other-org", name="x"))
    db.commit()
    db.close()
    r = client.post(f"/api/admin/devices/{enrolled_device['device_id']}/group",
                    json={"group_id": 999}, headers=ADMIN_HEADERS)
    assert r.status_code == 400


def test_read_only_cannot_manage_policy(client, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    tok = client.post("/api/auth/login", json={"email": "ro@x.com", "password": GOOD_PW}).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get("/api/admin/policies", headers=h).status_code == 200
    assert client.post("/api/admin/policies", json={"name": "x", "settings": {}},
                       headers=h).status_code == 403


def test_licensing_device_cap_blocks_enrollment(client, db_session_factory):
    db = db_session_factory()
    org = db.get(Organization, DEFAULT_ORG_ID)
    if org is None:
        org = Organization(id=DEFAULT_ORG_ID, name="Default", slug="default")
        db.add(org)
    org.max_devices = 1
    db.commit()
    db.close()
    first = client.post("/api/agent/enroll",
                        json={"enroll_token": ENROLL_TOKEN, "hostname": "a", "platform": "L"})
    assert first.status_code == 200
    second = client.post("/api/agent/enroll",
                         json={"enroll_token": ENROLL_TOKEN, "hostname": "b", "platform": "L"})
    assert second.status_code == 402  # license limit reached

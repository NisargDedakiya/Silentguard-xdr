"""Tests for M5 RBAC enforcement across admin endpoints and user management."""
import pytest

from app.core.permissions import Permission, has_permission
from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _login(client, email, password=GOOD_PW):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make(db_session_factory, email, role):
    db = db_session_factory()
    auth_service.create_user(db, email, GOOD_PW, role)
    db.close()


# -- permission matrix unit ----------------------------------------------
def test_matrix_read_only():
    assert has_permission(Role.READ_ONLY, Permission.READ_FLEET)
    assert not has_permission(Role.READ_ONLY, Permission.WRITE_ISOLATION)
    assert not has_permission(Role.READ_ONLY, Permission.MANAGE_USERS)


def test_matrix_responder_and_super_admin():
    assert has_permission(Role.RESPONDER, Permission.WRITE_ISOLATION)
    assert not has_permission(Role.RESPONDER, Permission.MANAGE_USERS)
    for perm in Permission:
        assert has_permission(Role.SUPER_ADMIN, perm)


# -- read-only role: can read, cannot mutate -----------------------------
def test_read_only_can_list_but_not_isolate(client, db_session_factory, enrolled_device):
    _make(db_session_factory, "ro@example.com", Role.READ_ONLY.value)
    h = _login(client, "ro@example.com")
    assert client.get("/api/admin/devices", headers=h).status_code == 200
    r = client.post(f"/api/admin/devices/{enrolled_device['device_id']}/isolate", headers=h)
    assert r.status_code == 403


def test_read_only_cannot_manage_users(client, db_session_factory):
    _make(db_session_factory, "ro2@example.com", Role.READ_ONLY.value)
    h = _login(client, "ro2@example.com")
    assert client.get("/api/admin/users", headers=h).status_code == 403


# -- responder: can isolate + blocklist, cannot read audit or manage users
def test_responder_can_isolate_and_blocklist(client, db_session_factory, enrolled_device):
    _make(db_session_factory, "resp@example.com", Role.RESPONDER.value)
    h = _login(client, "resp@example.com")
    assert client.post(f"/api/admin/devices/{enrolled_device['device_id']}/isolate",
                       headers=h).status_code == 200
    assert client.post("/api/admin/blocklist",
                       json={"kind": "domain", "value": "bad.example"},
                       headers=h).status_code == 200


def test_responder_cannot_read_audit(client, db_session_factory):
    _make(db_session_factory, "resp2@example.com", Role.RESPONDER.value)
    h = _login(client, "resp2@example.com")
    assert client.get("/api/admin/audit", headers=h).status_code == 403


# -- auditor: can read audit, cannot mutate ------------------------------
def test_auditor_reads_audit_but_cannot_blocklist(client, db_session_factory):
    _make(db_session_factory, "aud@example.com", Role.AUDITOR.value)
    h = _login(client, "aud@example.com")
    assert client.get("/api/admin/audit", headers=h).status_code == 200
    assert client.post("/api/admin/blocklist",
                       json={"kind": "domain", "value": "x.example"},
                       headers=h).status_code == 403


# -- user management ------------------------------------------------------
def test_super_admin_creates_user_and_it_can_login(client, db_session_factory):
    _make(db_session_factory, "boss@example.com", Role.SUPER_ADMIN.value)
    h = _login(client, "boss@example.com")
    r = client.post("/api/admin/users",
                    json={"email": "new@example.com", "password": GOOD_PW,
                          "role": Role.ANALYST.value}, headers=h)
    assert r.status_code == 201
    assert r.json()["role"] == Role.ANALYST.value
    # The new analyst can log in and read but not manage users.
    ha = _login(client, "new@example.com")
    assert client.get("/api/admin/devices", headers=ha).status_code == 200
    assert client.get("/api/admin/users", headers=ha).status_code == 403


def test_disabled_user_cannot_authenticate(client, db_session_factory):
    _make(db_session_factory, "boss2@example.com", Role.SUPER_ADMIN.value)
    _make(db_session_factory, "victim@example.com", Role.ANALYST.value)
    hb = _login(client, "boss2@example.com")
    # find victim id
    users = client.get("/api/admin/users", headers=hb).json()
    victim = next(u for u in users if u["email"] == "victim@example.com")
    hv = _login(client, "victim@example.com")
    assert client.post(f"/api/admin/users/{victim['id']}/disable", headers=hb).status_code == 200
    # Existing access token now rejected (user inactive)
    assert client.get("/api/admin/devices", headers=hv).status_code == 401


# -- backward compatibility: legacy admin token = super admin ------------
def test_legacy_token_has_full_access(client):
    assert client.get("/api/admin/devices", headers=ADMIN_HEADERS).status_code == 200
    assert client.get("/api/admin/audit", headers=ADMIN_HEADERS).status_code == 200
    assert client.get("/api/admin/users", headers=ADMIN_HEADERS).status_code == 200

"""Organization management, member roles, and individual home mode."""
import secrets

import pytest

from app.core.roles import Role
from app.models import Organization
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _org(db_factory, plan):
    oid = secrets.token_hex(16)
    db = db_factory()
    db.add(Organization(id=oid, name=f"{plan} org", slug=f"{plan}-{oid[:6]}", plan=plan))
    db.commit()
    db.close()
    return oid


def _user(db_factory, email, org_id, role):
    db = db_factory()
    auth_service.create_user(db, email, GOOD_PW, role, org_id=org_id)
    db.close()


def _bearer(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# -- organization CRUD (super-admin) --------------------------------------
def test_create_and_list_orgs(client):
    r = client.post("/api/admin/organizations", headers=ADMIN_HEADERS,
                    json={"name": "Acme Corp", "slug": "acme", "plan": "team"})
    assert r.status_code == 201
    body = r.json()
    assert body["plan"] == "team" and body["slug"] == "acme"
    orgs = client.get("/api/admin/organizations", headers=ADMIN_HEADERS).json()
    assert any(o["slug"] == "acme" for o in orgs)


def test_create_org_rejects_bad_plan_and_dup_slug(client):
    assert client.post("/api/admin/organizations", headers=ADMIN_HEADERS,
                       json={"name": "X", "slug": "x", "plan": "gold"}).status_code == 400
    client.post("/api/admin/organizations", headers=ADMIN_HEADERS,
                json={"name": "Dup", "slug": "dup", "plan": "team"})
    assert client.post("/api/admin/organizations", headers=ADMIN_HEADERS,
                       json={"name": "Dup2", "slug": "dup", "plan": "team"}).status_code == 409


def test_update_org_plan(client):
    oid = client.post("/api/admin/organizations", headers=ADMIN_HEADERS,
                      json={"name": "Grow", "slug": "grow", "plan": "individual"}).json()["id"]
    r = client.patch(f"/api/admin/organizations/{oid}", headers=ADMIN_HEADERS,
                     json={"plan": "enterprise"})
    assert r.status_code == 200 and r.json()["plan"] == "enterprise"


def test_org_management_requires_super_admin(client, db_session_factory):
    team = _org(db_session_factory, "team")
    _user(db_session_factory, "mgr@team.com", team, "soc_manager")
    h = _bearer(client, "mgr@team.com")
    # soc_manager lacks MANAGE_ORGS.
    assert client.get("/api/admin/organizations", headers=h).status_code == 403
    assert client.post("/api/admin/organizations", headers=h,
                       json={"name": "N", "slug": "n", "plan": "team"}).status_code == 403


# -- member role management (RBAC gated by plan) --------------------------
def test_role_update_on_team_plan(client, db_session_factory):
    team = _org(db_session_factory, "team")
    _user(db_session_factory, "owner@team.com", team, "super_admin")
    _user(db_session_factory, "member@team.com", team, "read_only")
    member_id = next(u["id"] for u in
                     client.get("/api/admin/users", headers=_bearer(client, "owner@team.com")).json()
                     if u["email"] == "member@team.com")
    r = client.patch(f"/api/admin/users/{member_id}/role",
                     headers=_bearer(client, "owner@team.com"), json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"


def test_role_update_gated_on_individual_plan(client, db_session_factory):
    ind = _org(db_session_factory, "individual")
    _user(db_session_factory, "owner@ind.com", ind, "super_admin")
    _user(db_session_factory, "m@ind.com", ind, "read_only")
    h = _bearer(client, "owner@ind.com")
    mid = next(u["id"] for u in client.get("/api/admin/users", headers=h).json()
               if u["email"] == "m@ind.com")
    assert client.patch(f"/api/admin/users/{mid}/role", headers=h,
                        json={"role": "analyst"}).status_code == 402


# -- individual / home mode ----------------------------------------------
def test_home_summary_shape(client, enrolled_device):
    body = client.get("/api/home/summary", headers=ADMIN_HEADERS).json()
    assert set(body) >= {"plan", "status", "devices", "online", "isolated",
                        "open_critical", "device_limit"}
    assert body["devices"] >= 1


def test_home_summary_reflects_threat(client, enrolled_device):
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "port_watchdog", "action": "killed", "severity": "critical",
         "summary": "x", "details": {"port": 4444}}]}, headers=enrolled_device["headers"])
    body = client.get("/api/home/summary", headers=ADMIN_HEADERS).json()
    assert body["open_critical"] >= 1 and body["status"] == "attention"

"""Plans, entitlements and feature gating (Individual / Team / Enterprise)."""
import secrets

import pytest

from app.core import plans
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


def _mgr(db_factory, email, org_id):
    db = db_factory()
    auth_service.create_user(db, email, GOOD_PW, "soc_manager", org_id=org_id)
    db.close()


def _bearer(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# -- unit -----------------------------------------------------------------
def test_entitlements_matrix(client, db_session_factory):
    db = db_session_factory()
    ind = _org(db_session_factory, "individual")
    team = _org(db_session_factory, "team")
    ent = _org(db_session_factory, "enterprise")
    assert plans.feature_enabled(db, ind, "integrations") is False
    assert plans.feature_enabled(db, team, "integrations") is True
    assert plans.feature_enabled(db, ent, "sso") is True
    assert plans.entitlements_for(db, ind)["max_devices"] == 5
    assert plans.entitlements_for(db, ent)["max_devices"] == 0        # unlimited
    # Missing org row -> legacy enterprise (non-breaking).
    assert plans.feature_enabled(db, "does-not-exist", "integrations") is True
    db.close()


def test_within_limit():
    class _DB:
        def get(self, *_):
            from types import SimpleNamespace
            return SimpleNamespace(plan="individual", max_devices=0)
    db = _DB()
    assert plans.within_limit(db, "o", "max_users", 0) is True    # individual cap = 1
    assert plans.within_limit(db, "o", "max_users", 1) is False


# -- entitlements endpoint ------------------------------------------------
def test_entitlements_endpoint_default_is_enterprise(client):
    ent = client.get("/api/admin/entitlements", headers=ADMIN_HEADERS).json()
    assert ent["plan"] == "enterprise" and ent["integrations"] is True


def test_entitlements_endpoint_reflects_plan(client, db_session_factory):
    ind = _org(db_session_factory, "individual")
    _mgr(db_session_factory, "m@ind.com", ind)
    ent = client.get("/api/admin/entitlements", headers=_bearer(client, "m@ind.com")).json()
    assert ent["plan"] == "individual"
    assert ent["integrations"] is False and ent["rbac"] is False


# -- endpoint gating ------------------------------------------------------
def test_individual_plan_gates_features(client, db_session_factory):
    ind = _org(db_session_factory, "individual")
    _mgr(db_session_factory, "m2@ind.com", ind)
    h = _bearer(client, "m2@ind.com")
    assert client.post("/api/admin/integrations", headers=h,
                       json={"name": "x", "kind": "webhook", "target": "http://x/h",
                             "min_severity": "low", "enabled": True}).status_code == 402
    assert client.post("/api/admin/groups", headers=h,
                       json={"name": "Dept", "description": ""}).status_code == 402
    assert client.get("/api/admin/analytics/compliance-report", headers=h).status_code == 402


def test_team_plan_unlocks_features(client, db_session_factory):
    team = _org(db_session_factory, "team")
    _mgr(db_session_factory, "m@team.com", team)
    h = _bearer(client, "m@team.com")
    ent = client.get("/api/admin/entitlements", headers=h).json()
    assert ent["plan"] == "team" and ent["compliance_reports"] is True
    # Group creation is allowed (device_groups feature on for team).
    assert client.post("/api/admin/groups", headers=h,
                       json={"name": "Finance", "description": "dept"}).status_code == 201
    # Integrations gate passes (not 402); destination validation may still apply.
    assert client.post("/api/admin/integrations", headers=h,
                       json={"name": "x", "kind": "webhook", "target": "http://x/h",
                             "min_severity": "low", "enabled": True}).status_code != 402
    # Compliance is available for team.
    assert client.get("/api/admin/analytics/compliance-report", headers=h).status_code == 200

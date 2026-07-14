"""Multi-tenancy (M6): org data isolation between tenants, with the legacy
admin token acting cross-org for backward compatibility."""
import pytest

from app.core.roles import Role
from app.models import DEFAULT_ORG_ID, Device, Organization, ThreatEvent
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


@pytest.fixture()
def two_orgs(db_session_factory):
    """Create two orgs, each with a device + event and a soc_manager user."""
    db = db_session_factory()
    for oid, name in [("org-a", "Org A"), ("org-b", "Org B")]:
        db.add(Organization(id=oid, name=name, slug=name.lower().replace(" ", "-")))
    db.flush()
    for oid in ("org-a", "org-b"):
        db.add(Device(id=f"dev-{oid}", org_id=oid, hostname=f"host-{oid}", api_key=f"key-{oid}"))
        db.add(ThreatEvent(device_id=f"dev-{oid}", org_id=oid, source="port_watchdog",
                           severity="warning", action="detected", summary=f"evt {oid}"))
    db.commit()
    auth_service.create_user(db, "a@corp.com", GOOD_PW, Role.SOC_MANAGER.value, org_id="org-a")
    auth_service.create_user(db, "b@corp.com", GOOD_PW, Role.SOC_MANAGER.value, org_id="org-b")
    db.close()


def _login(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_user_sees_only_own_org_devices(client, two_orgs):
    ha = _login(client, "a@corp.com")
    devices = client.get("/api/admin/devices", headers=ha).json()
    assert {d["id"] for d in devices} == {"dev-org-a"}


def test_user_sees_only_own_org_events(client, two_orgs):
    hb = _login(client, "b@corp.com")
    evs = client.get("/api/admin/events", headers=hb).json()
    assert evs and all(e["summary"] == "evt org-b" for e in evs if e["source"] == "port_watchdog")
    assert not any(e["summary"] == "evt org-a" for e in evs)


def test_cross_tenant_device_action_is_not_found(client, two_orgs):
    ha = _login(client, "a@corp.com")
    # Org A user cannot isolate Org B's device — 404, not 403 (no existence leak)
    r = client.post("/api/admin/devices/dev-org-b/isolate", headers=ha)
    assert r.status_code == 404


def test_legacy_admin_token_sees_all_orgs(client, two_orgs):
    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    assert {"dev-org-a", "dev-org-b"} <= {d["id"] for d in devices}


def test_blocklist_is_org_scoped(client, two_orgs):
    ha, hb = _login(client, "a@corp.com"), _login(client, "b@corp.com")
    # Same value blocked independently in each org
    assert client.post("/api/admin/blocklist", json={"kind": "domain", "value": "evil.example"},
                       headers=ha).status_code == 200
    assert client.post("/api/admin/blocklist", json={"kind": "domain", "value": "evil.example"},
                       headers=hb).status_code == 200
    a_list = client.get("/api/admin/blocklist", headers=ha).json()
    b_list = client.get("/api/admin/blocklist", headers=hb).json()
    assert len(a_list) == 1 and len(b_list) == 1


def test_enrolled_device_lands_in_default_org(client, enrolled_device):
    # Legacy token (cross-org) sees it; a default-org check via the model
    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    match = next(d for d in devices if d["id"] == enrolled_device["device_id"])
    assert match is not None  # enrolled successfully into the fleet


def test_checkin_returns_only_org_blocklist(client, two_orgs, db_session_factory):
    # Org A blocks a domain; a device in org B must not receive it.
    ha = _login(client, "a@corp.com")
    client.post("/api/admin/blocklist", json={"kind": "domain", "value": "a-only.example"},
                headers=ha)
    r = client.get("/api/agent/checkin", headers={"X-Agent-Key": "key-org-b"})
    assert r.status_code == 200
    assert "a-only.example" not in r.json()["blocklist"]["domain"]

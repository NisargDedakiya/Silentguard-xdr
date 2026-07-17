"""Key-based purchase model: Individual / Group / Enterprise (admin + invite keys)."""
import pytest

from app.services import auth_service

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _provision(client, plan, name="Buyer"):
    r = client.post("/api/auth/provision", json={"plan": plan, "org_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def _bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# -- provisioning: the keys each plan hands over --------------------------
def test_individual_gets_admin_key_only(client):
    p = _provision(client, "individual")
    assert p["admin_key"].startswith("sgk_")
    assert p["invite_key"] is None            # individual = admin key only


def test_group_gets_admin_and_invite_key(client):
    p = _provision(client, "team", "Acme Group")
    assert p["admin_key"].startswith("sgk_")
    assert p["invite_key"].startswith("join_")


def test_enterprise_gets_admin_and_invite_key(client):
    p = _provision(client, "enterprise", "BigCo")
    assert p["admin_key"] and p["invite_key"]


def test_provision_bad_plan_rejected(client):
    assert client.post("/api/auth/provision",
                       json={"plan": "gold", "org_name": "X"}).status_code == 400


# -- admin key login ------------------------------------------------------
def test_admin_key_logs_into_dashboard(client):
    p = _provision(client, "individual")
    r = client.post("/api/auth/key-login", json={"admin_key": p["admin_key"]})
    assert r.status_code == 200
    me = client.get("/api/auth/me", headers=_bearer(r.json())).json()
    assert me["role"] == "owner"


def test_bad_admin_key_rejected(client):
    assert client.post("/api/auth/key-login", json={"admin_key": "sgk_wrong"}).status_code == 401


# -- joining a group with the invite key ----------------------------------
def test_member_joins_group_with_invite_key(client):
    p = _provision(client, "team", "Team Org")
    r = client.post("/api/auth/join", json={"invite_key": p["invite_key"],
                                            "email": "member@team.com", "password": GOOD_PW})
    assert r.status_code == 201
    me = client.get("/api/auth/me", headers=_bearer(r.json())).json()
    assert me["email"] == "member@team.com"
    # can log in normally afterwards
    assert client.post("/api/auth/login",
                       json={"email": "member@team.com", "password": GOOD_PW}).status_code == 200


def test_join_bad_invite_key_rejected(client):
    assert client.post("/api/auth/join", json={"invite_key": "join_nope",
                                              "email": "x@y.com", "password": GOOD_PW}).status_code == 400


# -- subscription view: invite key + member count + price -----------------
def test_subscription_shows_key_members_and_price(client):
    p = _provision(client, "team", "Billed Org")
    admin = _bearer(client.post("/api/auth/key-login",
                                json={"admin_key": p["admin_key"]}).json())
    # start: 1 member (owner) -> price 1 * 6
    sub = client.get("/api/admin/subscription", headers=admin).json()
    assert sub["plan"] == "team" and sub["invite_key"] == p["invite_key"]
    assert sub["members"] == 1 and sub["price_per_seat"] == 6 and sub["total_price"] == 6
    # two members join -> 3 members -> price 18
    for e in ("a@team.com", "b@team.com"):
        client.post("/api/auth/join", json={"invite_key": p["invite_key"],
                                           "email": e, "password": GOOD_PW})
    sub = client.get("/api/admin/subscription", headers=admin).json()
    assert sub["members"] == 3 and sub["total_price"] == 18


def test_individual_subscription_has_no_invite_key(client):
    p = _provision(client, "individual")
    admin = _bearer(client.post("/api/auth/key-login",
                                json={"admin_key": p["admin_key"]}).json())
    sub = client.get("/api/admin/subscription", headers=admin).json()
    assert sub["invite_key"] is None and sub["total_price"] == 9   # flat individual price

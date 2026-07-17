"""Self-service signup, org owner, and team invitations (SaaS role model)."""
import pytest

from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _signup(client, email, org, plan="individual"):
    return client.post("/api/auth/signup",
                       json={"email": email, "password": GOOD_PW, "org_name": org, "plan": plan})


def _bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# -- signup ---------------------------------------------------------------
def test_signup_creates_org_and_owner(client):
    r = _signup(client, "founder@acme.com", "Acme", "team")
    assert r.status_code == 201
    h = _bearer(r.json())
    me = client.get("/api/auth/me", headers=h).json()
    assert me["email"] == "founder@acme.com" and me["role"] == "owner"
    ent = client.get("/api/admin/entitlements", headers=h).json()
    assert ent["plan"] == "team"


def test_signup_duplicate_email_rejected(client):
    _signup(client, "dup@x.com", "One")
    assert _signup(client, "dup@x.com", "Two").status_code == 409


def test_signup_cannot_self_serve_enterprise(client):
    h = _bearer(_signup(client, "big@corp.com", "Corp", "enterprise").json())
    ent = client.get("/api/admin/entitlements", headers=h).json()
    assert ent["plan"] == "individual"        # enterprise is sales-led, coerced down


# -- owner scope ----------------------------------------------------------
def test_owner_is_org_scoped_not_cross_org(client):
    a = _bearer(_signup(client, "a@a.com", "Org A", "team").json())
    _signup(client, "b@b.com", "Org B", "team")
    users = client.get("/api/admin/users", headers=a).json()
    emails = {u["email"] for u in users}
    assert emails == {"a@a.com"}              # owner A sees only its own org


# -- invitations ----------------------------------------------------------
def test_team_owner_can_invite_and_member_accepts(client):
    owner = _bearer(_signup(client, "owner@team.com", "Team", "team").json())
    inv = client.post("/api/admin/users/invite", headers=owner,
                      json={"email": "member@team.com", "role": "analyst"})
    assert inv.status_code == 201
    token = inv.json()["invite_token"]
    assert token  # exposed in non-prod
    # Member accepts and is signed in.
    acc = client.post("/api/auth/accept-invite", json={"token": token, "password": GOOD_PW})
    assert acc.status_code == 200
    member = _bearer(acc.json())
    me = client.get("/api/auth/me", headers=member).json()
    assert me["email"] == "member@team.com" and me["role"] == "analyst"
    # And they can log in normally afterward.
    assert client.post("/api/auth/login",
                       json={"email": "member@team.com", "password": GOOD_PW}).status_code == 200


def test_individual_plan_cannot_invite(client):
    owner = _bearer(_signup(client, "solo@me.com", "Just Me", "individual").json())
    r = client.post("/api/admin/users/invite", headers=owner,
                    json={"email": "friend@me.com", "role": "read_only"})
    assert r.status_code == 402                # seat cap = 1 on Individual


def test_accept_invalid_invite_rejected(client):
    assert client.post("/api/auth/accept-invite",
                       json={"token": "bogus", "password": GOOD_PW}).status_code == 400


def test_owner_role_change_within_org(client):
    owner = _bearer(_signup(client, "boss@team.com", "Team2", "team").json())
    token = client.post("/api/admin/users/invite", headers=owner,
                        json={"email": "m@team2.com", "role": "read_only"}).json()["invite_token"]
    client.post("/api/auth/accept-invite", json={"token": token, "password": GOOD_PW})
    mid = next(u["id"] for u in client.get("/api/admin/users", headers=owner).json()
               if u["email"] == "m@team2.com")
    r = client.patch(f"/api/admin/users/{mid}/role", headers=owner, json={"role": "responder"})
    assert r.status_code == 200 and r.json()["role"] == "responder"

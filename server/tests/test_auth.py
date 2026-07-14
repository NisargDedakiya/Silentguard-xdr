"""Tests for M4: users, JWT login/refresh/logout, lockout, rate limiting, and
backward-compatible admin authorization."""
import pytest

from app.core import security
from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


@pytest.fixture()
def user(db_session_factory):
    db = db_session_factory()
    u = auth_service.create_user(db, "analyst@example.com", GOOD_PW, Role.SOC_MANAGER.value)
    db.close()
    return u


# -- password hashing -----------------------------------------------------
def test_password_hash_roundtrip():
    h = security.hash_password("correct horse battery staple")
    assert security.verify_password("correct horse battery staple", h)
    assert not security.verify_password("wrong", h)
    assert not security.verify_password("x", "garbage")


# -- password policy ------------------------------------------------------
def test_password_policy_rejects_weak(db_session_factory):
    db = db_session_factory()
    with pytest.raises(auth_service.AuthError) as e:
        auth_service.create_user(db, "a@b.com", "short")
    assert e.value.status_code == 400
    db.close()


# -- login flow -----------------------------------------------------------
def test_login_returns_tokens(client, user):
    r = client.post("/api/auth/login",
                    json={"email": "analyst@example.com", "password": GOOD_PW})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]


def test_login_wrong_password_401(client, user):
    r = client.post("/api/auth/login",
                    json={"email": "analyst@example.com", "password": "nope"})
    assert r.status_code == 401


def test_me_requires_and_returns_user(client, user):
    tokens = client.post("/api/auth/login",
                         json={"email": "analyst@example.com", "password": GOOD_PW}).json()
    r = client.get("/api/auth/me",
                   headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["email"] == "analyst@example.com"
    assert r.json()["role"] == Role.SOC_MANAGER.value
    # No token → 401
    assert client.get("/api/auth/me").status_code == 401


# -- refresh + logout -----------------------------------------------------
def test_refresh_rotates_and_old_token_is_revoked(client, user):
    tokens = client.post("/api/auth/login",
                         json={"email": "analyst@example.com", "password": GOOD_PW}).json()
    r = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    # Old refresh token no longer works (rotation revoked it)
    assert client.post("/api/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_logout_revokes_refresh_token(client, user):
    tokens = client.post("/api/auth/login",
                         json={"email": "analyst@example.com", "password": GOOD_PW}).json()
    assert client.post("/api/auth/logout",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 200
    assert client.post("/api/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 401


# -- lockout --------------------------------------------------------------
def test_account_locks_after_max_attempts(client, user):
    for _ in range(5):
        client.post("/api/auth/login",
                    json={"email": "analyst@example.com", "password": "bad"})
    # Even the correct password is now refused with 423 Locked
    r = client.post("/api/auth/login",
                    json={"email": "analyst@example.com", "password": GOOD_PW})
    assert r.status_code == 423


# -- rate limiting --------------------------------------------------------
def test_login_rate_limited(client, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "login_rate_limit", 3)
    codes = [
        client.post("/api/auth/login", json={"email": "x@y.com", "password": "z"}).status_code
        for _ in range(5)
    ]
    assert 429 in codes


# -- backward compatibility: admin API accepts JWT OR legacy token --------
def test_admin_api_accepts_jwt(client, user):
    tokens = client.post("/api/auth/login",
                         json={"email": "analyst@example.com", "password": GOOD_PW}).json()
    r = client.get("/api/admin/devices",
                   headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200


def test_admin_api_still_accepts_legacy_token(client):
    assert client.get("/api/admin/devices", headers=ADMIN_HEADERS).status_code == 200


def test_admin_api_rejects_garbage_bearer(client):
    r = client.get("/api/admin/devices", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401

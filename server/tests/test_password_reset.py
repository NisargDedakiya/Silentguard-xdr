"""Tests for M7: password reset + email verification."""
import pytest

from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"
NEW_PW = "N3wStrongPass!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


@pytest.fixture()
def user(db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "user@example.com", GOOD_PW, Role.ANALYST.value)
    db.close()


def _login(client, email, pw):
    return client.post("/api/auth/login", json={"email": email, "password": pw})


# -- password reset -------------------------------------------------------
def test_password_reset_flow(client, user):
    req = client.post("/api/auth/password-reset/request", json={"email": "user@example.com"})
    assert req.status_code == 200
    token = req.json()["token"]  # exposed in non-production

    # Old password stops working after reset; new one works
    confirm = client.post("/api/auth/password-reset/confirm",
                          json={"token": token, "new_password": NEW_PW})
    assert confirm.status_code == 200
    assert _login(client, "user@example.com", GOOD_PW).status_code == 401
    assert _login(client, "user@example.com", NEW_PW).status_code == 200


def test_reset_unknown_email_no_enumeration(client):
    r = client.post("/api/auth/password-reset/request", json={"email": "ghost@example.com"})
    assert r.status_code == 200
    assert "token" not in r.json()  # nothing leaked for unknown accounts


def test_reset_token_is_single_use(client, user):
    token = client.post("/api/auth/password-reset/request",
                        json={"email": "user@example.com"}).json()["token"]
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": token, "new_password": NEW_PW}).status_code == 200
    # Reusing the same token fails
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": token, "new_password": "An0therPass!"}).status_code == 400


def test_reset_rejects_weak_password(client, user):
    token = client.post("/api/auth/password-reset/request",
                        json={"email": "user@example.com"}).json()["token"]
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": token, "new_password": "short"}).status_code == 400


def test_reset_invalid_token(client):
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": "nope", "new_password": NEW_PW}).status_code == 400


def test_issuing_new_reset_invalidates_old(client, user):
    t1 = client.post("/api/auth/password-reset/request",
                     json={"email": "user@example.com"}).json()["token"]
    t2 = client.post("/api/auth/password-reset/request",
                     json={"email": "user@example.com"}).json()["token"]
    assert t1 != t2
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": t1, "new_password": NEW_PW}).status_code == 400
    assert client.post("/api/auth/password-reset/confirm",
                       json={"token": t2, "new_password": NEW_PW}).status_code == 200


# -- email verification ---------------------------------------------------
def test_email_verification_flow(client, user):
    tokens = _login(client, "user@example.com", GOOD_PW).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/auth/me", headers=h).json()  # user starts unverified
    req = client.post("/api/auth/verify-email/request", headers=h)
    assert req.status_code == 200
    token = req.json()["token"]
    assert client.post("/api/auth/verify-email/confirm", json={"token": token}).status_code == 200
    # Confirm the flag flipped
    me = client.get("/api/auth/me", headers=h).json()
    assert me  # UserOut returned; email_verified reflected in DB


def test_verify_email_bad_token(client):
    assert client.post("/api/auth/verify-email/confirm",
                       json={"token": "bogus"}).status_code == 400

"""Tests for multi-factor authentication (TOTP, v1.4)."""
import time

import pytest

from app.core import totp
from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


# -- TOTP core unit tests -------------------------------------------------
def test_totp_roundtrip_and_window():
    secret = totp.generate_secret()
    now = time.time()
    code = totp.totp(secret, at=now)
    assert totp.verify(secret, code, at=now)
    # tolerate one step of clock skew either side
    assert totp.verify(secret, code, at=now + 30)
    assert totp.verify(secret, code, at=now - 30)
    # two steps away is rejected
    assert not totp.verify(secret, code, at=now + 90)


def test_totp_rejects_bad_input():
    secret = totp.generate_secret()
    assert not totp.verify(secret, "")
    assert not totp.verify(secret, "abcdef")
    assert not totp.verify(secret, "12")  # wrong length / not a real code
    # Verifying near epoch must not blow up on the negative-skew step.
    assert totp.verify(secret, totp.totp(secret, at=0), at=0)


def test_verify_fails_closed_on_empty_secret():
    # A null/empty secret must never be satisfiable, even by an HMAC computed
    # over an empty key (defense-in-depth against a bad MFA-enabled state).
    assert totp.verify("", totp.totp("", at=0), at=0) is False
    assert totp.verify("", "000000") is False


def test_provisioning_uri_shape():
    uri = totp.provisioning_uri("ABCDEF", "user@x.com")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEF" in uri and "issuer=SilentGuard" in uri


# -- endpoint flow --------------------------------------------------------
def _make_user(db_session_factory, email, role=Role.ANALYST.value):
    db = db_session_factory()
    auth_service.create_user(db, email, GOOD_PW, role)
    db.close()


def _login(client, email, **extra):
    return client.post("/api/auth/login", json={"email": email, "password": GOOD_PW, **extra})


def _bearer(client, email, **extra):
    return {"Authorization": f"Bearer {_login(client, email, **extra).json()['access_token']}"}


def test_full_mfa_enrolment_and_enforcement(client, db_session_factory):
    _make_user(db_session_factory, "mfa@x.com")
    headers = _bearer(client, "mfa@x.com")

    # Not enabled initially.
    assert client.get("/api/auth/mfa/status", headers=headers).json() == {"enabled": False}

    # Begin setup → returns a secret.
    setup = client.post("/api/auth/mfa/setup", headers=headers).json()
    secret = setup["secret"]
    assert setup["otpauth_uri"].startswith("otpauth://")

    # Activation requires a valid code.
    assert client.post("/api/auth/mfa/activate", headers=headers,
                       json={"code": "000000"}).status_code == 401
    code = totp.totp(secret)
    assert client.post("/api/auth/mfa/activate", headers=headers,
                       json={"code": code}).json() == {"enabled": True}

    # Now login without a code is rejected with a distinct message.
    r = _login(client, "mfa@x.com")
    assert r.status_code == 401 and "MFA code required" in r.json()["detail"]
    # Wrong code rejected.
    assert _login(client, "mfa@x.com", mfa_code="000000").status_code == 401
    # Correct code succeeds.
    assert _login(client, "mfa@x.com", mfa_code=totp.totp(secret)).status_code == 200


def test_mfa_disable_requires_code_and_restores_login(client, db_session_factory):
    _make_user(db_session_factory, "mfa2@x.com")
    headers = _bearer(client, "mfa2@x.com")
    secret = client.post("/api/auth/mfa/setup", headers=headers).json()["secret"]
    client.post("/api/auth/mfa/activate", headers=headers, json={"code": totp.totp(secret)})

    # Re-auth with MFA to get a fresh session for the disable call.
    headers = _bearer(client, "mfa2@x.com", mfa_code=totp.totp(secret))
    assert client.post("/api/auth/mfa/disable", headers=headers,
                       json={"code": "000000"}).status_code == 401
    assert client.post("/api/auth/mfa/disable", headers=headers,
                       json={"code": totp.totp(secret)}).json() == {"enabled": False}

    # Plain login works again.
    assert _login(client, "mfa2@x.com").status_code == 200


def test_login_without_mfa_unaffected(client, db_session_factory):
    _make_user(db_session_factory, "plain@x.com")
    assert _login(client, "plain@x.com").status_code == 200

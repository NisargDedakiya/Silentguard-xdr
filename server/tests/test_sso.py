"""Tests for OIDC SSO (v1.4). Network + id_token verification are mocked."""
import pytest

from app.core.config import settings
from app.services import auth_service, sso


@pytest.fixture(autouse=True)
def _reset():
    auth_service.reset_rate_limit()
    sso._discovery_cache.clear()
    yield
    sso._discovery_cache.clear()


@pytest.fixture()
def _configured(monkeypatch):
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example")
    monkeypatch.setattr(settings, "oidc_client_id", "sg-client")
    monkeypatch.setattr(settings, "oidc_client_secret", "s3cret")
    monkeypatch.setattr(settings, "oidc_redirect_uri", "https://xdr/callback")
    monkeypatch.setattr(sso, "discovery",
                        lambda: {"authorization_endpoint": "https://idp.example/authorize",
                                 "token_endpoint": "https://idp.example/token",
                                 "jwks_uri": "https://idp.example/jwks",
                                 "issuer": "https://idp.example"})
    yield


# -- signed state ---------------------------------------------------------
def test_state_roundtrip():
    token = sso._state_token("nonce-123")
    assert sso._verify_state(token) == "nonce-123"


def test_invalid_state_rejected():
    with pytest.raises(sso.SSOError):
        sso._verify_state("not-a-token")


# -- begin_login ----------------------------------------------------------
def test_begin_login_builds_authorize_url(_configured):
    url = sso.begin_login()
    assert url.startswith("https://idp.example/authorize?")
    assert "client_id=sg-client" in url
    assert "response_type=code" in url
    assert "state=" in url and "nonce=" in url


def test_begin_login_requires_config():
    with pytest.raises(sso.SSOError):
        sso.begin_login()


# -- provisioning ---------------------------------------------------------
def test_provision_creates_user_and_issues_tokens(_configured, db_session_factory, monkeypatch):
    monkeypatch.setattr(settings, "oidc_default_role", "analyst")
    db = db_session_factory()
    tokens = sso.provision_and_issue(db, {"email": "New.User@example.com", "email_verified": True})
    assert tokens["access_token"] and tokens["refresh_token"]
    from app.models import User
    user = db.query(User).filter(User.email == "new.user@example.com").first()
    assert user is not None and user.role == "analyst" and user.email_verified
    db.close()


def test_provision_matches_existing_user(_configured, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "existing@example.com", "Sup3rSecret!!", "soc_manager")
    tokens = sso.provision_and_issue(db, {"email": "existing@example.com", "email_verified": True})
    assert tokens["access_token"]
    from app.models import User
    # No duplicate user created; role preserved.
    users = db.query(User).filter(User.email == "existing@example.com").all()
    assert len(users) == 1 and users[0].role == "soc_manager"
    db.close()


def test_provision_rejects_missing_email(_configured, db_session_factory):
    db = db_session_factory()
    with pytest.raises(sso.SSOError):
        sso.provision_and_issue(db, {"email_verified": True})
    db.close()


def test_provision_rejects_unverified_email(_configured, db_session_factory):
    db = db_session_factory()
    with pytest.raises(sso.SSOError):
        sso.provision_and_issue(db, {"email": "x@example.com", "email_verified": False})
    db.close()


def test_provision_enforces_domain_allowlist(_configured, db_session_factory, monkeypatch):
    monkeypatch.setattr(settings, "oidc_allowed_domain", "example.com")
    db = db_session_factory()
    with pytest.raises(sso.SSOError):
        sso.provision_and_issue(db, {"email": "user@evil.com", "email_verified": True})
    # Allowed domain passes.
    assert sso.provision_and_issue(db, {"email": "ok@example.com", "email_verified": True})
    db.close()


# -- endpoints ------------------------------------------------------------
def test_login_endpoint_503_when_unconfigured(client):
    assert client.get("/api/auth/sso/login").status_code == 503


def test_login_endpoint_returns_url(client, _configured):
    r = client.get("/api/auth/sso/login")
    assert r.status_code == 200
    assert r.json()["authorization_url"].startswith("https://idp.example/authorize")


def test_callback_success_issues_tokens(client, _configured, monkeypatch):
    monkeypatch.setattr(sso, "fetch_claims",
                        lambda code, state: {"email": "sso@example.com", "email_verified": True})
    r = client.get("/api/auth/sso/callback?code=abc&state=xyz")
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_callback_maps_sso_error_to_401(client, _configured, monkeypatch):
    def boom(code, state):
        raise sso.SSOError("bad code")
    monkeypatch.setattr(sso, "fetch_claims", boom)
    r = client.get("/api/auth/sso/callback?code=abc&state=xyz")
    assert r.status_code == 401

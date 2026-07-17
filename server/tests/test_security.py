"""Tests for M21 security hardening: SSRF guard + integration URL validation."""
from unittest.mock import patch

from app.core.ssrf import is_safe_host, is_safe_url
from tests.conftest import ADMIN_HEADERS


def _fake_dns(ip):
    return lambda host, *a, **k: [(2, 1, 6, "", (ip, 0))]


# -- SSRF pure function ---------------------------------------------------
def test_public_ip_is_safe():
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("8.8.8.8")):
        assert is_safe_url("https://siem.example.com/hook") is True


def test_loopback_blocked():
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("127.0.0.1")):
        assert is_safe_url("http://localhost/x") is False


def test_cloud_metadata_blocked():
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("169.254.169.254")):
        assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False


def test_private_allowed_by_default_but_blockable():
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("10.0.0.5")):
        assert is_safe_url("https://internal-splunk:8088") is True
        assert is_safe_url("https://internal-splunk:8088", block_private=True) is False


def test_bad_scheme_and_unresolvable():
    assert is_safe_url("ftp://example.com") is False
    assert is_safe_url("not-a-url") is False
    import socket
    with patch("app.core.ssrf.socket.getaddrinfo", side_effect=socket.gaierror):
        assert is_safe_url("https://nope.invalid") is False


def test_is_safe_host():
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("127.0.0.1")):
        assert is_safe_host("localhost") is False


# -- integration creation enforces SSRF ----------------------------------
def test_integration_rejects_unsafe_url(client):
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("127.0.0.1")):
        r = client.post("/api/admin/integrations", json={
            "name": "evil", "kind": "webhook", "config": {"url": "http://127.0.0.1/x"}},
            headers=ADMIN_HEADERS)
    assert r.status_code == 400
    assert "SSRF" in r.json()["detail"]


def test_integration_accepts_public_url(client):
    with patch("app.core.ssrf.socket.getaddrinfo", _fake_dns("8.8.8.8")):
        r = client.post("/api/admin/integrations", json={
            "name": "ok", "kind": "slack", "config": {"url": "https://hooks.slack/x"}},
            headers=ADMIN_HEADERS)
    assert r.status_code == 201


# -- production secret guard (fail-fast) ----------------------------------
def test_production_refuses_demo_secrets(monkeypatch):
    """In production, insecure demo defaults must refuse to boot."""
    import pytest
    from app.main import _check_production_secrets
    from app.core.config import settings
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "admin_token", "silentguard-admin-demo")
    monkeypatch.setattr(settings, "enroll_token", "silentguard-enroll-demo")
    monkeypatch.setattr(settings, "jwt_secret", "")
    monkeypatch.setattr(settings, "allow_insecure", False)
    with pytest.raises(RuntimeError):
        _check_production_secrets()


def test_production_override_allows_boot(monkeypatch):
    from app.main import _check_production_secrets
    from app.core.config import settings
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "admin_token", "silentguard-admin-demo")
    monkeypatch.setattr(settings, "allow_insecure", True)
    _check_production_secrets()  # must not raise


def test_production_secure_config_boots(monkeypatch):
    from app.main import _check_production_secrets
    from app.core.config import settings
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "admin_token", "real-admin-token")
    monkeypatch.setattr(settings, "enroll_token", "real-enroll-token")
    monkeypatch.setattr(settings, "jwt_secret", "a-real-secret")
    monkeypatch.setattr(settings, "cors_origins", "https://app.example")
    monkeypatch.setattr(settings, "allow_insecure", False)
    _check_production_secrets()  # must not raise


def test_dev_skips_secret_check(monkeypatch):
    from app.main import _check_production_secrets
    from app.core.config import settings
    monkeypatch.setattr(settings, "environment", "development")
    _check_production_secrets()  # no-op in dev

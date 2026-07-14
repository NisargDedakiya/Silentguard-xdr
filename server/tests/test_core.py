"""Tests for the M1 foundation: config, logging, middleware, error handling."""
import json
import logging

import pytest
from fastapi import FastAPI

from app.core.config import Settings
from app.core.logging import JsonFormatter, configure_logging, request_id_var
from app.core.middleware import REQUEST_ID_HEADER


# -- config ---------------------------------------------------------------
def test_settings_defaults_match_legacy_env_contract():
    s = Settings()
    assert s.admin_token == "silentguard-admin-demo"
    assert s.enroll_token == "silentguard-enroll-demo"
    assert s.database_url == "sqlite:///./silentguard.db"
    assert s.unresponsive_seconds == 45
    assert s.monitor_interval_seconds == 15


def test_settings_read_legacy_env_names(monkeypatch):
    monkeypatch.setenv("SG_ADMIN_TOKEN", "rotated-token")
    monkeypatch.setenv("SG_UNRESPONSIVE_SECONDS", "90")
    s = Settings()
    assert s.admin_token == "rotated-token"
    assert s.unresponsive_seconds == 90


def test_cors_origin_list_parsing():
    assert Settings(SG_CORS_ORIGINS="*").cors_origin_list == ["*"]
    assert Settings(SG_CORS_ORIGINS="").cors_origin_list == ["*"]
    assert Settings(SG_CORS_ORIGINS="https://a.com, https://b.com").cors_origin_list == [
        "https://a.com",
        "https://b.com",
    ]


def test_is_production_flag():
    assert Settings(SG_ENV="production").is_production is True
    assert Settings(SG_ENV="development").is_production is False


# -- logging --------------------------------------------------------------
def test_json_formatter_emits_structured_line():
    configure_logging("INFO", "json")
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "hello", None, None)
    record.request_id = "abc123"
    record.custom_field = "x"
    line = JsonFormatter().format(record)
    payload = json.loads(line)
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "abc123"
    assert payload["custom_field"] == "x"


def test_request_id_contextvar_default():
    assert request_id_var.get() == "-"


# -- middleware & error handling (end to end) -----------------------------
def test_health_still_works_and_is_unchanged(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "silentguard-xdr"}


def test_secure_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_request_id_header_roundtrip(client):
    # Generated when absent
    r = client.get("/api/health")
    assert r.headers.get(REQUEST_ID_HEADER)
    # Echoed when supplied
    r2 = client.get("/api/health", headers={REQUEST_ID_HEADER: "trace-42"})
    assert r2.headers[REQUEST_ID_HEADER] == "trace-42"


def test_body_size_limit_rejects_oversized(client):
    big = "x" * (6 * 1024 * 1024)
    r = client.post(
        "/api/agent/enroll",
        data=big,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["error"]["type"] == "payload_too_large"


def test_unhandled_exception_returns_stable_envelope():
    """A route that raises should yield the non-leaky 500 envelope, not a stack."""
    from app.core.errors import register_error_handlers
    from app.core.middleware import RequestContextMiddleware
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
    register_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise RuntimeError("kaboom")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/boom")
    assert r.status_code == 500
    body = r.json()
    assert body["error"]["type"] == "internal_error"
    assert "kaboom" not in json.dumps(body)  # no leak
    assert body["error"]["request_id"]

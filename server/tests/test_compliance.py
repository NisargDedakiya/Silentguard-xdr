"""Tests for compliance/executive reporting (v1.4)."""
import pytest

from app.core.roles import Role
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"
URL = "/api/admin/analytics/compliance-report"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _emit_critical(client, headers):
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "port_watchdog", "action": "killed", "severity": "critical",
         "summary": "killed listener", "details": {"port": 4444, "process": "nc"}},
    ]}, headers=headers)


def _login(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_report_structure_and_score(client):
    r = client.get(URL, headers=ADMIN_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"generated_at", "window_days", "score", "controls_summary",
                         "fleet", "detections", "intel", "controls"}
    assert 0 <= body["score"] <= 100
    assert body["fleet"]["total_devices"] == 0
    # Controls are present and each has a valid status.
    assert body["controls"]
    assert all(c["status"] in ("pass", "warn", "fail") for c in body["controls"])
    summ = body["controls_summary"]
    assert summ["pass"] + summ["warn"] + summ["fail"] == len(body["controls"])


def test_open_critical_fails_backlog_control(client, enrolled_device):
    _emit_critical(client, enrolled_device["headers"])
    body = client.get(URL, headers=ADMIN_HEADERS).json()
    assert body["detections"]["open_critical"] == 1
    backlog = next(c for c in body["controls"] if c["id"] == "critical_backlog")
    assert backlog["status"] == "fail"


def test_resolving_clears_backlog_control(client, enrolled_device):
    _emit_critical(client, enrolled_device["headers"])
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    client.post(f"/api/admin/detections/{det_id}/resolve", headers=ADMIN_HEADERS)
    body = client.get(URL, headers=ADMIN_HEADERS).json()
    assert body["detections"]["open_critical"] == 0
    backlog = next(c for c in body["controls"] if c["id"] == "critical_backlog")
    assert backlog["status"] == "pass"


def test_intel_content_control_reflects_rules(client):
    # No content initially → warn.
    body = client.get(URL, headers=ADMIN_HEADERS).json()
    ctrl = next(c for c in body["controls"] if c["id"] == "detection_content")
    assert ctrl["status"] == "warn"
    # Add an IOC → pass.
    client.post("/api/admin/intel/iocs", headers=ADMIN_HEADERS,
                json={"ioc_type": "domain", "value": "evil.example", "confidence": 90})
    body = client.get(URL, headers=ADMIN_HEADERS).json()
    assert body["intel"]["iocs"] == 1
    ctrl = next(c for c in body["controls"] if c["id"] == "detection_content")
    assert ctrl["status"] == "pass"


def test_auditor_can_read_report(client, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "auditor@x.com", GOOD_PW, Role.AUDITOR.value)
    db.close()
    h = _login(client, "auditor@x.com")
    assert client.get(URL, headers=h).status_code == 200


def test_read_only_cannot_read_report(client, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    h = _login(client, "ro@x.com")
    assert client.get(URL, headers=h).status_code == 403

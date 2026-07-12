"""Tests for M18: integrations, dispatch, formatters, and exports."""
import json
from unittest.mock import patch

import pytest

from app.core.roles import Role
from app.services import auth_service
from app.services import integrations as integ
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


@pytest.fixture(autouse=True)
def _resolve_dns():
    """Integration destinations use example hostnames; resolve them to a public
    IP so the SSRF guard (M21) treats them as valid, without real DNS."""
    with patch("app.core.ssrf.socket.getaddrinfo",
               lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]):
        yield


# -- formatters -----------------------------------------------------------
def test_format_cef_escapes_and_headers():
    line = integ.format_cef({"severity": "critical", "name": "Reverse shell",
                             "hostname": "vm|1", "source": "port_watchdog",
                             "action": "killed", "technique": {"id": "T1059"}})
    assert line.startswith("CEF:0|SilentGuard|XDR|1.0|port_watchdog|Reverse shell|")
    assert "dvchost=vm\\|1" in line
    assert "cs2=T1059" in line


def test_format_chat_has_slack_and_discord_keys():
    body = json.loads(integ.format_chat({"summary": "boom", "hostname": "h", "severity": "critical"}))
    assert body["text"] == body["content"]
    assert "boom" in body["text"]


# -- CRUD + RBAC ----------------------------------------------------------
def test_integration_crud(client):
    r = client.post("/api/admin/integrations", json={
        "name": "soc-slack", "kind": "slack",
        "config": {"url": "https://hooks.slack/x"}, "min_severity": "high"},
        headers=ADMIN_HEADERS)
    assert r.status_code == 201
    iid = r.json()["id"]
    assert any(i["id"] == iid for i in client.get("/api/admin/integrations",
                                                  headers=ADMIN_HEADERS).json())
    assert client.delete(f"/api/admin/integrations/{iid}",
                         headers=ADMIN_HEADERS).status_code == 200


def test_invalid_kind_rejected(client):
    assert client.post("/api/admin/integrations",
                       json={"name": "x", "kind": "carrierpigeon", "config": {}},
                       headers=ADMIN_HEADERS).status_code == 400


def test_read_only_cannot_manage_integrations(client, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    tok = client.post("/api/auth/login", json={"email": "ro@x.com", "password": GOOD_PW}).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.post("/api/admin/integrations",
                       json={"name": "x", "kind": "webhook", "config": {"url": "http://x"}},
                       headers=h).status_code == 403


# -- dispatch on ingestion ------------------------------------------------
def test_critical_event_dispatched_to_matching_integration(client, enrolled_device):
    client.post("/api/admin/integrations", json={
        "name": "wh", "kind": "webhook", "config": {"url": "http://sink/x"},
        "min_severity": "high"}, headers=ADMIN_HEADERS)
    sent = []
    with patch.object(integ, "_send_webhook", lambda url, body, headers=None: sent.append((url, body))):
        client.post("/api/agent/telemetry", json={"events": [{
            "source": "port_watchdog", "action": "killed", "severity": "critical",
            "summary": "killed", "details": {"port": 4444}}]},
            headers=enrolled_device["headers"])
    # The critical event plus its detection both forward.
    assert len(sent) >= 1
    assert sent[0][0] == "http://sink/x"


def test_below_threshold_not_dispatched(client, enrolled_device):
    client.post("/api/admin/integrations", json={
        "name": "wh", "kind": "webhook", "config": {"url": "http://sink/x"},
        "min_severity": "critical"}, headers=ADMIN_HEADERS)
    sent = []
    with patch.object(integ, "_send_webhook", lambda *a, **k: sent.append(a)):
        client.post("/api/agent/telemetry", json={"events": [{
            "source": "agent", "action": "note", "severity": "info", "summary": "quiet"}]},
            headers=enrolled_device["headers"])
    assert sent == []


def test_delivery_failure_is_swallowed(client, enrolled_device):
    client.post("/api/admin/integrations", json={
        "name": "wh", "kind": "webhook", "config": {"url": "http://sink/x"}},
        headers=ADMIN_HEADERS)
    def boom(*a, **k):
        raise OSError("refused")
    with patch.object(integ, "_send_webhook", boom):
        r = client.post("/api/agent/telemetry", json={"events": [{
            "source": "port_watchdog", "action": "killed", "severity": "critical",
            "summary": "x", "details": {"port": 4444}}]},
            headers=enrolled_device["headers"])
    assert r.status_code == 200  # ingestion unaffected


# -- export ---------------------------------------------------------------
def test_export_ndjson_and_cef(client, enrolled_device):
    client.post("/api/agent/telemetry", json={"events": [{
        "source": "dns_sinkhole", "action": "blocked", "severity": "warning",
        "summary": "blocked bad.example", "details": {"domain": "bad.example"}}]},
        headers=enrolled_device["headers"])
    nd = client.get("/api/admin/export/events?format=ndjson", headers=ADMIN_HEADERS)
    assert nd.status_code == 200
    first = json.loads(nd.text.splitlines()[0])
    assert first["source"] in ("dns_sinkhole", "agent")
    cef = client.get("/api/admin/export/events?format=cef", headers=ADMIN_HEADERS)
    assert cef.status_code == 200 and cef.text.startswith("CEF:0|SilentGuard")
    assert client.get("/api/admin/export/events?format=xml",
                      headers=ADMIN_HEADERS).status_code == 400

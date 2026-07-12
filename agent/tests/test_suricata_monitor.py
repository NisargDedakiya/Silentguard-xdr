"""Suricata eve.json ingestion tests (v1.5)."""
import json

from silentguard_agent.monitors.suricata_monitor import SuricataMonitor


def _alert_line(sig="ET MALWARE Cobalt Strike", sid=2027, sev=1,
                src="10.0.0.5", dst="10.0.0.9"):
    return json.dumps({
        "event_type": "alert", "src_ip": src, "dest_ip": dst, "dest_port": 443,
        "proto": "TCP",
        "alert": {"signature": sig, "signature_id": sid, "category": "A Network Trojan",
                  "severity": sev},
    }) + "\n"


def _mk(config, telemetry, tmp_path, enabled=True):
    eve = tmp_path / "eve.json"
    eve.write_text("")
    config.suricata_enabled = enabled
    config.suricata_eve_path = str(eve)
    return SuricataMonitor(config, telemetry), eve


def test_disabled_is_noop(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path, enabled=False)
    eve.write_text(_alert_line())
    mon.scan()
    assert telemetry.events == []


def test_baseline_skips_existing_alerts(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    eve.write_text(_alert_line())  # pre-existing
    mon.scan()  # baseline: seeks to end
    assert telemetry.by_action("alert") == []


def test_new_alert_is_forwarded(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    mon.scan()  # baseline on empty file
    with eve.open("a") as f:
        f.write(_alert_line())
    mon.scan()
    alerts = telemetry.by_action("alert")
    assert len(alerts) == 1
    d = alerts[0]["details"]
    assert d["signature"] == "ET MALWARE Cobalt Strike"
    assert d["signature_id"] == 2027
    assert d["src_ip"] == "10.0.0.5" and d["dest_ip"] == "10.0.0.9"
    assert alerts[0]["source"] == "suricata"


def test_non_alert_events_ignored(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    mon.scan()
    with eve.open("a") as f:
        f.write(json.dumps({"event_type": "flow", "src_ip": "1.1.1.1"}) + "\n")
        f.write(json.dumps({"event_type": "dns"}) + "\n")
    mon.scan()
    assert telemetry.by_action("alert") == []


def test_malformed_lines_are_skipped(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    mon.scan()
    with eve.open("a") as f:
        f.write("not json\n")
        f.write(_alert_line(sig="Rule B"))
    mon.scan()
    alerts = telemetry.by_action("alert")
    assert len(alerts) == 1 and alerts[0]["details"]["signature"] == "Rule B"


def test_not_replayed_across_scans(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    mon.scan()
    with eve.open("a") as f:
        f.write(_alert_line())
    mon.scan()
    mon.scan()  # nothing new
    assert len(telemetry.by_action("alert")) == 1


def test_log_rotation_resets_offset(config, telemetry, tmp_path):
    mon, eve = _mk(config, telemetry, tmp_path)
    mon.scan()
    with eve.open("a") as f:
        f.write(_alert_line(sig="Before"))
    mon.scan()
    # Rotation: file shrinks below current offset.
    eve.write_text(_alert_line(sig="After"))
    mon.scan()
    sigs = [e["details"]["signature"] for e in telemetry.by_action("alert")]
    assert sigs == ["Before", "After"]


def test_burst_is_bounded(config, telemetry, tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("")
    config.suricata_enabled = True
    config.suricata_eve_path = str(eve)
    mon = SuricataMonitor(config, telemetry, max_events_per_scan=5)
    mon.scan()
    with eve.open("a") as f:
        for i in range(20):
            f.write(_alert_line(sig=f"S{i}"))
    mon.scan()
    assert len(telemetry.by_action("alert")) == 5

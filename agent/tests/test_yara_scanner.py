"""YARA scanner tests (yara library mocked via injected rules)."""
from pathlib import Path

from silentguard_agent.monitors.yara_scanner import YaraScanner


class FakeMatch:
    def __init__(self, rule):
        self.rule = rule


class FakeRules:
    """Stand-in for a compiled yara.Rules: matches files whose path contains a
    trigger substring."""
    def __init__(self, trigger="evil", rule_name="Malware_Generic"):
        self.trigger = trigger
        self.rule_name = rule_name

    def match(self, filepath=None):
        return [FakeMatch(self.rule_name)] if self.trigger in str(filepath) else []


class FakeQuarantine:
    def __init__(self):
        self.calls = []

    def quarantine(self, path, sha256=None, reason=""):
        self.calls.append({"path": str(path), "reason": reason})
        return {"id": "q1", "original_path": str(path)}


def _mk(config, telemetry, tmp_path, **kw):
    config.file_drop_dirs = [str(tmp_path)]
    return YaraScanner(config, telemetry, rules=FakeRules(), **kw)


def test_disabled_when_no_rules(config, telemetry, tmp_path):
    config.file_drop_dirs = [str(tmp_path)]
    config.yara_enabled = False
    scanner = YaraScanner(config, telemetry)  # no injected rules, not enabled
    assert scanner.enabled is False
    (tmp_path / "evil.bin").write_text("x")
    scanner.scan()  # no-op
    assert telemetry.events == []


def test_baseline_is_silent(config, telemetry, tmp_path):
    (tmp_path / "evil.bin").write_text("x")
    scanner = _mk(config, telemetry, tmp_path)
    scanner.scan()  # baseline: pre-existing file not scanned
    assert telemetry.by_action("match") == []
    assert telemetry.by_action("quarantined") == []


def test_new_matching_file_is_reported_and_quarantined(config, telemetry, tmp_path):
    q = FakeQuarantine()
    scanner = _mk(config, telemetry, tmp_path, quarantine=q)
    scanner.scan()  # baseline (empty)
    (tmp_path / "evil.bin").write_text("payload")
    scanner.scan()
    events = telemetry.by_action("quarantined")
    assert len(events) == 1
    d = events[0]["details"]
    assert d["rules"] == ["Malware_Generic"]
    assert d["quarantine_id"] == "q1"
    assert events[0]["severity"] == "critical"
    assert len(q.calls) == 1


def test_non_matching_file_is_ignored(config, telemetry, tmp_path):
    scanner = _mk(config, telemetry, tmp_path)
    scanner.scan()
    (tmp_path / "clean.txt").write_text("benign")
    scanner.scan()
    assert telemetry.events == []


def test_match_without_quarantine_emits_match(config, telemetry, tmp_path):
    config.yara_quarantine = False
    scanner = _mk(config, telemetry, tmp_path, quarantine=FakeQuarantine())
    scanner.scan()
    (tmp_path / "evil.bin").write_text("x")
    scanner.scan()
    assert len(telemetry.by_action("match")) == 1
    assert telemetry.by_action("quarantined") == []


def test_file_not_reported_twice(config, telemetry, tmp_path):
    scanner = _mk(config, telemetry, tmp_path)
    scanner.scan()
    (tmp_path / "evil.bin").write_text("x")
    scanner.scan()
    scanner.scan()
    assert len(telemetry.by_action("match") + telemetry.by_action("quarantined")) == 1

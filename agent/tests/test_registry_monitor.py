"""Registry autorun monitor tests (winreg mocked via snapshot injection)."""
import sys

from silentguard_agent.monitors.registry_monitor import RegistryMonitor

RUN = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def _mon(config, telemetry, snapshots):
    """Build a monitor whose _snapshot() yields the given sequence of dicts."""
    mon = RegistryMonitor(config, telemetry)
    mon.enabled = True  # force-on so the diff logic runs off-Windows
    seq = iter(snapshots)
    mon._snapshot = lambda: next(seq)
    return mon


def test_disabled_off_windows_by_default(config, telemetry):
    mon = RegistryMonitor(config, telemetry)
    # On this Linux CI host the monitor must be inert.
    assert mon.enabled is (sys.platform.startswith("win") and config.registry_enabled)
    if not sys.platform.startswith("win"):
        assert mon.enabled is False
        mon.scan()
        assert telemetry.events == []


def test_baseline_is_silent(config, telemetry):
    mon = _mon(config, telemetry, [{RUN: {"OneDrive": "C:\\onedrive.exe"}}])
    mon.scan()
    assert telemetry.events == []


def test_new_autorun_is_reported(config, telemetry):
    mon = _mon(config, telemetry, [
        {RUN: {"OneDrive": "C:\\onedrive.exe"}},
        {RUN: {"OneDrive": "C:\\onedrive.exe", "Evil": "C:\\temp\\evil.exe"}},
    ])
    mon.scan()  # baseline
    mon.scan()
    added = telemetry.by_action("autorun_added")
    assert len(added) == 1
    d = added[0]["details"]
    assert d["name"] == "Evil" and d["command_line"] == "C:\\temp\\evil.exe"
    assert "CurrentVersion\\Run" in added[0]["summary"]


def test_changed_autorun_is_reported(config, telemetry):
    mon = _mon(config, telemetry, [
        {RUN: {"Updater": "C:\\good.exe"}},
        {RUN: {"Updater": "C:\\bad.exe"}},
    ])
    mon.scan()
    mon.scan()
    changed = telemetry.by_action("autorun_changed")
    assert len(changed) == 1
    assert changed[0]["details"]["command_line"] == "C:\\bad.exe"


def test_unchanged_autorun_is_silent(config, telemetry):
    mon = _mon(config, telemetry, [
        {RUN: {"Updater": "C:\\good.exe"}},
        {RUN: {"Updater": "C:\\good.exe"}},
    ])
    mon.scan()
    mon.scan()
    assert telemetry.events == []

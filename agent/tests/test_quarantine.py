"""Quarantine manager + file-drop monitor tests using real temp files."""
import os

import pytest

from silentguard_agent.config import EICAR_SHA256, AgentConfig
from silentguard_agent.monitors.file_drop import FileDropMonitor
from silentguard_agent.quarantine import (
    VERDICT_ALLOWLISTED,
    VERDICT_KNOWN_BAD,
    VERDICT_UNKNOWN,
    QuarantineManager,
    sha256_of,
)
from tests.conftest import FakeTelemetry

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def live_config(tmp_path):
    """Config with dry_run disabled so quarantine really moves files (only
    ever inside tmp_path)."""
    cfg = AgentConfig()
    cfg.dry_run = False
    cfg.file_drop_dirs = [str(tmp_path / "drop")]
    (tmp_path / "drop").mkdir()
    return cfg


@pytest.fixture()
def manager(live_config, tmp_path):
    return QuarantineManager(live_config, quarantine_dir=tmp_path / "qdir")


def test_sha256_of_known_content(tmp_path):
    f = tmp_path / "eicar.com"
    f.write_bytes(EICAR)
    assert sha256_of(f) == EICAR_SHA256
    assert sha256_of(tmp_path / "missing") is None


def test_verdicts(manager, live_config):
    live_config.allowlisted_hashes.add("aaa")
    assert manager.verdict(EICAR_SHA256) == VERDICT_KNOWN_BAD
    assert manager.verdict("aaa") == VERDICT_ALLOWLISTED
    assert manager.verdict("bbb") == VERDICT_UNKNOWN
    assert manager.verdict(None) == VERDICT_UNKNOWN


def test_quarantine_moves_and_strips_permissions(manager, tmp_path):
    victim = tmp_path / "payload.bin"
    victim.write_bytes(b"malware")
    entry = manager.quarantine(victim, reason="test")
    assert entry is not None
    assert not victim.exists()
    stored = manager.dir / entry["stored_name"]
    assert stored.exists()
    assert (os.stat(stored).st_mode & 0o777) == 0
    assert manager.list()[0]["id"] == entry["id"]
    assert entry["status"] == "quarantined"


def test_restore_roundtrip(manager, tmp_path):
    victim = tmp_path / "sub" / "payload.bin"
    victim.parent.mkdir()
    victim.write_bytes(b"malware")
    entry = manager.quarantine(victim)
    restored = manager.restore(entry["id"])
    assert restored["status"] == "restored"
    assert victim.exists()
    assert victim.read_bytes() == b"malware"
    # Second restore of the same id is a no-op failure
    assert manager.restore(entry["id"]) is None


def test_restore_unknown_id(manager):
    assert manager.restore("nope") is None


def test_quarantine_missing_file_returns_none(manager, tmp_path):
    assert manager.quarantine(tmp_path / "ghost") is None


def test_file_drop_quarantines_known_bad(live_config, manager, tmp_path):
    telemetry = FakeTelemetry()
    mon = FileDropMonitor(live_config, telemetry, manager)
    drop = tmp_path / "drop"
    (drop / "pre-existing.txt").write_bytes(b"already here")
    mon.scan()  # baseline — no alerts
    assert telemetry.events == []

    (drop / "eicar.com").write_bytes(EICAR)
    mon.scan()
    quarantined = telemetry.by_action("quarantined")
    assert len(quarantined) == 1
    assert quarantined[0]["severity"] == "critical"
    assert quarantined[0]["details"]["sha256"] == EICAR_SHA256
    assert not (drop / "eicar.com").exists()


def test_file_drop_reports_new_executable(live_config, manager, tmp_path):
    telemetry = FakeTelemetry()
    mon = FileDropMonitor(live_config, telemetry, manager)
    mon.scan()  # baseline
    exe = tmp_path / "drop" / "dropper.sh"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    mon.scan()
    detected = telemetry.by_action("detected")
    assert len(detected) == 1
    assert detected[0]["severity"] == "warning"
    # Plain data files are ignored, and nothing is reported twice
    (tmp_path / "drop" / "notes.txt").write_text("hello")
    mon.scan()
    assert len(telemetry.by_action("detected")) == 1


def test_file_drop_skips_allowlisted(live_config, manager, tmp_path):
    live_config.allowlisted_hashes.add(EICAR_SHA256)
    telemetry = FakeTelemetry()
    mon = FileDropMonitor(live_config, telemetry, manager)
    mon.scan()
    (tmp_path / "drop" / "eicar.com").write_bytes(EICAR)
    mon.scan()
    assert telemetry.events == []
    assert (tmp_path / "drop" / "eicar.com").exists()

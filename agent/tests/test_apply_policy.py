"""Tests for M16 agent-side policy application."""
from silentguard_agent.main import apply_policy


def test_apply_policy_merges_settings(config):
    config.suspicious_ports = {4444}
    config.blocked_processes = {"nc.exe"}
    config.blocked_domains = set()
    config.file_drop_dirs = ["/tmp"]
    config.block_usb_storage = False

    apply_policy(config, {
        "suspicious_ports": [9999, "1234"],
        "blocked_processes": ["mimikatz.exe"],
        "blocked_domains": ["evil.example"],
        "file_drop_dirs": ["/home/user/Downloads", "/tmp"],
        "block_usb_storage": True,
    })

    assert {4444, 9999, 1234} <= config.suspicious_ports
    assert "mimikatz.exe" in config.blocked_processes and "nc.exe" in config.blocked_processes
    assert "evil.example" in config.blocked_domains
    assert config.file_drop_dirs.count("/tmp") == 1  # no duplicate
    assert "/home/user/Downloads" in config.file_drop_dirs
    assert config.block_usb_storage is True


def test_apply_policy_empty_is_noop(config):
    before = set(config.suspicious_ports)
    apply_policy(config, {})
    assert set(config.suspicious_ports) == before


def test_apply_policy_ignores_bad_ports(config):
    apply_policy(config, {"suspicious_ports": ["notaport", None, 5555]})
    assert 5555 in config.suspicious_ports

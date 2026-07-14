"""Tests for TLS certificate pinning (v1.4)."""
from silentguard_agent import cert_pinning
from silentguard_agent.cert_pinning import (FingerprintAdapter, build_session,
                                            normalize_pin, parse_pins)
from silentguard_agent.config import AgentConfig
from silentguard_agent.telemetry import TelemetryClient


def test_normalize_pin_strips_colons_and_case():
    assert normalize_pin("AA:BB:CC") == "aabbcc"
    assert normalize_pin(" Ff:00 ") == "ff00"


def test_parse_pins_splits_and_normalizes():
    assert parse_pins("AA:BB, cc:dd") == ["aabb", "ccdd"]
    assert parse_pins("") == []
    assert parse_pins(None) == []


def test_build_session_without_pin_has_no_fingerprint_adapter():
    cfg = AgentConfig()
    cfg.pin_sha256 = ""
    session = build_session(cfg)
    https = session.get_adapter("https://example.com")
    assert not isinstance(https, FingerprintAdapter)


def test_build_session_with_pin_mounts_adapter():
    cfg = AgentConfig()
    cfg.pin_sha256 = "AB:CD:EF:00"
    session = build_session(cfg)
    adapter = session.get_adapter("https://example.com")
    assert isinstance(adapter, FingerprintAdapter)
    assert adapter._fingerprint == "abcdef00"


def test_fingerprint_adapter_passes_assert_fingerprint(monkeypatch):
    captured = {}
    import requests.adapters as ra
    orig = ra.HTTPAdapter.init_poolmanager

    def spy(self, *args, **kwargs):
        captured.update(kwargs)
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(ra.HTTPAdapter, "init_poolmanager", spy)
    FingerprintAdapter("deadbeef")
    assert captured.get("assert_fingerprint") == "deadbeef"


def test_multiple_pins_uses_first(monkeypatch, caplog):
    cfg = AgentConfig()
    cfg.pin_sha256 = "aa:aa, bb:bb"
    session = build_session(cfg)
    assert session.get_adapter("https://x")._fingerprint == "aaaa"


def test_telemetry_client_uses_pinned_session():
    cfg = AgentConfig()
    cfg.pin_sha256 = "11:22:33"
    client = TelemetryClient(cfg)
    assert isinstance(client.session.get_adapter("https://x"), FingerprintAdapter)

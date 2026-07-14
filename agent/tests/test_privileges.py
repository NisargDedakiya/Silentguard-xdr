"""Enforcement-capability detection tests (v1.5)."""
from silentguard_agent import privileges
from silentguard_agent.config import AgentConfig


def test_is_elevated_returns_bool():
    assert isinstance(privileges.is_elevated(), bool)


def test_dry_run_disables_enforcement(monkeypatch):
    monkeypatch.setattr(privileges, "is_elevated", lambda: True)
    cfg = AgentConfig()
    cfg.dry_run = True
    status = privileges.enforcement_status(cfg)
    assert status["can_enforce"] is False
    assert any("dry-run" in r for r in status["reasons"])
    assert "device isolation" in status["affected"]


def test_not_elevated_disables_enforcement(monkeypatch):
    monkeypatch.setattr(privileges, "is_elevated", lambda: False)
    cfg = AgentConfig()
    cfg.dry_run = False
    status = privileges.enforcement_status(cfg)
    assert status["can_enforce"] is False
    assert any("elevated" in r for r in status["reasons"])


def test_elevated_live_enables_enforcement(monkeypatch):
    monkeypatch.setattr(privileges, "is_elevated", lambda: True)
    cfg = AgentConfig()
    cfg.dry_run = False
    status = privileges.enforcement_status(cfg)
    assert status["can_enforce"] is True
    assert status["affected"] == []
    assert status["reasons"] == []

import pytest

from silentguard_agent.config import AgentConfig


class FakeTelemetry:
    """Captures emit() calls without any network I/O."""

    def __init__(self):
        self.events = []

    def emit(self, source, action, summary, severity="info", details=None):
        self.events.append(
            {
                "source": source,
                "action": action,
                "summary": summary,
                "severity": severity,
                "details": details or {},
            }
        )

    def by_action(self, action):
        return [e for e in self.events if e["action"] == action]


@pytest.fixture()
def config():
    cfg = AgentConfig()
    cfg.dry_run = True  # never touch the real OS in tests
    return cfg


@pytest.fixture()
def telemetry():
    return FakeTelemetry()

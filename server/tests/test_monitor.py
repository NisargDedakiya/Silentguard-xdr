"""Tests for the background liveness monitor (device_unresponsive events)."""
import datetime

import pytest

from app import monitor
from app.models import Device, ThreatEvent, utcnow


@pytest.fixture()
def patched_sessionlocal(db_session_factory, monkeypatch):
    monkeypatch.setattr(monitor, "SessionLocal", db_session_factory)
    return db_session_factory


def _make_device(session_factory, last_seen_delta_s, stopped=False, alerted=False):
    db = session_factory()
    dev = Device(
        id=f"dev-{last_seen_delta_s}-{stopped}-{alerted}",
        hostname="vm",
        last_seen=utcnow() - datetime.timedelta(seconds=last_seen_delta_s),
        stopped=stopped,
        unresponsive_alerted=alerted,
    )
    db.add(dev)
    db.commit()
    db.close()
    return dev.id


@pytest.mark.asyncio
async def test_flags_silent_device(patched_sessionlocal, monkeypatch):
    monkeypatch.setattr(monitor, "UNRESPONSIVE_SECONDS", 30)
    _make_device(patched_sessionlocal, last_seen_delta_s=120)
    flagged = await monitor.check_once()
    assert flagged == ["vm"]

    db = patched_sessionlocal()
    events = db.query(ThreatEvent).filter(ThreatEvent.action == "device_unresponsive").all()
    assert len(events) == 1 and events[0].severity == "critical"
    db.close()


@pytest.mark.asyncio
async def test_does_not_flag_recent_device(patched_sessionlocal, monkeypatch):
    monkeypatch.setattr(monitor, "UNRESPONSIVE_SECONDS", 30)
    _make_device(patched_sessionlocal, last_seen_delta_s=5)
    assert await monitor.check_once() == []


@pytest.mark.asyncio
async def test_does_not_flag_cleanly_stopped_device(patched_sessionlocal, monkeypatch):
    monkeypatch.setattr(monitor, "UNRESPONSIVE_SECONDS", 30)
    _make_device(patched_sessionlocal, last_seen_delta_s=120, stopped=True)
    assert await monitor.check_once() == []


@pytest.mark.asyncio
async def test_does_not_double_flag(patched_sessionlocal, monkeypatch):
    monkeypatch.setattr(monitor, "UNRESPONSIVE_SECONDS", 30)
    _make_device(patched_sessionlocal, last_seen_delta_s=120)
    assert await monitor.check_once() == ["vm"]
    assert await monitor.check_once() == []  # already alerted

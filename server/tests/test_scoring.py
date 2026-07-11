"""Tests for device risk scoring."""
import datetime

from app.models import Device, ThreatEvent, utcnow
from app.scoring import compute_score, risk_band

from .conftest import ADMIN_HEADERS


def _seed(db_factory, events):
    db = db_factory()
    dev = Device(id="d1", hostname="vm")
    db.add(dev)
    for severity, age_hours in events:
        db.add(
            ThreatEvent(
                device_id="d1",
                severity=severity,
                source="test",
                action="x",
                summary="e",
                timestamp=utcnow() - datetime.timedelta(hours=age_hours),
            )
        )
    db.commit()
    db.close()


def test_bands():
    assert risk_band(0) == "clear"
    assert risk_band(5) == "low"
    assert risk_band(10) == "elevated"
    assert risk_band(25) == "critical"


def test_fresh_critical_scores_near_full_weight(db_session_factory):
    _seed(db_session_factory, [("critical", 0)])
    result = compute_score(db_session_factory(), "d1")
    assert 9.9 <= result["score"] <= 10.0
    assert result["band"] == "elevated"
    assert result["counts"]["critical"] == 1


def test_old_events_decay_toward_zero(db_session_factory):
    _seed(db_session_factory, [("critical", 23.9)])
    result = compute_score(db_session_factory(), "d1")
    assert result["score"] < 1.0


def test_events_outside_window_ignored(db_session_factory):
    _seed(db_session_factory, [("critical", 30)])
    result = compute_score(db_session_factory(), "d1")
    assert result["score"] == 0.0
    assert result["event_count"] == 0


def test_info_events_add_no_weight(db_session_factory):
    _seed(db_session_factory, [("info", 0), ("info", 1)])
    result = compute_score(db_session_factory(), "d1")
    assert result["score"] == 0.0
    assert result["counts"]["info"] == 2


def test_score_endpoint_and_device_list_badge(client, enrolled_device):
    client.post(
        "/api/agent/telemetry",
        headers=enrolled_device["headers"],
        json={"events": [{"source": "port_watchdog", "severity": "critical",
                          "action": "killed", "summary": "boom"}]},
    )
    device_id = enrolled_device["device_id"]
    score = client.get(f"/api/admin/devices/{device_id}/score", headers=ADMIN_HEADERS).json()
    assert score["score"] > 0 and score["band"] in ("elevated", "critical")

    devices = client.get("/api/admin/devices", headers=ADMIN_HEADERS).json()
    assert devices[0]["risk_score"] > 0
    assert devices[0]["risk_band"] in ("elevated", "critical")


def test_score_unknown_device_404(client):
    assert client.get("/api/admin/devices/nope/score", headers=ADMIN_HEADERS).status_code == 404

"""Device risk scoring — foundation for the roadmap "Behavioral Detection
Engine".

A simple weighted score over a rolling 24h window: each event contributes its
severity weight, linearly decayed by age (a fresh critical counts full weight,
one ~24h old counts near zero). This gives admins an at-a-glance sense of which
devices are currently "hot" without any ML.
"""
import datetime

from sqlalchemy.orm import Session

from .models import ThreatEvent, utcnow
from .utils.time import aware_utc

SEVERITY_WEIGHTS = {"critical": 10.0, "warning": 3.0, "info": 0.0}
WINDOW = datetime.timedelta(hours=24)


def risk_band(score: float) -> str:
    if score >= 20:
        return "critical"
    if score >= 8:
        return "elevated"
    if score > 0:
        return "low"
    return "clear"


def _empty_score(device_id: str) -> dict:
    return {
        "device_id": device_id,
        "score": 0.0,
        "band": "clear",
        "window_hours": 24,
        "counts": {"critical": 0, "warning": 0, "info": 0},
        "event_count": 0,
    }


def compute_scores(db: Session, device_ids: list[str] | None = None) -> dict[str, dict]:
    """Batch-compute risk scores. One grouped query fetches every in-window
    event (optionally restricted to `device_ids`) and the per-device
    aggregation happens in Python — no per-device query loop."""
    now = utcnow()
    cutoff = now - WINDOW
    window_seconds = WINDOW.total_seconds()

    q = db.query(ThreatEvent.device_id, ThreatEvent.severity, ThreatEvent.timestamp).filter(
        ThreatEvent.timestamp >= cutoff
    )
    if device_ids is not None:
        q = q.filter(ThreatEvent.device_id.in_(device_ids))

    scores: dict[str, dict] = {d: _empty_score(d) for d in (device_ids or [])}
    raw: dict[str, float] = {}
    for device_id, severity, timestamp in q.all():
        entry = scores.setdefault(device_id, _empty_score(device_id))
        entry["counts"][severity] = entry["counts"].get(severity, 0) + 1
        entry["event_count"] += 1
        weight = SEVERITY_WEIGHTS.get(severity, 0.0)
        if weight == 0.0:
            continue
        age = (now - aware_utc(timestamp)).total_seconds()
        decay = max(0.0, 1.0 - age / window_seconds)
        raw[device_id] = raw.get(device_id, 0.0) + weight * decay
    for device_id, value in raw.items():
        scores[device_id]["score"] = round(value, 1)
        scores[device_id]["band"] = risk_band(scores[device_id]["score"])
    return scores


def compute_score(db: Session, device_id: str) -> dict:
    return compute_scores(db, [device_id])[device_id]

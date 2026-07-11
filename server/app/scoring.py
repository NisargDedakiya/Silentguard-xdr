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

SEVERITY_WEIGHTS = {"critical": 10.0, "warning": 3.0, "info": 0.0}
WINDOW = datetime.timedelta(hours=24)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def risk_band(score: float) -> str:
    if score >= 20:
        return "critical"
    if score >= 8:
        return "elevated"
    if score > 0:
        return "low"
    return "clear"


def compute_score(db: Session, device_id: str) -> dict:
    now = utcnow()
    cutoff = now - WINDOW
    events = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.device_id == device_id, ThreatEvent.timestamp >= cutoff)
        .all()
    )
    score = 0.0
    counts = {"critical": 0, "warning": 0, "info": 0}
    window_seconds = WINDOW.total_seconds()
    for ev in events:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1
        weight = SEVERITY_WEIGHTS.get(ev.severity, 0.0)
        if weight == 0.0:
            continue
        age = (now - _aware(ev.timestamp)).total_seconds()
        decay = max(0.0, 1.0 - age / window_seconds)
        score += weight * decay
    score = round(score, 1)
    return {
        "device_id": device_id,
        "score": score,
        "band": risk_band(score),
        "window_hours": 24,
        "counts": counts,
        "event_count": len(events),
    }

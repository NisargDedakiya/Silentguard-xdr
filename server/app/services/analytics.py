"""Visibility & analytics aggregations (M17).

Aggregation is done in Python over an org-scoped, time-bounded window so the
queries stay portable across SQLite and Postgres (no dialect-specific date
functions). Heavy DB-side aggregation for very large fleets is deferred to the
scale-out module (M20).
"""
import datetime

from sqlalchemy.orm import Query, Session

from ..models import Detection, Device, IOC, ThreatEvent
from ..services.tenancy import scope_query
from ..utils.time import aware_utc

# Timeline categories → the telemetry sources that populate them.
TIMELINE_CATEGORIES = {
    "usb": ("usb_guard",),
    "network": ("arp_guard", "dns_sinkhole", "port_watchdog"),
    "registry": ("registry_monitor",),   # populated by M12
    "process": ("process", "port_watchdog"),
    "quarantine": ("quarantine", "file_drop"),
}


def _scoped(db: Session, model, org_column, principal) -> Query:
    return scope_query(db.query(model), org_column, principal)


def _day_buckets(days: int):
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return [today - datetime.timedelta(days=i) for i in range(days - 1, -1, -1)]


def summary(db: Session, principal) -> dict:
    devices = _scoped(db, Device, Device.org_id, principal).all()
    online_window = datetime.timedelta(seconds=60)
    now = datetime.datetime.now(datetime.timezone.utc)
    online = sum(1 for d in devices if (now - aware_utc(d.last_seen)) < online_window)
    isolated = sum(1 for d in devices if d.isolated)

    ev_q = _scoped(db, ThreatEvent, ThreatEvent.org_id, principal)
    det_q = _scoped(db, Detection, Detection.org_id, principal)
    det_rows = det_q.all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for d in det_rows:
        by_status[d.status] = by_status.get(d.status, 0) + 1
        by_severity[d.severity] = by_severity.get(d.severity, 0) + 1

    return {
        "devices": len(devices),
        "online": online,
        "isolated": isolated,
        "events": ev_q.count(),
        "detections": len(det_rows),
        "detections_by_status": by_status,
        "detections_by_severity": by_severity,
        "open_critical": sum(1 for d in det_rows
                             if d.severity == "critical" and d.status != "resolved"),
        "iocs": _scoped(db, IOC, IOC.org_id, principal).count(),
    }


def events_by_day(db: Session, principal, days: int = 14) -> list[dict]:
    days = max(1, min(days, 90))
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    rows = (
        _scoped(db, ThreatEvent, ThreatEvent.org_id, principal)
        .filter(ThreatEvent.timestamp >= cutoff)
        .all()
    )
    index = {d: i for i, d in enumerate(_day_buckets(days))}
    buckets = [{"day": d.isoformat(), "critical": 0, "warning": 0, "info": 0}
               for d in _day_buckets(days)]
    for r in rows:
        day = aware_utc(r.timestamp).date()
        if day in index:
            sev = r.severity if r.severity in ("critical", "warning", "info") else "info"
            buckets[index[day]][sev] += 1
    return buckets


def top_devices(db: Session, principal, limit: int = 10) -> list[dict]:
    hostnames = {d.id: d.hostname for d in _scoped(db, Device, Device.org_id, principal).all()}
    counts: dict[str, dict] = {}
    for d in _scoped(db, Detection, Detection.org_id, principal).all():
        entry = counts.setdefault(d.device_id, {"detections": 0, "risk": 0})
        entry["detections"] += 1
        entry["risk"] += d.risk_score
    ranked = sorted(
        ({"device_id": k, "hostname": hostnames.get(k, ""), **v} for k, v in counts.items()),
        key=lambda x: x["risk"], reverse=True,
    )
    return ranked[:max(1, min(limit, 100))]


def mitre_coverage(db: Session, principal) -> list[dict]:
    counts: dict[str, dict] = {}
    for d in _scoped(db, Detection, Detection.org_id, principal).all():
        if not d.technique_id:
            continue
        entry = counts.setdefault(d.technique_id, {"technique_id": d.technique_id,
                                                   "technique_name": d.technique_name, "count": 0})
        entry["count"] += 1
    return sorted(counts.values(), key=lambda x: x["count"], reverse=True)


def timeline(db: Session, principal, category: str, limit: int = 100) -> list[dict]:
    sources = TIMELINE_CATEGORIES.get(category)
    if sources is None:
        raise ValueError(f"unknown timeline category '{category}'")
    rows = (
        _scoped(db, ThreatEvent, ThreatEvent.org_id, principal)
        .filter(ThreatEvent.source.in_(sources))
        .order_by(ThreatEvent.timestamp.desc(), ThreatEvent.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [{"id": r.id, "device_id": r.device_id, "timestamp": r.timestamp,
             "source": r.source, "action": r.action, "severity": r.severity,
             "summary": r.summary, "details": r.details or {}} for r in rows]


def process_tree(db: Session, principal, device_id: str) -> list[dict]:
    """Best-effort process ancestry from events carrying pid/ppid in details.
    Fully populated once the process monitor (M12) emits pid/ppid; returns
    whatever is available now."""
    rows = (
        _scoped(db, ThreatEvent, ThreatEvent.org_id, principal)
        .filter(ThreatEvent.device_id == device_id)
        .order_by(ThreatEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    nodes: dict[int, dict] = {}
    for r in rows:
        d = r.details or {}
        pid = d.get("pid")
        if pid is None:
            continue
        node = nodes.setdefault(int(pid), {"pid": int(pid), "ppid": d.get("ppid"),
                                           "name": d.get("process") or d.get("name") or "",
                                           "children": []})
        if d.get("ppid") is not None and node["ppid"] is None:
            node["ppid"] = d.get("ppid")
    # Link children to parents that are present.
    roots = []
    for pid, node in nodes.items():
        ppid = node.get("ppid")
        if ppid is not None and int(ppid) in nodes and int(ppid) != pid:
            nodes[int(ppid)]["children"].append(node)
        else:
            roots.append(node)
    return roots

"""Threat-intelligence service (M10).

Maintains a local, org-scoped IOC store that doubles as the lookup cache. IOCs
carry a confidence score and optional expiration; expired IOCs are ignored by
lookups and can be pruned. Indicators are extracted from telemetry events and
matched against the store by the detection engine.
"""
import datetime
import json

from sqlalchemy.orm import Session

from ..core.logging import get_logger
from ..models import IOC, utcnow
from ..utils.time import aware_utc

log = get_logger("silentguard.intel")

IOC_TYPES = ("domain", "ip", "url", "sha256", "certificate")

# Map an IOC type to the ATT&CK technique its match most directly evidences.
IOC_TECHNIQUE = {
    "domain": ("T1071.004", "Application Layer Protocol: DNS"),
    "url": ("T1071.001", "Application Layer Protocol: Web"),
    "ip": ("T1071", "Application Layer Protocol"),
    "sha256": ("T1105", "Ingress Tool Transfer"),
    "certificate": ("T1587.002", "Digital Certificates"),
}


def normalize(ioc_type: str, value: str) -> str:
    value = value.strip()
    if ioc_type in ("domain", "url", "sha256", "certificate"):
        return value.lower()
    return value


def upsert_ioc(db: Session, org_id: str | None, ioc_type: str, value: str,
               confidence: int = 50, source: str = "manual", description: str = "",
               expires_at: datetime.datetime | None = None) -> IOC:
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"unknown ioc_type '{ioc_type}'")
    value = normalize(ioc_type, value)
    existing = (
        db.query(IOC)
        .filter(IOC.org_id == org_id, IOC.ioc_type == ioc_type, IOC.value == value)
        .first()
    )
    if existing:
        existing.confidence = confidence
        existing.source = source
        existing.description = description
        existing.expires_at = expires_at
        return existing
    row = IOC(org_id=org_id, ioc_type=ioc_type, value=value, confidence=confidence,
              source=source, description=description, expires_at=expires_at)
    db.add(row)
    return row


def import_iocs(db: Session, org_id: str | None, entries: list[dict], source: str) -> int:
    """Bulk import IOCs from a feed. Each entry: {type, value, [confidence],
    [description], [expires_at ISO]}. Returns the count imported."""
    count = 0
    for e in entries:
        try:
            expires = e.get("expires_at")
            expires_dt = datetime.datetime.fromisoformat(expires) if expires else None
            upsert_ioc(db, org_id, e["type"], e["value"],
                       confidence=int(e.get("confidence", 50)),
                       source=source, description=e.get("description", ""),
                       expires_at=expires_dt)
            count += 1
        except (KeyError, ValueError) as exc:
            log.warning("skipping malformed IOC entry: %s", exc)
    db.commit()
    log.info("imported IOCs", extra={"count": count, "source": source, "org_id": org_id})
    return count


def _active(query, now: datetime.datetime):
    from sqlalchemy import or_

    return query.filter(or_(IOC.expires_at.is_(None), IOC.expires_at > now))


def lookup(db: Session, org_id: str | None, ioc_type: str, value: str) -> IOC | None:
    """Return a matching, non-expired IOC for the org, or None."""
    value = normalize(ioc_type, value)
    now = utcnow()
    q = db.query(IOC).filter(IOC.org_id == org_id, IOC.ioc_type == ioc_type, IOC.value == value)
    row = _active(q, now).first()
    return row


def prune_expired(db: Session) -> int:
    now = utcnow()
    rows = db.query(IOC).filter(IOC.expires_at.isnot(None), IOC.expires_at <= now).all()
    for r in rows:
        db.delete(r)
    db.commit()
    return len(rows)


def extract_indicators(details: dict | None) -> list[tuple[str, str]]:
    """Pull candidate indicators out of a telemetry event's details."""
    d = details or {}
    out: list[tuple[str, str]] = []
    for key, ioc_type in (("domain", "domain"), ("url", "url"), ("sha256", "sha256"),
                          ("hash", "sha256")):
        if d.get(key):
            out.append((ioc_type, str(d[key])))
    for key in ("ip", "remote_ip", "dest_ip", "gateway"):
        if d.get(key):
            out.append(("ip", str(d[key])))
    return out


def load_feed_file(path: str) -> list[dict]:
    """Read a JSON IOC feed file: a list of entries, or {"iocs": [...]}."""
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("iocs", data) if isinstance(data, dict) else data
    except (OSError, ValueError) as exc:
        log.warning("could not load intel feed %s: %s", path, exc)
        return []

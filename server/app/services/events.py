"""Threat-event serialization service.

Single source of truth for turning a ``ThreatEvent`` (or an equivalent mapping)
into (a) the WebSocket broadcast payload and (b) the REST ``EventOut`` schema.
Before M3 this dict was hand-built three times — in ``routers/agents.py``,
``monitor.py`` and ``routers/admin.py`` — with slightly different shapes and a
separately-attached MITRE technique (Audit §14). Centralizing it guarantees the
live stream and the REST timeline always agree.
"""
from typing import Any

from .. import schemas
from ..mitre import technique_for


def _field(row: Any, name: str, default: Any = None) -> Any:
    """Read a field from either an ORM object or a plain mapping."""
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def broadcast_payload(row: Any, hostname: str) -> dict:
    """The `threat_event` message pushed to dashboard WebSocket clients."""
    source = _field(row, "source")
    action = _field(row, "action")
    return {
        "type": "threat_event",
        "id": _field(row, "id"),
        "device_id": _field(row, "device_id"),
        "hostname": hostname,
        "timestamp": _field(row, "timestamp"),
        "source": source,
        "severity": _field(row, "severity"),
        "action": action,
        "summary": _field(row, "summary"),
        "details": _field(row, "details") or {},
        "mitre": technique_for(source, action),
    }


def event_out(row: Any, hostname: str = "") -> schemas.EventOut:
    """The REST `EventOut` representation of a threat event."""
    source = _field(row, "source")
    action = _field(row, "action")
    return schemas.EventOut(
        id=_field(row, "id"),
        device_id=_field(row, "device_id"),
        hostname=hostname,
        timestamp=_field(row, "timestamp"),
        source=source,
        severity=_field(row, "severity"),
        action=action,
        summary=_field(row, "summary"),
        details=_field(row, "details") or {},
        mitre=technique_for(source, action),
    )

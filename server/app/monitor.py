"""Background liveness monitor.

Periodically scans enrolled devices. If a device has not been seen for longer
than the unresponsive threshold, and it did not report a clean stop, a
critical "device_unresponsive" event is emitted to the timeline exactly once
(until the agent checks in again). This surfaces an agent that was killed and
did not restart — a possible tamper attempt.
"""
import asyncio
import datetime
import logging

from . import alerting
from .core.config import settings
from .database import SessionLocal
from .mitre import technique_for
from .models import Device, ThreatEvent, utcnow
from .ws import hub

log = logging.getLogger("silentguard.monitor")

UNRESPONSIVE_SECONDS = settings.unresponsive_seconds
SCAN_INTERVAL_SECONDS = settings.monitor_interval_seconds


def _aware(dt: datetime.datetime) -> datetime.datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


async def check_once() -> list[str]:
    """Run one liveness sweep. Returns hostnames newly flagged (for tests)."""
    flagged: list[dict] = []
    db = SessionLocal()
    try:
        threshold = datetime.timedelta(seconds=UNRESPONSIVE_SECONDS)
        now = utcnow()
        for device in db.query(Device).all():
            silent_for = now - _aware(device.last_seen)
            if silent_for <= threshold or device.stopped or device.unresponsive_alerted:
                continue
            device.unresponsive_alerted = True
            event = ThreatEvent(
                device_id=device.id,
                source="agent",
                severity="critical",
                action="device_unresponsive",
                summary=f"Device {device.hostname} unresponsive for "
                        f"{int(silent_for.total_seconds())}s — agent may have been "
                        f"killed without restarting",
                details={"last_seen": device.last_seen.isoformat(),
                         "threshold_seconds": UNRESPONSIVE_SECONDS},
            )
            db.add(event)
            db.flush()
            flagged.append(
                {
                    "id": event.id,
                    "device_id": device.id,
                    "hostname": device.hostname,
                    "timestamp": event.timestamp,
                    "source": event.source,
                    "severity": event.severity,
                    "action": event.action,
                    "summary": event.summary,
                    "details": event.details,
                    "mitre": technique_for(event.source, event.action),
                }
            )
        db.commit()
    finally:
        db.close()

    for payload in flagged:
        await hub.broadcast({"type": "threat_event", **payload})
        await alerting.notify_critical(payload)
    return [f["hostname"] for f in flagged]


async def run_monitor_loop() -> None:
    log.info("Liveness monitor started (threshold=%ss, interval=%ss)",
             UNRESPONSIVE_SECONDS, SCAN_INTERVAL_SECONDS)
    while True:
        try:
            await check_once()
        except Exception:  # noqa: BLE001 — never let the loop die
            log.exception("Liveness sweep failed")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)

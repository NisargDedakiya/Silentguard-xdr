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
from .models import Device, ThreatEvent, utcnow
from .services import events
from .utils.time import aware_utc
from .ws import hub

log = logging.getLogger("silentguard.monitor")

UNRESPONSIVE_SECONDS = settings.unresponsive_seconds
SCAN_INTERVAL_SECONDS = settings.monitor_interval_seconds


async def check_once() -> list[str]:
    """Run one liveness sweep. Returns hostnames newly flagged (for tests)."""
    flagged: list[dict] = []
    db = SessionLocal()
    try:
        threshold = datetime.timedelta(seconds=UNRESPONSIVE_SECONDS)
        now = utcnow()
        for device in db.query(Device).all():
            silent_for = now - aware_utc(device.last_seen)
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
            # Serialize while the event is still attached to the session.
            flagged.append(events.broadcast_payload(event, device.hostname))
        db.commit()
    finally:
        db.close()

    for payload in flagged:
        await hub.broadcast(payload)
        await alerting.notify_critical(payload)
    return [p["hostname"] for p in flagged]


async def run_monitor_loop() -> None:
    log.info("Liveness monitor started (threshold=%ss, interval=%ss)",
             UNRESPONSIVE_SECONDS, SCAN_INTERVAL_SECONDS)
    while True:
        try:
            await check_once()
        except Exception:  # noqa: BLE001 — never let the loop die
            log.exception("Liveness sweep failed")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)

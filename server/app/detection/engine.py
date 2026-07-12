"""Detection engine (M8): evaluate telemetry against rules, persist detections,
and dispatch configured responses.

Kept side-effect-safe: response dispatch is best-effort and never raises into
the telemetry-ingestion path.
"""
from sqlalchemy.orm import Session

from .. import alerting
from ..core.config import settings
from ..core.logging import get_logger
from ..models import Detection, Device, ThreatEvent
from ..services import threat_intel
from .rules import RULES_BY_ID, SEED_RULES, EventContext, Rule

log = get_logger("silentguard.detection")


def evaluate_event(db: Session, device: Device, event: ThreatEvent) -> list[Detection]:
    """Run every rule against a stored ThreatEvent. Persist and return the
    Detection rows produced (committed by the caller's transaction)."""
    ctx = EventContext(event.source, event.action, event.severity, event.summary, event.details)
    detections: list[Detection] = []
    for rule in SEED_RULES:
        try:
            fired = rule.matches(ctx)
        except Exception:  # noqa: BLE001 — a broken rule must not drop telemetry
            log.exception("detection rule error", extra={"rule_id": rule.id})
            continue
        if not fired:
            continue
        det = Detection(
            org_id=event.org_id,
            device_id=device.id,
            event_id=event.id,
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity.value,
            risk_score=rule.risk_score,
            technique_id=rule.technique_id,
            technique_name=rule.technique_name,
            status="new",
            details={"summary": event.summary, "responses": list(rule.responses)},
        )
        db.add(det)
        detections.append(det)

    detections.extend(_evaluate_iocs(db, device, event))
    return detections


def _evaluate_iocs(db: Session, device: Device, event: ThreatEvent) -> list[Detection]:
    """Match indicators in the event against the org's threat-intel store."""
    detections: list[Detection] = []
    for ioc_type, value in threat_intel.extract_indicators(event.details):
        try:
            hit = threat_intel.lookup(db, event.org_id, ioc_type, value)
        except Exception:  # noqa: BLE001
            log.exception("ioc lookup error", extra={"ioc_type": ioc_type})
            continue
        if hit is None:
            continue
        technique_id, technique_name = threat_intel.IOC_TECHNIQUE.get(
            ioc_type, ("T1071", "Application Layer Protocol"))
        severity = "critical" if hit.confidence >= 80 else "high" if hit.confidence >= 50 else "medium"
        det = Detection(
            org_id=event.org_id, device_id=device.id, event_id=event.id,
            rule_id="ioc_match", name=f"Known-bad {ioc_type} indicator",
            severity=severity, risk_score=min(100, hit.confidence),
            technique_id=technique_id, technique_name=technique_name, status="new",
            details={"ioc_type": ioc_type, "value": hit.value, "source": hit.source,
                     "confidence": hit.confidence, "responses": ["alert"]},
        )
        db.add(det)
        detections.append(det)
    return detections


def detection_payload(det: Detection, hostname: str) -> dict:
    """WebSocket payload for a new detection."""
    return {
        "type": "detection",
        "id": det.id,
        "org_id": det.org_id,
        "device_id": det.device_id,
        "hostname": hostname,
        "rule_id": det.rule_id,
        "name": det.name,
        "severity": det.severity,
        "risk_score": det.risk_score,
        "technique": {"id": det.technique_id, "name": det.technique_name},
        "status": det.status,
    }


async def dispatch_responses(db: Session, det: Detection, device: Device) -> None:
    """Apply a detection's configured response actions. Best-effort: alerting is
    non-blocking; the state-changing `isolate` action is gated behind
    ``settings.detection_auto_isolate`` and only for critical detections."""
    rule: Rule | None = RULES_BY_ID.get(det.rule_id)
    responses = tuple(rule.responses) if rule else ("alert",)

    if "alert" in responses and det.severity == "critical":
        await alerting.notify_critical({
            "severity": "critical",
            "summary": f"[detection] {det.name} on {device.hostname}",
            "hostname": device.hostname,
            "source": "detection",
            "action": det.rule_id,
            "mitre": {"id": det.technique_id, "name": det.technique_name},
        })

    if "isolate" in responses and settings.detection_auto_isolate and det.severity == "critical":
        if not device.isolated:
            device.isolated = True
            cmds = list(device.pending_commands or [])
            cmds.append({"command": "isolate"})
            device.pending_commands = cmds
            db.commit()
            log.warning("auto-isolated device from detection",
                        extra={"device_id": device.id, "rule_id": det.rule_id})

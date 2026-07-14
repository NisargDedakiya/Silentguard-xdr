"""Compliance & executive reporting (v1.4).

Produces a single, org-scoped posture report a SOC manager or auditor can hand to
leadership: fleet health, detection backlog, threat-intel coverage, and a set of
pass/warn/fail **control checks** derived from the platform's live configuration
and data. The controls give a headline compliance score without any external
GRC tooling.

Aggregation is done in Python over an org-scoped window so it stays portable
across SQLite and Postgres (consistent with `analytics.py`); heavy DB-side
aggregation for very large fleets is deferred to the scale-out module (M20).
"""
import datetime

from sqlalchemy.orm import Session

from ..core.config import settings
from ..models import IOC, Detection, Device, IntelRule
from ..utils.time import aware_utc
from .tenancy import scope_query

PASS, WARN, FAIL = "pass", "warn", "fail"


def _control(cid: str, title: str, status: str, detail: str) -> dict:
    return {"id": cid, "title": title, "status": status, "detail": detail}


def _fleet_posture(db: Session, principal) -> tuple[dict, int]:
    devices = scope_query(db.query(Device), Device.org_id, principal).all()
    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = datetime.timedelta(seconds=max(settings.unresponsive_seconds, 60))
    online = sum(1 for d in devices if (now - aware_utc(d.last_seen)) < threshold)
    isolated = sum(1 for d in devices if d.isolated)
    versions: dict[str, int] = {}
    for d in devices:
        versions[d.agent_version] = versions.get(d.agent_version, 0) + 1
    total = len(devices)
    offline = total - online
    fleet = {
        "total_devices": total,
        "online": online,
        "offline": offline,
        "isolated": isolated,
        "reporting_pct": round(100 * online / total) if total else 100,
        "agent_versions": versions,
    }
    return fleet, offline


def _detection_stats(db: Session, principal, days: int) -> tuple[dict, int]:
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    rows = (
        scope_query(db.query(Detection), Detection.org_id, principal)
        .filter(Detection.created_at >= since)
        .all()
    )
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    open_critical = 0
    for d in rows:
        by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
        by_status[d.status] = by_status.get(d.status, 0) + 1
        if d.severity == "critical" and d.status in ("new", "acknowledged"):
            open_critical += 1
    resolved = by_status.get("resolved", 0)
    stats = {
        "window_total": len(rows),
        "by_severity": by_severity,
        "by_status": by_status,
        "open_critical": open_critical,
        "resolved_rate_pct": round(100 * resolved / len(rows)) if rows else 100,
    }
    return stats, open_critical


def _intel_coverage(db: Session, principal) -> dict:
    ioc_count = scope_query(db.query(IOC), IOC.org_id, principal).count()
    rules = scope_query(db.query(IntelRule), IntelRule.org_id, principal).all()
    return {
        "iocs": ioc_count,
        "sigma_rules": sum(1 for r in rules if r.kind == "sigma" and r.enabled),
        "yara_rules": sum(1 for r in rules if r.kind == "yara" and r.enabled),
    }


def _controls(offline: int, open_critical: int, intel: dict) -> list[dict]:
    controls = [
        _control(
            "strong_authentication", "Strong authentication secret configured",
            PASS if settings.jwt_secret else WARN,
            "Dedicated SG_JWT_SECRET is set." if settings.jwt_secret
            else "JWT secret is derived from the admin token; set SG_JWT_SECRET to an "
                 "independent high-entropy value.",
        ),
        _control(
            "transport_security", "HTTP transport hardening (HSTS)",
            PASS if settings.hsts_enabled else WARN,
            "HSTS enabled." if settings.hsts_enabled
            else "Enable SG_HSTS_ENABLED when served over TLS.",
        ),
        _control(
            "token_exposure", "Auth tokens not exposed in API responses",
            FAIL if (settings.is_production and settings.should_expose_tokens) else PASS,
            "Reset/verify tokens are exposed in responses in production."
            if (settings.is_production and settings.should_expose_tokens)
            else "Tokens are not exposed in production responses.",
        ),
        _control(
            "request_size_guard", "Request body-size guard enabled",
            PASS if settings.max_request_bytes > 0 else WARN,
            f"Bodies larger than {settings.max_request_bytes} bytes are rejected."
            if settings.max_request_bytes > 0 else "Body-size guard is disabled.",
        ),
        _control(
            "sigma_detection", "Custom Sigma detections enabled",
            PASS if settings.sigma_enabled else WARN,
            "Sigma evaluation is on." if settings.sigma_enabled
            else "Sigma evaluation is disabled (SG_SIGMA_ENABLED).",
        ),
        _control(
            "fleet_reporting", "All endpoints reporting",
            PASS if offline == 0 else WARN,
            "Every enrolled device is online." if offline == 0
            else f"{offline} device(s) have not checked in recently.",
        ),
        _control(
            "critical_backlog", "No unresolved critical detections",
            PASS if open_critical == 0 else FAIL,
            "No open critical detections." if open_critical == 0
            else f"{open_critical} critical detection(s) are unresolved.",
        ),
        _control(
            "detection_content", "Threat-intel content present",
            PASS if (intel["iocs"] or intel["sigma_rules"] or intel["yara_rules"]) else WARN,
            "IOCs / Sigma / YARA content is loaded."
            if (intel["iocs"] or intel["sigma_rules"] or intel["yara_rules"])
            else "No IOCs or custom rules loaded; detection relies on built-ins only.",
        ),
    ]
    return controls


def build_compliance_report(db: Session, principal, days: int = 30) -> dict:
    days = max(1, min(days, 365))
    fleet, offline = _fleet_posture(db, principal)
    detections, open_critical = _detection_stats(db, principal, days)
    intel = _intel_coverage(db, principal)
    controls = _controls(offline, open_critical, intel)

    counts = {PASS: 0, WARN: 0, FAIL: 0}
    for c in controls:
        counts[c["status"]] += 1
    # Score: pass = full credit, warn = half, fail = none.
    score = round(100 * (counts[PASS] + 0.5 * counts[WARN]) / len(controls)) if controls else 100

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "window_days": days,
        "org_id": None if principal.cross_org else principal.org_id,
        "score": score,
        "controls_summary": counts,
        "fleet": fleet,
        "detections": detections,
        "intel": intel,
        "controls": controls,
    }

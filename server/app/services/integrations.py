"""Outbound integrations (M18): forward events/detections to SIEM/SOAR/chat/
syslog destinations, and format exports.

Delivery is best-effort and must never stall ingestion: each send is wrapped and
failures are logged and swallowed. Network I/O uses the standard library
(urllib/socket) so it is easily patched in tests.
"""
import json
import socket
import urllib.request

from sqlalchemy.orm import Session

from ..core.logging import get_logger
from ..models import Integration

log = get_logger("silentguard.integrations")

TIMEOUT = 5
_SEVERITY_RANK = {"info": 0, "warning": 1, "medium": 1, "high": 2, "critical": 3}


def _rank(sev: str) -> int:
    return _SEVERITY_RANK.get((sev or "").lower(), 0)


# -- formatters -----------------------------------------------------------
def format_generic(payload: dict) -> bytes:
    return json.dumps(payload, default=str).encode()


def format_chat(payload: dict) -> bytes:
    text = f"🛡️ SilentGuard: {payload.get('summary') or payload.get('name', 'event')}"
    meta = " · ".join(str(v) for v in (payload.get("hostname"), payload.get("source"),
                                       payload.get("severity")) if v)
    if meta:
        text += f"\n{meta}"
    # "text" for Slack, "content" for Discord/Teams-compatible webhooks.
    return json.dumps({"text": text, "content": text}).encode()


def format_splunk_hec(payload: dict) -> bytes:
    return json.dumps({"event": payload, "sourcetype": "silentguard:xdr"}, default=str).encode()


def _cef_escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")


def format_cef(payload: dict) -> str:
    """ArcSight CEF line (also accepted by many syslog SIEMs)."""
    sev = min(10, _rank(payload.get("severity", "info")) * 3 + 1)
    name = payload.get("name") or payload.get("summary") or payload.get("action") or "event"
    fields = (("dvchost", payload.get("hostname")),
              ("cs1", payload.get("source")),
              ("act", payload.get("action")),
              ("cs2", (payload.get("technique") or {}).get("id")))
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in fields if v)
    header = f"CEF:0|SilentGuard|XDR|1.0|{payload.get('source', 'event')}|{name}|{sev}|"
    return header + ext


# -- delivery -------------------------------------------------------------
def _send_webhook(url: str, body: bytes, headers: dict | None = None) -> None:
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    urllib.request.urlopen(req, timeout=TIMEOUT)  # noqa: S310 — admin-configured URL


def _send_syslog(host: str, port: int, line: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(f"<134>{line}".encode(), (host, int(port)))
    finally:
        sock.close()


def deliver(integration: Integration, payload: dict) -> None:
    """Deliver a single payload to one integration. Best-effort."""
    cfg = integration.config or {}
    kind = integration.kind
    try:
        if kind in ("webhook",):
            _send_webhook(cfg["url"], format_generic(payload), cfg.get("headers"))
        elif kind in ("slack", "discord", "teams"):
            _send_webhook(cfg["url"], format_chat(payload))
        elif kind == "splunk_hec":
            _send_webhook(cfg["url"], format_splunk_hec(payload),
                          {"Authorization": f"Splunk {cfg.get('token', '')}"})
        elif kind == "syslog":
            _send_syslog(cfg.get("host", "127.0.0.1"), cfg.get("port", 514), format_cef(payload))
        else:
            log.warning("unknown integration kind", extra={"kind": kind})
    except Exception as exc:  # noqa: BLE001 — never propagate into ingestion
        log.warning("integration delivery failed", extra={"kind": kind, "error": str(exc)})


def dispatch(db: Session, org_id: str | None, payload: dict) -> int:
    """Forward a payload to every enabled org integration meeting the severity
    threshold. Returns the number of integrations attempted."""
    severity = payload.get("severity", "info")
    integrations = (
        db.query(Integration)
        .filter(Integration.org_id == org_id, Integration.enabled.is_(True))
        .all()
    )
    attempted = 0
    for integ in integrations:
        if _rank(severity) < _rank(integ.min_severity):
            continue
        deliver(integ, payload)
        attempted += 1
    return attempted

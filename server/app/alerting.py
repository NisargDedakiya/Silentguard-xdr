"""Best-effort alerting for critical-severity events.

Configured entirely via environment variables:
    SG_ALERT_WEBHOOK_URL   Slack or Discord incoming-webhook URL
    SG_SMTP_HOST / SG_SMTP_PORT (default 587) / SG_SMTP_USER / SG_SMTP_PASSWORD
    SG_SMTP_FROM / SG_ALERT_EMAIL_TO   (both required for email)
    SG_SMTP_STARTTLS=0     disable STARTTLS (on by default)

Delivery is fire-and-forget on a worker thread: a broken webhook or SMTP
server can never stall telemetry ingestion. Failures are logged and
swallowed. Uses only the standard library (urllib/smtplib).
"""
import asyncio
import json
import logging
import os
import smtplib
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("silentguard.alerting")

TIMEOUT_SECONDS = 5


def _settings() -> dict:
    """Read alerting config from the environment on every call so tests and
    runtime reconfiguration don't need a restart."""
    return {
        "webhook_url": os.environ.get("SG_ALERT_WEBHOOK_URL", ""),
        "smtp_host": os.environ.get("SG_SMTP_HOST", ""),
        "smtp_port": int(os.environ.get("SG_SMTP_PORT", "587")),
        "smtp_user": os.environ.get("SG_SMTP_USER", ""),
        "smtp_password": os.environ.get("SG_SMTP_PASSWORD", ""),
        "smtp_from": os.environ.get("SG_SMTP_FROM", ""),
        "email_to": os.environ.get("SG_ALERT_EMAIL_TO", ""),
        "smtp_starttls": os.environ.get("SG_SMTP_STARTTLS", "1") != "0",
    }


def format_message(event: dict) -> str:
    parts = [f"🚨 SilentGuard critical event: {event.get('summary', '')}"]
    meta = " · ".join(
        str(v) for v in (event.get("hostname"), event.get("source"), event.get("action")) if v
    )
    if meta:
        parts.append(meta)
    mitre = event.get("mitre")
    if mitre:
        parts.append(f"ATT&CK {mitre.get('id')} — {mitre.get('name')}")
    return "\n".join(parts)


def _send_webhook(url: str, message: str) -> None:
    # "text" is read by Slack, "content" by Discord; each ignores the other.
    body = json.dumps({"text": message, "content": message}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS)  # noqa: S310 — admin-configured URL


def _send_email(settings: dict, message: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = "SilentGuard XDR critical alert"
    msg["From"] = settings["smtp_from"]
    msg["To"] = settings["email_to"]
    msg.set_content(message)
    with smtplib.SMTP(settings["smtp_host"], settings["smtp_port"],
                      timeout=TIMEOUT_SECONDS) as smtp:
        if settings["smtp_starttls"]:
            smtp.starttls()
        if settings["smtp_user"]:
            smtp.login(settings["smtp_user"], settings["smtp_password"])
        smtp.send_message(msg)


def _dispatch(settings: dict, message: str) -> None:
    """Runs on a worker thread; every failure is logged and swallowed."""
    if settings["webhook_url"]:
        try:
            _send_webhook(settings["webhook_url"], message)
        except Exception as exc:  # noqa: BLE001 — alerting must never propagate
            log.warning("Alert webhook delivery failed: %s", exc)
    if settings["smtp_host"] and settings["smtp_from"] and settings["email_to"]:
        try:
            _send_email(settings, message)
        except Exception as exc:  # noqa: BLE001
            log.warning("Alert email delivery failed: %s", exc)


async def notify_critical(event: dict) -> asyncio.Task | None:
    """Schedule alert delivery for a critical event and return immediately.
    Returns the background task (or None if not critical / not configured)."""
    if event.get("severity") != "critical":
        return None
    settings = _settings()
    if not settings["webhook_url"] and not settings["smtp_host"]:
        return None
    return asyncio.create_task(asyncio.to_thread(_dispatch, settings, format_message(event)))

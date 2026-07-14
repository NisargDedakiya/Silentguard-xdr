"""Minimal best-effort email sender (M7), reusing the SMTP env config.

Sends via smtplib on a worker thread; failures are logged and swallowed so an
unavailable mailbox never breaks the auth flow. When SMTP is not configured the
message is logged instead (useful in dev).
"""
import asyncio
import os
import smtplib
from email.message import EmailMessage

from ..core.logging import get_logger

log = get_logger("silentguard.email")
TIMEOUT = 5


def _smtp_settings() -> dict:
    return {
        "host": os.environ.get("SG_SMTP_HOST", ""),
        "port": int(os.environ.get("SG_SMTP_PORT", "587")),
        "user": os.environ.get("SG_SMTP_USER", ""),
        "password": os.environ.get("SG_SMTP_PASSWORD", ""),
        "sender": os.environ.get("SG_SMTP_FROM", "no-reply@silentguard.local"),
        "starttls": os.environ.get("SG_SMTP_STARTTLS", "1") != "0",
    }


def _send_sync(to: str, subject: str, body: str) -> None:
    cfg = _smtp_settings()
    if not cfg["host"]:
        log.info("email (no SMTP configured)", extra={"to": to, "subject": subject})
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    msg["To"] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=TIMEOUT) as smtp:
            if cfg["starttls"]:
                smtp.starttls()
            if cfg["user"]:
                smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)
    except Exception as exc:  # noqa: BLE001 — email must never break the flow
        log.warning("email send failed", extra={"to": to, "error": str(exc)})


def send_email(to: str, subject: str, body: str) -> None:
    """Fire-and-forget email. Uses the running loop if present, else runs sync."""
    try:
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, _send_sync, to, subject, body)
    except RuntimeError:
        _send_sync(to, subject, body)

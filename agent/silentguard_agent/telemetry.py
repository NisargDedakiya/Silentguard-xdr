"""Telemetry client: enrollment, buffered event delivery, check-in.

Events are queued locally and flushed in batches; if the server is
unreachable, events stay buffered (bounded) so nothing is lost during
connectivity gaps. The buffer is also **spooled to disk** (v1.2) so it survives
an agent restart while offline — an endpoint that reboots mid-outage still
delivers everything it captured once connectivity returns.
"""
import datetime
import logging
import threading
from collections import deque

import requests

from . import __version__, tamper
from .cert_pinning import build_session
from .config import (AgentConfig, effective_tamper_key, load_queue, load_state,
                     save_queue, save_state)

log = logging.getLogger("silentguard.telemetry")

MAX_BUFFER = 5000


class TelemetryClient:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.buffer: deque = deque(maxlen=MAX_BUFFER)
        self.lock = threading.Lock()
        self.device_id: str | None = None
        self.api_key: str | None = None
        # HTTP session with optional TLS certificate pinning (v1.4).
        self.session = build_session(config)
        # Recover any events spooled before a previous shutdown/crash.
        spooled = load_queue()
        if spooled:
            self.buffer.extend(spooled[-MAX_BUFFER:])
            log.info("Recovered %d spooled telemetry events", len(self.buffer))

    def _persist_locked(self) -> None:
        """Persist the current buffer to the offline spool. Caller holds lock."""
        save_queue(list(self.buffer))

    # -- enrollment -------------------------------------------------------
    def ensure_enrolled(self) -> None:
        state = load_state()
        if tamper.has_credentials(state):
            if tamper.is_authentic(state, effective_tamper_key()):
                self.device_id, self.api_key = state["device_id"], state["api_key"]
                return
            # The state file was modified out from under us: refuse the stored
            # credentials and re-enrol, reporting the tamper attempt.
            log.warning("State file failed integrity check; discarding credentials")
            self.emit("agent", "tamper",
                      "Agent state file integrity check failed; re-enrolling",
                      severity="critical",
                      details={"device_id": state.get("device_id", "")})
        resp = self.session.post(
            f"{self.config.server_url}/api/agent/enroll",
            json={
                "enroll_token": self.config.enroll_token,
                "hostname": self.config.hostname,
                "platform": self.config.platform,
                "agent_version": __version__,
            },
            timeout=10,
            verify=self.config.verify_tls,
        )
        resp.raise_for_status()
        data = resp.json()
        self.device_id, self.api_key = data["device_id"], data["api_key"]
        save_state({"device_id": self.device_id, "api_key": self.api_key})
        log.info("Enrolled as device %s", self.device_id)

    # -- events -----------------------------------------------------------
    def emit(self, source: str, action: str, summary: str,
             severity: str = "info", details: dict | None = None) -> None:
        event = {
            "source": source,
            "action": action,
            "summary": summary,
            "severity": severity,
            "details": details or {},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        with self.lock:
            self.buffer.append(event)
            self._persist_locked()
        log.info("[%s/%s] %s", source, severity, summary)

    def flush(self) -> None:
        with self.lock:
            if not self.buffer:
                return
            batch = list(self.buffer)
        try:
            resp = self.session.post(
                f"{self.config.server_url}/api/agent/telemetry",
                json={"events": batch},
                headers={"X-Agent-Key": self.api_key or ""},
                timeout=10,
                verify=self.config.verify_tls,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Telemetry flush failed, keeping %d buffered events: %s", len(batch), exc)
            return
        with self.lock:
            for _ in range(min(len(batch), len(self.buffer))):
                self.buffer.popleft()
            # Shrink the on-disk spool to match the delivered state.
            self._persist_locked()

    # -- inventory --------------------------------------------------------
    def send_inventory(self, report: dict) -> bool:
        """Post a device inventory snapshot. Best-effort; returns success."""
        try:
            resp = self.session.post(
                f"{self.config.server_url}/api/agent/inventory",
                json=report,
                headers={"X-Agent-Key": self.api_key or ""},
                timeout=10,
                verify=self.config.verify_tls,
            )
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.warning("Inventory report failed: %s", exc)
            return False

    # -- check-in ---------------------------------------------------------
    def checkin(self) -> dict | None:
        try:
            resp = self.session.get(
                f"{self.config.server_url}/api/agent/checkin",
                headers={"X-Agent-Key": self.api_key or ""},
                timeout=10,
                verify=self.config.verify_tls,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            log.warning("Check-in failed: %s", exc)
            return None

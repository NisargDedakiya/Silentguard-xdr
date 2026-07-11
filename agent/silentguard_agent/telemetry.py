"""Telemetry client: enrollment, buffered event delivery, check-in.

Events are queued locally and flushed in batches; if the server is
unreachable, events stay buffered (bounded) so nothing is lost during
connectivity gaps.
"""
import datetime
import logging
import threading
from collections import deque

import requests

from . import __version__
from .config import AgentConfig, load_state, save_state

log = logging.getLogger("silentguard.telemetry")

MAX_BUFFER = 5000


class TelemetryClient:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.buffer: deque = deque(maxlen=MAX_BUFFER)
        self.lock = threading.Lock()
        self.device_id: str | None = None
        self.api_key: str | None = None

    # -- enrollment -------------------------------------------------------
    def ensure_enrolled(self) -> None:
        state = load_state()
        if state.get("device_id") and state.get("api_key"):
            self.device_id, self.api_key = state["device_id"], state["api_key"]
            return
        resp = requests.post(
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
        log.info("[%s/%s] %s", source, severity, summary)

    def flush(self) -> None:
        with self.lock:
            if not self.buffer:
                return
            batch = list(self.buffer)
        try:
            resp = requests.post(
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

    # -- check-in ---------------------------------------------------------
    def checkin(self) -> dict | None:
        try:
            resp = requests.get(
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

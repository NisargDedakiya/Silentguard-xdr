"""Suricata IDS integration (v1.5).

Tails a Suricata ``eve.json`` log and forwards each network **alert** as
telemetry, so IDS detections show up alongside endpoint detections in the XDR —
the network and endpoint pictures land in one timeline. The server turns a
``source="suricata"`` alert into a detection via the ``suricata_alert`` rule.

Follows the file incrementally (like ``tail -f``): the first scan seeds the read
offset at the end of the file so historical alerts aren't replayed on start, and
a shrunk file (log rotation/truncation) resets the offset to the top. Bounded
per scan so an alert storm can't flood telemetry.

Inert unless ``SG_SURICATA_ENABLED`` is set; the eve.json path is
``SG_SURICATA_EVE`` (default ``/var/log/suricata/eve.json``).
"""
import json
import logging
import os

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.suricata")


class SuricataMonitor:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient,
                 max_events_per_scan: int = 100):
        self.config = config
        self.telemetry = telemetry
        self.max_events = max_events_per_scan
        self._offset = 0
        self._baselined = False
        self.enabled = bool(getattr(config, "suricata_enabled", False))

    def _path(self) -> str:
        return getattr(self.config, "suricata_eve_path", "") or ""

    def _parse_alert(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        try:
            ev = json.loads(line)
        except ValueError:
            return None
        if not isinstance(ev, dict) or ev.get("event_type") != "alert":
            return None
        return ev

    def _emit(self, ev: dict) -> None:
        alert = ev.get("alert", {}) or {}
        details = {
            "signature": alert.get("signature", ""),
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category", ""),
            "suricata_severity": alert.get("severity"),
            "src_ip": ev.get("src_ip", ""),
            "dest_ip": ev.get("dest_ip", ""),
            "dest_port": ev.get("dest_port"),
            "proto": ev.get("proto", ""),
        }
        flow = f" ({details['src_ip']} -> {details['dest_ip']})" if details["src_ip"] else ""
        self.telemetry.emit(
            source="suricata",
            action="alert",
            severity="warning",
            summary=f"Suricata alert: {details['signature'] or 'unknown'}{flow}",
            details=details,
        )

    def scan(self) -> None:
        if not self.enabled:
            return
        path = self._path()
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if not self._baselined:
            # Start reading from the current end so we don't replay old alerts.
            self._offset = size
            self._baselined = True
            return
        if size < self._offset:
            # File rotated or truncated — restart from the top.
            self._offset = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()
        except OSError as exc:
            log.debug("Suricata read failed: %s", exc)
            return
        emitted = 0
        for line in lines:
            if emitted >= self.max_events:
                break
            alert = self._parse_alert(line)
            if alert:
                self._emit(alert)
                emitted += 1

"""Process execution monitor (M12a).

Enumerates running processes and emits telemetry for **newly seen** ones,
including the full command line, pid/ppid, executable, and user. This is the
data source that activates the server-side behavioral detection rules
(PowerShell abuse, LOLBins, credential dumping, injection, persistence, …) and
powers the process-tree view.

Cross-platform: psutil provides cmdline/ppid/username on Windows, Linux, and
macOS, so the same monitor serves every OS (Stage 5). The first scan records a
baseline silently so a restart never floods the timeline with pre-existing
processes.
"""
import logging

import psutil

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.process_monitor")


class ProcessMonitor:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient,
                 max_events_per_scan: int = 50):
        self.config = config
        self.telemetry = telemetry
        self.max_events = max_events_per_scan
        self._seen: set[int] = set()
        self._baselined = False

    def _snapshot(self) -> dict[int, dict]:
        procs: dict[int, dict] = {}
        for proc in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "exe"]):
            try:
                info = proc.info
                cmdline = info.get("cmdline") or []
                procs[info["pid"]] = {
                    "pid": info["pid"],
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "",
                    "user": info.get("username") or "",
                    "command_line": " ".join(cmdline) if cmdline else (info.get("name") or ""),
                    "exe": info.get("exe") or "",
                }
            except (psutil.Error, KeyError):
                continue
        return procs

    def scan(self) -> None:
        snapshot = self._snapshot()
        if not self._baselined:
            self._seen = set(snapshot)
            self._baselined = True
            return
        new_pids = [pid for pid in snapshot if pid not in self._seen]
        # Bound the burst so a fork storm can't flood telemetry.
        for pid in new_pids[: self.max_events]:
            details = snapshot[pid]
            self.telemetry.emit(
                source="process",
                action="exec",
                severity="info",
                summary=f"Process started: {details['name']} (pid {pid})",
                details=details,
            )
        self._seen = set(snapshot)

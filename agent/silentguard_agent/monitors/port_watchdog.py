"""Pillar 1 — Automated Host Defense ("The Bouncer").

Polls listening TCP/UDP sockets. If an unallowlisted process opens a
suspicious listening port (e.g. a reverse-shell listener on 4444) or a
known-bad process name appears, the process is terminated automatically.
"""
import logging

import psutil

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.port_watchdog")


class PortWatchdog:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self._known_listeners: set[tuple[int, int]] = set()  # (pid, port)

    def _kill(self, proc: psutil.Process, reason: str) -> bool:
        if self.config.dry_run:
            log.info("[dry-run] would kill pid=%s (%s)", proc.pid, reason)
            return True
        try:
            proc.kill()
            proc.wait(timeout=3)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            log.warning("Failed to kill pid=%s: %s", proc.pid, exc)
            return False

    def scan(self) -> None:
        # 1. Known-bad process names anywhere on the host
        for proc in psutil.process_iter(["pid", "name"]):
            name = (proc.info.get("name") or "").lower()
            if name in {p.lower() for p in self.config.blocked_processes}:
                killed = self._kill(proc, f"blocked process name {name}")
                self.telemetry.emit(
                    source="port_watchdog",
                    action="killed" if killed else "kill_failed",
                    severity="critical",
                    summary=f"Blocked process '{name}' (pid {proc.info['pid']}) "
                            f"{'terminated' if killed else 'could not be terminated'}",
                    details={"pid": proc.info["pid"], "process": name},
                )

        # 2. New listening sockets on suspicious ports from unallowlisted processes
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return
        current: set[tuple[int, int]] = set()
        for c in conns:
            if c.status != psutil.CONN_LISTEN or not c.laddr or c.pid is None:
                continue
            port = c.laddr.port
            current.add((c.pid, port))
            if (c.pid, port) in self._known_listeners:
                continue
            try:
                proc = psutil.Process(c.pid)
                name = proc.name()
            except psutil.Error:
                continue
            if port in self.config.suspicious_ports:
                # Suspicious ports override the allowlist: a reverse shell on
                # 4444 is malicious no matter which interpreter hosts it.
                killed = self._kill(proc, f"suspicious listener on port {port}")
                self.telemetry.emit(
                    source="port_watchdog",
                    action="killed" if killed else "kill_failed",
                    severity="critical",
                    summary=f"Unauthorized listener '{name}' on port {port} "
                            f"{'terminated' if killed else 'detected but not terminated'}",
                    details={"pid": c.pid, "process": name, "port": port},
                )
            elif name not in self.config.allowlisted_processes:
                self.telemetry.emit(
                    source="port_watchdog",
                    action="detected",
                    severity="warning",
                    summary=f"New listening port {port} opened by '{name}'",
                    details={"pid": c.pid, "process": name, "port": port},
                )
        self._known_listeners = current

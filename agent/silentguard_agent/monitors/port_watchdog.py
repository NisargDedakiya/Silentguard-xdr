"""Pillar 1 — Automated Host Defense ("The Bouncer").

Polls listening TCP/UDP sockets. If an unallowlisted process opens a
suspicious listening port (e.g. a reverse-shell listener on 4444) or a
known-bad process name appears, the process is terminated automatically.
When a quarantine manager is attached, the killed process's executable is
hashed (SHA-256), checked against the local reputation table, and moved to
quarantine — never deleted — unless its hash is allowlisted.
"""
import logging

import psutil

from ..config import AgentConfig
from ..quarantine import VERDICT_ALLOWLISTED, QuarantineManager, sha256_of
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.port_watchdog")


class PortWatchdog:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient,
                 quarantine: QuarantineManager | None = None):
        self.config = config
        self.telemetry = telemetry
        self.quarantine = quarantine
        self._known_listeners: set[tuple[int, int]] = set()  # (pid, port)

    def _exe_of(self, proc: psutil.Process) -> str | None:
        try:
            return proc.exe() or None
        except psutil.Error:
            return None

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

    def _quarantine_exe(self, exe: str | None, process_name: str, reason: str) -> None:
        """Hash + reputation-check a killed process's executable, then move it
        to quarantine (unless the hash is explicitly allowlisted)."""
        if self.quarantine is None or not exe:
            return
        digest = sha256_of(exe)
        verdict = self.quarantine.verdict(digest)
        if verdict == VERDICT_ALLOWLISTED:
            self.telemetry.emit(
                source="quarantine",
                action="skipped_allowlisted",
                severity="info",
                summary=f"Executable of '{process_name}' left in place — hash is allowlisted",
                details={"path": exe, "sha256": digest, "process": process_name},
            )
            return
        entry = self.quarantine.quarantine(exe, sha256=digest, reason=reason)
        if entry is None:
            return
        self.telemetry.emit(
            source="quarantine",
            action="quarantined",
            severity="critical",
            summary=f"Executable of '{process_name}' quarantined ({verdict} hash)",
            details={**entry, "verdict": verdict, "process": process_name},
        )

    def scan(self) -> None:
        # 1. Known-bad process names anywhere on the host
        for proc in psutil.process_iter(["pid", "name"]):
            name = (proc.info.get("name") or "").lower()
            if name in {p.lower() for p in self.config.blocked_processes}:
                exe = self._exe_of(proc)  # capture before the process dies
                killed = self._kill(proc, f"blocked process name {name}")
                self.telemetry.emit(
                    source="port_watchdog",
                    action="killed" if killed else "kill_failed",
                    severity="critical",
                    summary=f"Blocked process '{name}' (pid {proc.info['pid']}) "
                            f"{'terminated' if killed else 'could not be terminated'}",
                    details={"pid": proc.info["pid"], "process": name},
                )
                if killed:
                    self._quarantine_exe(exe, name, f"blocked process name {name}")

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
                exe = self._exe_of(proc)
                killed = self._kill(proc, f"suspicious listener on port {port}")
                self.telemetry.emit(
                    source="port_watchdog",
                    action="killed" if killed else "kill_failed",
                    severity="critical",
                    summary=f"Unauthorized listener '{name}' on port {port} "
                            f"{'terminated' if killed else 'detected but not terminated'}",
                    details={"pid": c.pid, "process": name, "port": port},
                )
                if killed:
                    self._quarantine_exe(exe, name, f"suspicious listener on port {port}")
            elif name not in self.config.allowlisted_processes:
                self.telemetry.emit(
                    source="port_watchdog",
                    action="detected",
                    severity="warning",
                    summary=f"New listening port {port} opened by '{name}'",
                    details={"pid": c.pid, "process": name, "port": port},
                )
        self._known_listeners = current

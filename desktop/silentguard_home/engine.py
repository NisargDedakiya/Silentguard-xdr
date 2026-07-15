"""Protection engine — ties the blocklist to the OS enforcement layers and keeps
them in sync on a timer.

`sync()` is the heart: for the current blocklist it (re)applies firewall rules,
the hosts-file sinkhole, and the process guard, and removes rules for entries the
user has deleted. It returns a summary the UI shows. Designed so the blockers are
injectable, making the whole flow unit-testable without touching the real OS.
"""
import logging
import platform
import threading
import time
from pathlib import Path

from .blocklist import Blocklist
from .enforcement import (FW_PREFIX, FirewallBlocker, ProcessGuard,
                          resolve_ips)

log = logging.getLogger("silentguard.home.engine")

HOSTS_BEGIN = "# >>> SilentGuard Home >>>"
HOSTS_END = "# <<< SilentGuard Home <<<"


def hosts_path() -> Path:
    if platform.system() == "Windows":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def apply_hosts(domains: list[str], path: Path | None = None) -> bool:
    """Pin domains (and www/m of an apex) to 0.0.0.0 in the hosts file."""
    path = path or hosts_path()
    entries = set()
    for d in domains:
        entries.add(d)
        if d.count(".") == 1:
            entries.update(f"{p}.{d}" for p in ("www", "m", "mobile"))
    try:
        content = path.read_text()
    except OSError:
        return False
    if HOSTS_BEGIN in content and HOSTS_END in content:
        head, rest = content.split(HOSTS_BEGIN, 1)
        _, tail = rest.split(HOSTS_END, 1)
        content = head + tail
    block = "\n".join([HOSTS_BEGIN] + [f"0.0.0.0 {h}" for h in sorted(entries)] + [HOSTS_END])
    try:
        path.write_text(content.rstrip("\n") + "\n" + block + "\n")
        return True
    except OSError:
        return False


class ProtectionEngine:
    def __init__(self, blocklist: Blocklist, firewall: FirewallBlocker | None = None,
                 process_guard: ProcessGuard | None = None, resolver=resolve_ips,
                 hosts_writer=apply_hosts, process_source=None):
        self.blocklist = blocklist
        self.firewall = firewall or FirewallBlocker()
        self.process_guard = process_guard or ProcessGuard()
        self.resolver = resolver
        self.hosts_writer = hosts_writer
        self.process_source = process_source or _iter_processes
        self._active_hosts: set[str] = set()
        self._running = False
        self._thread: threading.Thread | None = None
        self.last_summary: dict = {}

    def sync(self) -> dict:
        domains = self.blocklist.values("domain")
        # Firewall: apply current domains, drop rules for removed ones.
        for host in self._active_hosts - set(domains):
            self.firewall.unblock(host)
        blocked_ips = 0
        for host in domains:
            ips = self.resolver(host)
            self.firewall.block(host, ips)
            blocked_ips += len(ips)
        self._active_hosts = set(domains)
        # Hosts sinkhole (secondary).
        hosts_ok = self.hosts_writer(domains) if domains else True
        # Process guard.
        killed = self.process_guard.enforce(set(self.blocklist.values("process")),
                                            self.process_source())
        self.last_summary = {
            "domains": len(domains),
            "firewall_ips": blocked_ips,
            "hosts_written": hosts_ok,
            "processes_killed": len(killed),
            "ports_blocked": len(self.blocklist.values("port")),
        }
        return self.last_summary

    # -- background loop --------------------------------------------------
    def start(self, interval: float = 30.0) -> None:
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                try:
                    self.sync()
                except Exception:  # noqa: BLE001 — never let the loop die
                    log.exception("sync error")
                time.sleep(interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False


def _iter_processes():
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name"]):
            yield p.info.get("pid"), p.info.get("name")
    except Exception:  # noqa: BLE001
        return

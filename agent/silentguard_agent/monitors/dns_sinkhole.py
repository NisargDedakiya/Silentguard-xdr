"""Pillar 2a — DNS Sinkholing ("The Invisible Fence").

Blocks resolution of known-malicious domains at the OS level by pinning them
to 0.0.0.0 in the hosts file (works on Windows, Linux, macOS without needing
a local DNS proxy). The employee's browser simply shows "site unreachable" —
no decision required.
"""
import logging
import platform
from pathlib import Path

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.dns_sinkhole")

MARK_BEGIN = "# >>> SilentGuard XDR sinkhole >>>"
MARK_END = "# <<< SilentGuard XDR sinkhole <<<"


def hosts_path() -> Path:
    if platform.system() == "Windows":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


class DnsSinkhole:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self._applied: set[str] = set()

    def sync(self) -> None:
        """Ensure the hosts file sinkholes exactly the current blocked set."""
        domains = sorted(self.config.blocked_domains)
        if set(domains) == self._applied:
            return
        if self.config.dry_run:
            log.info("[dry-run] would sinkhole %d domains", len(domains))
            self._applied = set(domains)
            return
        path = hosts_path()
        try:
            content = path.read_text()
        except OSError as exc:
            log.warning("Cannot read hosts file (%s); need admin/root privileges", exc)
            return

        # Strip any previous SilentGuard block, then append the fresh one.
        if MARK_BEGIN in content and MARK_END in content:
            head, rest = content.split(MARK_BEGIN, 1)
            _, tail = rest.split(MARK_END, 1)
            content = head + tail
        block = "\n".join([MARK_BEGIN] + [f"0.0.0.0 {d}" for d in domains] + [MARK_END])
        new_content = content.rstrip("\n") + "\n" + block + "\n"
        try:
            path.write_text(new_content)
        except OSError as exc:
            log.warning("Cannot write hosts file (%s); need admin/root privileges", exc)
            return

        newly_blocked = set(domains) - self._applied
        self._applied = set(domains)
        for d in sorted(newly_blocked):
            self.telemetry.emit(
                source="dns_sinkhole",
                action="blocked",
                severity="warning",
                summary=f"Domain '{d}' sinkholed to 0.0.0.0",
                details={"domain": d},
            )
        log.info("Sinkhole updated: %d domains active", len(domains))

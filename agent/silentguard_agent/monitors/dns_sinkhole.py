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
from ..net_match import extract_host
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.dns_sinkhole")

MARK_BEGIN = "# >>> SilentGuard XDR sinkhole >>>"
MARK_END = "# <<< SilentGuard XDR sinkhole <<<"

# Hosts files cannot wildcard, and browsers usually load the ``www``/``m`` host
# of a site (you type youtube.com, the browser goes to www.youtube.com). So when
# an apex domain is blocked we also sinkhole its most common subdomains, which
# covers the everyday "I blocked the site but it still opens" case.
COMMON_SUBDOMAINS = ("www", "m", "mobile")


def hosts_path() -> Path:
    if platform.system() == "Windows":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def expand_hosts(hosts) -> set[str]:
    """Add common subdomain variants for each blocked apex domain."""
    out: set[str] = set()
    for h in hosts:
        if not h:
            continue
        out.add(h)
        if h.count(".") == 1:  # a registrable apex like youtube.com
            for prefix in COMMON_SUBDOMAINS:
                out.add(f"{prefix}.{h}")
    return out


class DnsSinkhole:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self._applied: set[str] = set()

    def sync(self) -> None:
        """Ensure the hosts file sinkholes exactly the current blocked set.

        Each entry is reduced to its bare host (a URL such as
        ``https://evil.example.com/x`` becomes ``evil.example.com``) so the
        hosts-file line is always a valid hostname. Note: hosts-file sinkholing
        is exact-hostname, so we also sinkhole common subdomains (www/m) of each
        blocked apex; broader subdomain coverage is enforced by the server-side
        blocked-domain detection + response (see docs/domain-blocking.md)."""
        configured = {h for d in self.config.blocked_domains if (h := extract_host(d))}
        domains = sorted(expand_hosts(configured))
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
            log.warning("Cannot read hosts file (%s) — the agent must run "
                        "elevated (Administrator/root) to enforce domain blocks", exc)
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
            log.warning("Cannot write hosts file (%s) — the agent must run "
                        "elevated (Administrator/root) to enforce domain blocks", exc)
            return

        newly_blocked = set(domains) - self._applied
        self._applied = set(domains)
        # Announce only the domains the operator actually configured — the
        # auto-added www/m variants are enforcement detail, not separate events.
        for d in sorted(newly_blocked & configured):
            self.telemetry.emit(
                source="dns_sinkhole",
                action="blocked",
                severity="warning",
                summary=f"Domain '{d}' (and common subdomains) sinkholed to 0.0.0.0",
                details={"domain": d},
            )
        log.info("Sinkhole updated: %d host entries active", len(domains))

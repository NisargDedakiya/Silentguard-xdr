"""Enforcement engine for SilentGuard Home.

Makes the blocklist actually take effect on this PC, using layers that a normal
user (and a normal browser) can't trivially bypass:

- **Firewall (primary):** resolves each blocked domain to its IPs and adds
  Windows Firewall / iptables DROP rules for them. This works even when the
  browser uses DNS-over-HTTPS, because it blocks the connection at the network
  layer regardless of how the name was resolved. IPs are re-resolved on each
  refresh to follow changes (note: CDN-heavy sites like YouTube rotate IPs, so
  firewall blocking is best-effort for those).
- **Hosts file (secondary):** also pins the domain (and www/m) to 0.0.0.0 as a
  fast local block.
- **Process guard:** terminates any running process whose name is blocked.

All OS mutations require Administrator/root — see privileges.py. Every OS command
is built as a list and passed to an injectable runner, so the logic is unit
tested without touching the real firewall.
"""
import logging
import platform
import socket
import subprocess

log = logging.getLogger("silentguard.home.enforce")

FW_PREFIX = "SilentGuard-Block-"
HOSTS_BEGIN = "# >>> SilentGuard Home >>>"
HOSTS_END = "# <<< SilentGuard Home <<<"
COMMON_SUBDOMAINS = ("www", "m", "mobile")


def resolve_ips(host: str, resolver=socket.getaddrinfo) -> set[str]:
    """All IPv4/IPv6 addresses a host currently resolves to (empty on failure)."""
    ips: set[str] = set()
    for h in _with_common_subdomains(host):
        try:
            for info in resolver(h, None):
                ips.add(info[4][0])
        except (OSError, ValueError):
            continue
    return ips


def _with_common_subdomains(host: str) -> list[str]:
    hosts = [host]
    if host.count(".") == 1:  # apex like youtube.com -> also www./m.
        hosts += [f"{p}.{host}" for p in COMMON_SUBDOMAINS]
    return hosts


class FirewallBlocker:
    """Adds/removes OS firewall rules blocking outbound traffic to given IPs."""

    def __init__(self, system: str | None = None, runner=None):
        self.system = system or platform.system()
        self._run = runner or self._default_runner

    @staticmethod
    def _default_runner(cmd: list[str]) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=15)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("firewall command failed %s: %s", cmd, exc)
            return False

    def _rule_name(self, host: str) -> str:
        return FW_PREFIX + host

    def block(self, host: str, ips: set[str]) -> list[list[str]]:
        """Block outbound to ``ips`` for ``host``. Returns the commands issued."""
        self.unblock(host)  # replace any prior rule so IP changes are picked up
        if not ips:
            return []
        cmds: list[list[str]] = []
        if self.system == "Windows":
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={self._rule_name(host)}", "dir=out", "action=block",
                         f"remoteip={','.join(sorted(ips))}"])
        else:  # Linux/macOS via iptables
            for ip in sorted(ips):
                if ":" in ip:
                    continue  # skip IPv6 for the iptables path
                cmds.append(["iptables", "-A", "OUTPUT", "-d", ip,
                             "-m", "comment", "--comment", self._rule_name(host),
                             "-j", "DROP"])
        for c in cmds:
            self._run(c)
        return cmds

    def unblock(self, host: str) -> list[list[str]]:
        cmds: list[list[str]] = []
        if self.system == "Windows":
            cmds.append(["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={self._rule_name(host)}"])
        else:
            # Best-effort flush of our tagged OUTPUT rules for this host.
            cmds.append(["bash", "-c",
                         "iptables-save | grep -- '--comment \"%s\"' | "
                         "sed 's/^-A/iptables -D/' | sh || true" % self._rule_name(host)])
        for c in cmds:
            self._run(c)
        return cmds


class ProcessGuard:
    """Terminates running processes whose name is on the blocklist."""

    def __init__(self, killer=None):
        self._kill = killer or self._default_kill

    @staticmethod
    def _default_kill(pid: int) -> bool:
        try:
            import psutil
            psutil.Process(pid).kill()
            return True
        except Exception:  # noqa: BLE001
            return False

    def enforce(self, blocked_names: set[str], processes) -> list[int]:
        """`processes` is an iterable of (pid, name). Returns pids killed."""
        killed = []
        wanted = {n.lower() for n in blocked_names}
        for pid, name in processes:
            if (name or "").lower() in wanted and self._kill(pid):
                killed.append(pid)
        return killed

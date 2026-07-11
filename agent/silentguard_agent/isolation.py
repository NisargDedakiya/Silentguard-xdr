"""Remote isolation: restrict the device's network access to the management
server only, while keeping the agent's control channel alive.

Linux: iptables rules. Windows: netsh advfirewall. Both are reverted by
release(). In dry-run mode the state change is only logged.
"""
import logging
import platform
import subprocess
from urllib.parse import urlparse

from .config import AgentConfig
from .telemetry import TelemetryClient

log = logging.getLogger("silentguard.isolation")

CHAIN = "SILENTGUARD_ISOLATE"


class IsolationController:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self.isolated = False
        parsed = urlparse(config.server_url)
        self.server_host = parsed.hostname or "127.0.0.1"
        self.server_port = str(parsed.port or (443 if parsed.scheme == "https" else 80))

    def _sh(self, cmd: list[str]) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=15)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("Command failed %s: %s", cmd, exc)
            return False

    def isolate(self) -> None:
        if self.isolated:
            return
        ok = True
        if not self.config.dry_run:
            system = platform.system()
            if system == "Linux":
                ok = (
                    self._sh(["iptables", "-N", CHAIN])
                    and self._sh(["iptables", "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"])
                    and self._sh(["iptables", "-A", CHAIN, "-d", self.server_host,
                                  "-p", "tcp", "--dport", self.server_port, "-j", "ACCEPT"])
                    and self._sh(["iptables", "-A", CHAIN, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
                    and self._sh(["iptables", "-A", CHAIN, "-j", "DROP"])
                    and self._sh(["iptables", "-I", "OUTPUT", "1", "-j", CHAIN])
                )
            elif system == "Windows":
                ok = (
                    self._sh(["netsh", "advfirewall", "firewall", "add", "rule",
                              "name=SilentGuard-Allow-Mgmt", "dir=out", "action=allow",
                              f"remoteip={self.server_host}", "protocol=TCP",
                              f"remoteport={self.server_port}"])
                    and self._sh(["netsh", "advfirewall", "set", "allprofiles",
                                  "firewallpolicy", "blockinbound,blockoutbound"])
                )
            else:
                ok = False
        self.isolated = True
        self.telemetry.emit(
            source="isolation",
            action="isolated" if ok else "isolation_partial",
            severity="critical",
            summary="Device isolated: network restricted to management server"
                    + ("" if ok else " (some firewall rules could not be applied)"),
            details={"management_server": f"{self.server_host}:{self.server_port}"},
        )

    def release(self) -> None:
        if not self.isolated:
            return
        if not self.config.dry_run:
            system = platform.system()
            if system == "Linux":
                self._sh(["iptables", "-D", "OUTPUT", "-j", CHAIN])
                self._sh(["iptables", "-F", CHAIN])
                self._sh(["iptables", "-X", CHAIN])
            elif system == "Windows":
                self._sh(["netsh", "advfirewall", "set", "allprofiles",
                          "firewallpolicy", "blockinbound,allowoutbound"])
                self._sh(["netsh", "advfirewall", "firewall", "delete", "rule",
                          "name=SilentGuard-Allow-Mgmt"])
        self.isolated = False
        self.telemetry.emit(
            source="isolation",
            action="released",
            severity="info",
            summary="Device isolation released: normal network access restored",
        )

"""Pillar 2b — Rogue Network Defense.

Watches the OS ARP cache for gateway spoofing: if the default gateway's IP
suddenly resolves to a different MAC address, a nearby attacker is likely
impersonating the router. The attacker's MAC is blocked via the local
firewall (Linux: iptables/nftables; Windows: netsh) and a critical alert is
emitted.
"""
import logging
import platform
import re
import subprocess

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.arp_guard")


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway() -> str | None:
    if platform.system() == "Windows":
        out = _run(["route", "print", "0.0.0.0"])
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
    else:
        out = _run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP cache."""
    table: dict[str, str] = {}
    if platform.system() == "Windows":
        out = _run(["arp", "-a"])
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", out):
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    else:
        out = _run(["ip", "neigh"])
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-f:]{17})", out):
            table[m.group(1)] = m.group(2).lower()
    return table


class ArpGuard:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self.gateway_ip: str | None = None
        self.trusted_mac: str | None = None
        self._blocked_macs: set[str] = set()

    def _block_mac(self, mac: str) -> bool:
        if mac in self._blocked_macs:
            return True
        if self.config.dry_run:
            log.info("[dry-run] would block MAC %s", mac)
            self._blocked_macs.add(mac)
            return True
        system = platform.system()
        try:
            if system == "Linux":
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                    check=True, capture_output=True, timeout=10,
                )
            elif system == "Windows":
                # Windows firewall has no MAC filter; drop the spoofed neighbor entry
                # and re-pin the trusted gateway mapping instead.
                if self.gateway_ip and self.trusted_mac:
                    subprocess.run(
                        ["netsh", "interface", "ip", "add", "neighbors",
                         "name=*", self.gateway_ip, self.trusted_mac.replace(":", "-")],
                        capture_output=True, timeout=10,
                    )
            else:
                return False
            self._blocked_macs.add(mac)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("Failed to block MAC %s: %s", mac, exc)
            return False

    def scan(self) -> None:
        gw = default_gateway()
        if gw is None:
            return
        table = arp_table()
        mac = table.get(gw)
        if mac is None:
            return
        if self.gateway_ip != gw:
            # New network — trust the first observed gateway MAC (TOFU).
            self.gateway_ip, self.trusted_mac = gw, mac
            log.info("Gateway pinned: %s -> %s", gw, mac)
            return
        if mac != self.trusted_mac:
            blocked = self._block_mac(mac)
            self.telemetry.emit(
                source="arp_guard",
                action="dropped" if blocked else "detected",
                severity="critical",
                summary=f"ARP spoofing detected: gateway {gw} changed MAC "
                        f"{self.trusted_mac} -> {mac}; attacker traffic "
                        f"{'blocked' if blocked else 'NOT blocked (insufficient privileges)'}",
                details={"gateway": gw, "trusted_mac": self.trusted_mac, "spoofed_mac": mac},
            )

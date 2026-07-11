"""SilentGuard XDR endpoint agent.

Runs silently in the background: enrolls with the management server, then
loops over the three monitors (port/process watchdog, DNS sinkhole, ARP
guard), streams telemetry, and obeys remote isolation commands.

Usage:
    python -m silentguard_agent.main
Environment:
    SG_SERVER_URL     management server base URL (default http://127.0.0.1:8000)
    SG_ENROLL_TOKEN   one-time enrollment token
    SG_DRY_RUN=1      log actions instead of killing processes / editing
                      hosts / firewall (useful for demos without root)
"""
import logging
import signal
import sys
import time

from .config import AgentConfig
from .isolation import IsolationController
from .monitors.arp_guard import ArpGuard
from .monitors.dns_sinkhole import DnsSinkhole
from .monitors.port_watchdog import PortWatchdog
from .telemetry import TelemetryClient

log = logging.getLogger("silentguard")


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    config = AgentConfig()
    telemetry = TelemetryClient(config)

    # Retry enrollment until the server is reachable.
    while True:
        try:
            telemetry.ensure_enrolled()
            break
        except Exception as exc:  # noqa: BLE001 — keep the agent alive
            log.warning("Enrollment failed (%s), retrying in 5s", exc)
            time.sleep(5)

    watchdog = PortWatchdog(config, telemetry)
    sinkhole = DnsSinkhole(config, telemetry)
    arp_guard = ArpGuard(config, telemetry)
    isolation = IsolationController(config, telemetry)

    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    telemetry.emit("agent", "started", f"SilentGuard agent online on {config.hostname}")
    last_checkin = 0.0

    while running:
        try:
            watchdog.scan()
            arp_guard.scan()
            sinkhole.sync()

            now = time.monotonic()
            if now - last_checkin >= config.checkin_interval:
                last_checkin = now
                state = telemetry.checkin()
                if state:
                    # Merge fleet blocklist pushed from the dashboard.
                    bl = state.get("blocklist", {})
                    config.blocked_domains.update(bl.get("domain", []))
                    config.blocked_processes.update(bl.get("process", []))
                    for p in bl.get("port", []):
                        try:
                            config.suspicious_ports.add(int(p))
                        except ValueError:
                            pass
                    if state.get("isolated"):
                        isolation.isolate()
                    else:
                        isolation.release()

            telemetry.flush()
        except Exception as exc:  # noqa: BLE001 — the agent must not die
            log.exception("Monitor loop error: %s", exc)
        time.sleep(config.poll_interval)

    telemetry.emit("agent", "stopped", f"SilentGuard agent stopped on {config.hostname}")
    telemetry.flush()
    sys.exit(0)


if __name__ == "__main__":
    run()

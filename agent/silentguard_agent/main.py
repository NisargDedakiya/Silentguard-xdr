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
from .inventory import collect_inventory
from .isolation import IsolationController
from .monitors.arp_guard import ArpGuard
from .monitors.dns_sinkhole import DnsSinkhole
from .monitors.file_drop import FileDropMonitor
from .monitors.port_watchdog import PortWatchdog
from .monitors.usb_guard import UsbGuard
from .quarantine import QuarantineManager
from . import response_handlers as handlers
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

    quarantine = QuarantineManager(config)
    watchdog = PortWatchdog(config, telemetry, quarantine)
    sinkhole = DnsSinkhole(config, telemetry)
    arp_guard = ArpGuard(config, telemetry)
    file_drop = FileDropMonitor(config, telemetry, quarantine)
    usb_guard = UsbGuard(config, telemetry)
    isolation = IsolationController(config, telemetry)

    def _report_result(action_id, status, **extra):
        if action_id is not None:
            telemetry.emit("response", "result",
                           f"Response action {action_id} {status}",
                           severity="info",
                           details={"action_id": action_id, "status": status, **extra})

    def handle_command(cmd: dict) -> None:
        command = cmd.get("command")
        action_id = cmd.get("action_id")
        if command == "restore_quarantine":
            qid = cmd.get("id", "")
            entry = quarantine.restore(qid)
            if entry:
                telemetry.emit(
                    "quarantine", "restored",
                    f"Quarantined file restored to {entry['original_path']}",
                    severity="info", details=entry,
                )
                _report_result(action_id, "ok", restored=entry["original_path"])
            else:
                telemetry.emit(
                    "quarantine", "restore_failed",
                    f"Failed to restore quarantine item {qid}",
                    severity="warning", details={"id": qid},
                )
                _report_result(action_id, "failed", id=qid)
        elif command == "kill_process":
            handlers.kill_process(cmd, telemetry, config, _report_result)
        elif command == "delete_file":
            handlers.delete_file(cmd, telemetry, config, quarantine, _report_result)
        elif command == "remote_scan":
            handlers.remote_scan(cmd, telemetry, config, _report_result)
        elif command == "remote_update":
            handlers.remote_update(cmd, telemetry, _report_result)

    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    telemetry.emit("agent", "started", f"SilentGuard agent online on {config.hostname}")
    last_checkin = 0.0
    last_inventory = 0.0

    while running:
        try:
            watchdog.scan()
            arp_guard.scan()
            sinkhole.sync()
            file_drop.scan()
            usb_guard.scan()

            now = time.monotonic()
            # Report inventory on the same cadence as check-in.
            if now - last_inventory >= config.inventory_interval:
                last_inventory = now
                try:
                    telemetry.send_inventory(collect_inventory())
                except Exception as exc:  # noqa: BLE001 — inventory must not kill the loop
                    log.warning("Inventory collection failed: %s", exc)

            if now - last_checkin >= config.checkin_interval:
                last_checkin = now
                state = telemetry.checkin()
                if state:
                    for cmd in state.get("commands", []):
                        handle_command(cmd)
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

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
from .monitors.process_monitor import ProcessMonitor
from .monitors.registry_monitor import RegistryMonitor
from .monitors.suricata_monitor import SuricataMonitor
from .monitors.usb_guard import UsbGuard
from .monitors.yara_scanner import YaraScanner
from .privileges import enforcement_status
from .quarantine import QuarantineManager
from . import response_handlers as handlers
from .telemetry import TelemetryClient

log = logging.getLogger("silentguard")


def apply_policy(config: AgentConfig, policy: dict) -> None:
    """Merge a server-resolved effective policy into the agent config (M16)."""
    if not policy:
        return
    for port in policy.get("suspicious_ports", []):
        try:
            config.suspicious_ports.add(int(port))
        except (TypeError, ValueError):
            pass
    config.blocked_processes.update(policy.get("blocked_processes", []))
    config.blocked_domains.update(policy.get("blocked_domains", []))
    for d in policy.get("file_drop_dirs", []):
        if d not in config.file_drop_dirs:
            config.file_drop_dirs.append(d)
    if "block_usb_storage" in policy:
        config.block_usb_storage = bool(policy["block_usb_storage"])


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
    process_monitor = ProcessMonitor(config, telemetry)
    usb_guard = UsbGuard(config, telemetry)
    yara_scanner = YaraScanner(config, telemetry, quarantine)
    suricata = SuricataMonitor(config, telemetry)
    registry_monitor = RegistryMonitor(config, telemetry)
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
            handlers.remote_update(cmd, telemetry, config, _report_result)

    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    telemetry.emit("agent", "started", f"SilentGuard agent online on {config.hostname}")

    # Tell the operator up front whether enforcement can actually take effect;
    # otherwise a blocklist/isolation that silently no-ops looks like a bug.
    status = enforcement_status(config)
    if status["can_enforce"]:
        log.info("Enforcement enabled (elevated, live mode)")
        telemetry.emit("agent", "capabilities",
                       "Enforcement enabled: domain blocking, isolation, USB control active",
                       severity="info", details=status)
    else:
        reason = "; ".join(status["reasons"])
        log.warning("ENFORCEMENT DISABLED (%s). Blocklist, isolation and USB "
                    "blocking will NOT take effect. Run the agent elevated "
                    "(Administrator/root) and without SG_DRY_RUN to enforce.", reason)
        telemetry.emit("agent", "enforcement_disabled",
                       f"Enforcement disabled: {reason}. Domain blocking and "
                       f"isolation will not take effect until the agent runs elevated.",
                       severity="warning", details=status)

    last_checkin = 0.0
    last_inventory = 0.0

    while running:
        try:
            watchdog.scan()
            arp_guard.scan()
            sinkhole.sync()
            file_drop.scan()
            process_monitor.scan()
            usb_guard.scan()
            yara_scanner.scan()
            suricata.scan()
            registry_monitor.scan()

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
                    # Apply the effective policy resolved server-side (M16).
                    apply_policy(config, state.get("policy", {}))
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

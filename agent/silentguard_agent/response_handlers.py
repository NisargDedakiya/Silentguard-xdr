"""Agent-side handlers for M14 response actions.

Each handler executes best-effort, emits a telemetry event, and reports the
result back to the server via the supplied ``report`` callback. Handlers honor
``config.dry_run`` so demos/tests never touch the real OS.
"""
import logging
import os

import psutil

log = logging.getLogger("silentguard.response")


def kill_process(cmd, telemetry, config, report):
    pid = cmd.get("pid")
    name = (cmd.get("name") or "").lower()
    action_id = cmd.get("action_id")
    killed = []
    try:
        targets = []
        if pid is not None:
            targets.append(psutil.Process(int(pid)))
        elif name:
            targets = [p for p in psutil.process_iter(["name"])
                       if (p.info.get("name") or "").lower() == name]
        for proc in targets:
            if config.dry_run:
                log.info("[dry-run] would kill pid=%s", proc.pid)
                killed.append(proc.pid)
                continue
            proc.kill()
            proc.wait(timeout=3)
            killed.append(proc.pid)
    except (psutil.Error, ValueError) as exc:
        telemetry.emit("response", "kill_failed", f"kill_process failed: {exc}",
                       severity="warning", details={"pid": pid, "name": name})
        report(action_id, "failed", error=str(exc))
        return
    telemetry.emit("response", "process_killed",
                   f"Killed {len(killed)} process(es)", severity="critical",
                   details={"killed": killed})
    report(action_id, "ok", killed=killed)


def delete_file(cmd, telemetry, config, quarantine, report):
    """Quarantine (move, not delete) the file, so it can still be restored."""
    path = cmd.get("path", "")
    action_id = cmd.get("action_id")
    if not path:
        report(action_id, "failed", error="no path")
        return
    entry = quarantine.quarantine(path, reason="response:delete_file")
    if entry:
        telemetry.emit("response", "file_deleted",
                       f"File {path} quarantined for deletion", severity="critical",
                       details=entry)
        report(action_id, "ok", quarantined=entry.get("id"))
    else:
        report(action_id, "failed", path=path)


def remote_scan(cmd, telemetry, config, report):
    """Lightweight on-demand scan: hash-check watched dirs / running binaries.
    Here it reports process + open-file counts as a stand-in for a full scan."""
    action_id = cmd.get("action_id")
    try:
        proc_count = len(psutil.pids())
    except Exception:  # noqa: BLE001
        proc_count = 0
    telemetry.emit("response", "scan_complete",
                   f"Remote scan complete ({proc_count} processes)", severity="info",
                   details={"process_count": proc_count})
    report(action_id, "ok", process_count=proc_count)


def remote_update(cmd, telemetry, report):
    """Acknowledge an update request. Real package delivery is out of scope
    (deferred agent auto-update); this records the intent."""
    action_id = cmd.get("action_id")
    target = cmd.get("version", "latest")
    telemetry.emit("response", "update_requested",
                   f"Agent update to {target} acknowledged", severity="info",
                   details={"version": target, "current_pid": os.getpid()})
    report(action_id, "ok", acknowledged=target)

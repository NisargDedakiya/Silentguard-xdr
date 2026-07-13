"""Agent-side handlers for M14 response actions.

Each handler executes best-effort, emits a telemetry event, and reports the
result back to the server via the supplied ``report`` callback. Handlers honor
``config.dry_run`` so demos/tests never touch the real OS.
"""
import logging
import os

import psutil

from .update_verifier import verify_update

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


def remote_update(cmd, telemetry, config, report):
    """Handle an update request (M15a). When the command carries an update
    manifest (``url``/``sha256``) or a signature, it MUST verify against the
    provisioned trust key before it is honored — a compromised channel cannot
    push arbitrary code. A version-only acknowledgement (no manifest) keeps the
    legacy best-effort behavior. Real package delivery remains deferred; this
    records verified intent."""
    action_id = cmd.get("action_id")
    target = cmd.get("version", "latest")
    is_manifest = bool(cmd.get("url") or cmd.get("sha256") or cmd.get("signature"))

    if is_manifest:
        ok, reason = verify_update(cmd, config)
        if not ok:
            telemetry.emit("response", "update_rejected",
                           f"Agent update to {target} rejected: {reason}",
                           severity="warning",
                           details={"version": target, "reason": reason})
            report(action_id, "failed", error=reason, version=target)
            return
        # Anti-rollback: refuse a signed downgrade below the accepted floor
        # unless the (signed) manifest explicitly allows it (v1.4).
        from . import update_verifier as uv
        from .config import get_update_floor, set_update_floor
        floor = get_update_floor()
        allow_rollback = str(cmd.get("allow_rollback", "")).lower() in ("1", "true", "yes")
        if (uv.is_numeric_version(target) and floor
                and uv.is_rollback(target, floor) and not allow_rollback):
            telemetry.emit("response", "update_rejected",
                           f"Agent update to {target} rejected: rollback below {floor} blocked",
                           severity="warning",
                           details={"version": target, "floor": floor,
                                    "reason": "rollback_blocked"})
            report(action_id, "failed", error="rollback_blocked",
                   version=target, floor=floor)
            return
        # Advance the floor when accepting a newer version.
        if uv.is_numeric_version(target) and (not floor or uv.version_gt(target, floor)):
            set_update_floor(target)
        telemetry.emit("response", "update_verified",
                       f"Agent update to {target} verified and acknowledged",
                       severity="info",
                       details={"version": target, "sha256": cmd.get("sha256", ""),
                                "current_pid": os.getpid(), "verified": True})
        report(action_id, "ok", acknowledged=target, verified=True)
        return

    # No manifest: a bare version-only intent. Nothing is downloaded or
    # executed, so it is acknowledged, but flagged unsigned for visibility.
    telemetry.emit("response", "update_requested",
                   f"Agent update to {target} acknowledged (unsigned)", severity="info",
                   details={"version": target, "current_pid": os.getpid(), "verified": False})
    report(action_id, "ok", acknowledged=target, verified=False)

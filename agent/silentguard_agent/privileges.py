"""Privilege / capability detection.

Enforcement actions — DNS sinkholing (hosts file), network isolation (firewall),
and USB blocking — require the agent to run **elevated** (Administrator on
Windows, root on Linux/macOS). Telemetry and detection do not. When the agent is
not elevated these actions fail silently at the OS layer, which looks like "the
blocklist isn't working". This module makes that state explicit so the operator
sees *why* in the logs and the dashboard.
"""
import logging
import os
import platform

log = logging.getLogger("silentguard.privileges")


def is_elevated() -> bool:
    """True if the process can modify the hosts file / firewall."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001 — any failure means "assume not admin"
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX without geteuid
        return False


def enforcement_status(config) -> dict:
    """Describe whether enforcement actions can actually take effect."""
    elevated = is_elevated()
    dry_run = bool(getattr(config, "dry_run", False))
    can_enforce = elevated and not dry_run
    reasons = []
    if dry_run:
        reasons.append("running in dry-run (SG_DRY_RUN=1)")
    if not elevated:
        reasons.append("not elevated (needs Administrator/root)")
    return {
        "elevated": elevated,
        "dry_run": dry_run,
        "can_enforce": can_enforce,
        # Actions that silently no-op when enforcement is unavailable.
        "affected": ["domain blocking (DNS sinkhole)", "device isolation",
                     "USB blocking"] if not can_enforce else [],
        "reasons": reasons,
    }

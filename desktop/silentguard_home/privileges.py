"""Elevation helpers for SilentGuard Home.

Blocking (firewall + hosts) needs Administrator. If the app is launched without
it, ``relaunch_as_admin`` restarts the same program through the UAC prompt so the
user just clicks "Yes" once instead of having to right-click "Run as admin".
"""
import ctypes
import logging
import os
import platform
import sys

log = logging.getLogger("silentguard.home.priv")


def is_elevated() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover
        return False


def relaunch_as_admin() -> bool:
    """Relaunch the current program elevated (Windows UAC). Returns True if a
    relaunch was triggered (the caller should then exit)."""
    if platform.system() != "Windows" or is_elevated():
        return False
    try:
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        # ShellExecuteW verb "runas" raises the UAC prompt.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{sys.argv[0]}" {params}', None, 1)
        return rc > 32  # >32 means success per ShellExecute contract
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not relaunch elevated: %s", exc)
        return False

"""Registry autorun monitor (v1.3).

Watches the Windows Run/RunOnce registry keys — the classic persistence foothold
(MITRE T1547.001) — and reports **new or changed** autorun entries. The emitted
telemetry carries the full key path, so the server's existing
``registry_persistence`` rule fires a detection with no server change (the M9
rule was written to be fed by exactly this monitor).

Windows-only: registry access uses the stdlib ``winreg``. On Linux/macOS the
monitor is a clean no-op, so the same agent build runs everywhere. The first
scan records a baseline silently so a restart never replays existing autoruns.
"""
import logging
import sys

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.registry")

# (display hive, winreg hive attribute, subkey) for the autostart locations.
AUTORUN_KEYS = [
    ("HKLM", "HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", "HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", "HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", "HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


class RegistryMonitor:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient):
        self.config = config
        self.telemetry = telemetry
        self.enabled = sys.platform.startswith("win") and getattr(
            config, "registry_enabled", True)
        self._seen: dict[str, dict[str, str]] = {}
        self._baselined = False

    def _read_key(self, hive_attr: str, subkey: str) -> dict[str, str]:
        """Return ``{value_name: command}`` for one autorun key (Windows only)."""
        import winreg  # noqa: PLC0415 — Windows-only import kept out of module load

        entries: dict[str, str] = {}
        try:
            with winreg.OpenKey(getattr(winreg, hive_attr), subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    entries[name] = str(value)
                    i += 1
        except OSError:
            return {}
        return entries

    def _snapshot(self) -> dict[str, dict[str, str]]:
        snap: dict[str, dict[str, str]] = {}
        for hive_name, hive_attr, subkey in AUTORUN_KEYS:
            snap[f"{hive_name}\\{subkey}"] = self._read_key(hive_attr, subkey)
        return snap

    def _emit(self, key: str, name: str, command: str, action: str) -> None:
        verb = action.split("_", 1)[1]  # added | changed
        self.telemetry.emit(
            source="registry_monitor",
            action=action,
            severity="warning",
            # The raw key path in the summary lets the server rule match reliably
            # (JSON serialization would double the backslashes).
            summary=f"Registry autorun {verb}: {key}\\{name} -> {command}",
            details={"key": key, "name": name, "command_line": command},
        )

    def scan(self) -> None:
        if not self.enabled:
            return
        snapshot = self._snapshot()
        if not self._baselined:
            self._seen = snapshot
            self._baselined = True
            return
        for key, entries in snapshot.items():
            prev = self._seen.get(key, {})
            for name, command in entries.items():
                if name not in prev:
                    self._emit(key, name, command, "autorun_added")
                elif prev[name] != command:
                    self._emit(key, name, command, "autorun_changed")
        self._seen = snapshot

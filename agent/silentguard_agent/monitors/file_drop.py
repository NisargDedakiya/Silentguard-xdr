"""File-drop hook — watches common drop directories for new files.

Each new file's SHA-256 is checked against the local reputation table:
known-bad files are quarantined immediately (moved, renamed, permissions
stripped — never deleted); unknown executables are reported as suspicious.
The first scan only records a baseline so a restart never floods the
timeline with pre-existing files.
"""
import logging
import os
from pathlib import Path

from ..config import AgentConfig
from ..quarantine import (
    VERDICT_ALLOWLISTED,
    VERDICT_KNOWN_BAD,
    QuarantineManager,
    sha256_of,
)
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.file_drop")


class FileDropMonitor:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient,
                 quarantine: QuarantineManager):
        self.config = config
        self.telemetry = telemetry
        self.quarantine = quarantine
        self._seen: set[str] = set()
        self._baselined = False

    def _list_files(self) -> list[Path]:
        files: list[Path] = []
        for d in self.config.file_drop_dirs:
            try:
                for p in Path(d).iterdir():
                    if p.is_file() and not p.is_symlink():
                        files.append(p)
            except OSError:
                continue
        return files

    def _handle_new_file(self, path: Path) -> None:
        digest = sha256_of(path)
        if digest is None:
            return
        verdict = self.quarantine.verdict(digest)
        if verdict == VERDICT_ALLOWLISTED:
            return
        if verdict == VERDICT_KNOWN_BAD:
            entry = self.quarantine.quarantine(path, sha256=digest,
                                               reason="known-bad hash dropped on disk")
            self.telemetry.emit(
                source="file_drop",
                action="quarantined" if entry else "quarantine_failed",
                severity="critical",
                summary=f"Known-bad file '{path.name}' dropped in {path.parent} "
                        f"{'and quarantined' if entry else 'but quarantine failed'}",
                details={**(entry or {"original_path": str(path)}),
                         "sha256": digest, "verdict": verdict},
            )
            return
        if os.access(path, os.X_OK):
            self.telemetry.emit(
                source="file_drop",
                action="detected",
                severity="warning",
                summary=f"New executable file '{path.name}' dropped in {path.parent}",
                details={"path": str(path), "sha256": digest, "verdict": verdict},
            )

    def scan(self) -> None:
        files = self._list_files()
        if not self._baselined:
            # First scan records pre-existing files without alerting.
            self._seen = {str(p) for p in files}
            self._baselined = True
            return
        current: set[str] = set()
        for p in files:
            key = str(p)
            current.add(key)
            if key not in self._seen:
                self._handle_new_file(p)
        # Quarantined files vanish from the directory; only remember what is
        # still present so a re-dropped file is flagged again.
        self._seen = current

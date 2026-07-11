"""File hash reputation + quarantine.

When a monitor flags a suspicious process or dropped file, its SHA-256 is
checked against a local reputation table (known-bad hashes plus a
user-maintained allowlist). Instead of deleting anything, flagged files are
*moved* into a quarantine directory — renamed to an opaque id and with all
permissions stripped — so they can be inspected or restored later from the
dashboard.
"""
import datetime
import hashlib
import json
import logging
import os
import shutil
import uuid
from pathlib import Path

from .config import STATE_DIR, AgentConfig

log = logging.getLogger("silentguard.quarantine")

QUARANTINE_DIR = STATE_DIR / "quarantine"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"

VERDICT_KNOWN_BAD = "known_bad"
VERDICT_ALLOWLISTED = "allowlisted"
VERDICT_UNKNOWN = "unknown"


def sha256_of(path: str | Path) -> str | None:
    """SHA-256 of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


class QuarantineManager:
    def __init__(self, config: AgentConfig, quarantine_dir: Path | None = None):
        self.config = config
        self.dir = quarantine_dir or QUARANTINE_DIR
        self.manifest_file = self.dir / "manifest.json"

    # -- reputation ---------------------------------------------------------
    def verdict(self, sha256: str | None) -> str:
        if sha256 and sha256 in self.config.allowlisted_hashes:
            return VERDICT_ALLOWLISTED
        if sha256 and sha256 in self.config.known_bad_hashes:
            return VERDICT_KNOWN_BAD
        return VERDICT_UNKNOWN

    # -- manifest -----------------------------------------------------------
    def _load_manifest(self) -> list[dict]:
        try:
            data = json.loads(self.manifest_file.read_text())
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save_manifest(self, entries: list[dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file.write_text(json.dumps(entries, indent=2))
        try:
            os.chmod(self.manifest_file, 0o600)
        except OSError:
            pass

    def list(self) -> list[dict]:
        return self._load_manifest()

    # -- actions ------------------------------------------------------------
    def quarantine(self, path: str | Path, sha256: str | None = None,
                   reason: str = "") -> dict | None:
        """Move `path` into quarantine. Returns the manifest entry, or None if
        the file could not be quarantined (already gone, permissions, ...)."""
        src = Path(path)
        digest = sha256 or sha256_of(src)
        qid = uuid.uuid4().hex
        entry = {
            "id": qid,
            "original_path": str(src),
            "sha256": digest,
            "stored_name": f"{qid}.quarantined",
            "reason": reason,
            "quarantined_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "quarantined",
        }
        if self.config.dry_run:
            log.info("[dry-run] would quarantine %s (sha256=%s)", src, digest)
            entries = self._load_manifest()
            entries.append(entry)
            self._save_manifest(entries)
            return entry
        if not src.is_file():
            return None
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            dest = self.dir / entry["stored_name"]
            shutil.move(str(src), dest)
            os.chmod(dest, 0o000)  # strip all permissions
        except OSError as exc:
            log.warning("Failed to quarantine %s: %s", src, exc)
            return None
        entries = self._load_manifest()
        entries.append(entry)
        self._save_manifest(entries)
        log.info("Quarantined %s -> %s", src, dest)
        return entry

    def restore(self, qid: str) -> dict | None:
        """Move a quarantined file back to its original path. Returns the
        updated entry, or None if the id is unknown or the move failed."""
        entries = self._load_manifest()
        for entry in entries:
            if entry["id"] != qid or entry.get("status") != "quarantined":
                continue
            if self.config.dry_run:
                log.info("[dry-run] would restore %s", entry["original_path"])
            else:
                stored = self.dir / entry["stored_name"]
                dest = Path(entry["original_path"])
                try:
                    os.chmod(stored, 0o600)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(stored), dest)
                except OSError as exc:
                    log.warning("Failed to restore %s: %s", qid, exc)
                    return None
            entry["status"] = "restored"
            entry["restored_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self._save_manifest(entries)
            log.info("Restored %s -> %s", qid, entry["original_path"])
            return entry
        return None

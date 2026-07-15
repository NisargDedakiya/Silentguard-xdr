"""Local blocklist store for the standalone SilentGuard Home app.

A single JSON file the user edits through the app. Entries are kinds:
``domain`` (covers subdomains), ``process`` (executable name), ``port``. No
server, no network — everything lives on this one PC.
"""
import json
import os
import platform
from pathlib import Path
from urllib.parse import urlsplit

KINDS = ("domain", "process", "port")


def data_dir() -> Path:
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", str(Path.home()))
        return Path(base) / "SilentGuard"
    return Path.home() / ".silentguard-home"


def _norm_domain(value: str) -> str:
    v = str(value).strip().lower().rstrip(".")
    if not v:
        return ""
    if "://" not in v:
        v = "//" + v
    return urlsplit(v).hostname or ""


def normalize(kind: str, value: str) -> str:
    value = str(value).strip()
    if kind == "domain":
        return _norm_domain(value)
    if kind == "process":
        return value.lower()
    if kind == "port":
        return str(int(value))  # raises ValueError on bad input
    return value


class Blocklist:
    def __init__(self, path: Path | None = None):
        self.path = path or (data_dir() / "blocklist.json")
        self._entries: list[dict] = []
        self.load()

    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text())
            self._entries = [e for e in data if e.get("kind") in KINDS]
        except (OSError, ValueError):
            self._entries = []

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._entries, indent=2))

    def add(self, kind: str, value: str) -> dict:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        value = normalize(kind, value)
        if not value:
            raise ValueError("empty value")
        if not any(e["kind"] == kind and e["value"] == value for e in self._entries):
            self._entries.append({"kind": kind, "value": value})
            self.save()
        return {"kind": kind, "value": value}

    def remove(self, kind: str, value: str) -> None:
        value = normalize(kind, value)
        self._entries = [e for e in self._entries
                         if not (e["kind"] == kind and e["value"] == value)]
        self.save()

    def entries(self) -> list[dict]:
        return list(self._entries)

    def values(self, kind: str) -> list[str]:
        return [e["value"] for e in self._entries if e["kind"] == kind]

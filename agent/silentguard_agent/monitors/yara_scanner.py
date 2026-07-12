"""YARA file scanner (v1.3).

Scans newly-dropped files in the watched directories against a YARA rule set and
reports (and optionally quarantines) matches. YARA is the de-facto standard for
signature-based malware identification, so this lets a SOC ship its own or
vendor rule packs to the fleet.

Fully optional and dependency-light: it is inert unless ``SG_YARA_ENABLED`` is
set with a rules path (``SG_YARA_RULES``, a ``.yar``/``.yara`` file or a
directory of them) and the ``yara-python`` package is installed. Any missing
piece degrades to a clean no-op — the agent never fails to start because YARA
isn't configured. The server side turns a ``source="yara"`` match into a
critical detection via the ``yara_match`` rule.

Baseline-aware like the file-drop monitor: the first scan records existing files
silently so a restart never re-scans the whole directory.
"""
import logging
from pathlib import Path

from ..config import AgentConfig
from ..quarantine import QuarantineManager
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.yara")


class YaraScanner:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient,
                 quarantine: QuarantineManager | None = None, rules=None):
        self.config = config
        self.telemetry = telemetry
        self.quarantine = quarantine
        self._seen: set[str] = set()
        self._baselined = False
        # ``rules`` is injectable for testing; otherwise compile from config.
        self._rules = rules if rules is not None else self._compile()
        self.enabled = self._rules is not None

    # -- rule compilation -------------------------------------------------
    def _compile(self):
        if not getattr(self.config, "yara_enabled", False):
            return None
        path = getattr(self.config, "yara_rules_path", "")
        if not path:
            log.info("YARA enabled but SG_YARA_RULES is unset; scanner disabled")
            return None
        try:
            import yara
        except ImportError:
            log.warning("YARA enabled but yara-python not installed; scanner disabled")
            return None
        try:
            p = Path(path)
            if p.is_dir():
                filepaths = {}
                for pattern in ("*.yar", "*.yara"):
                    for f in p.glob(pattern):
                        filepaths[f.stem] = str(f)
                if not filepaths:
                    log.warning("No .yar/.yara rules in %s; scanner disabled", path)
                    return None
                return yara.compile(filepaths=filepaths)
            return yara.compile(filepath=str(p))
        except Exception as exc:  # noqa: BLE001 — bad rules must not crash the agent
            log.warning("YARA rule compilation failed (%s); scanner disabled", exc)
            return None

    # -- scanning ---------------------------------------------------------
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

    def _scan_file(self, path: Path) -> None:
        try:
            matches = self._rules.match(filepath=str(path))
        except Exception as exc:  # noqa: BLE001 — one bad file can't stop the scan
            log.debug("YARA match error on %s: %s", path, exc)
            return
        if not matches:
            return
        names = [getattr(m, "rule", str(m)) for m in matches]
        entry = None
        if self.quarantine is not None and getattr(self.config, "yara_quarantine", True):
            entry = self.quarantine.quarantine(path, reason=f"yara:{','.join(names)}")
        details = {"path": str(path), "rules": names}
        if entry:
            details["quarantine_id"] = entry.get("id")
        self.telemetry.emit(
            source="yara",
            action="quarantined" if entry else "match",
            severity="critical",
            summary=f"YARA rule(s) {', '.join(names)} matched '{path.name}'"
                    + (" (quarantined)" if entry else ""),
            details=details,
        )

    def scan(self) -> None:
        if not self.enabled:
            return
        files = self._list_files()
        if not self._baselined:
            self._seen = {str(p) for p in files}
            self._baselined = True
            return
        current: set[str] = set()
        for p in files:
            key = str(p)
            current.add(key)
            if key not in self._seen:
                self._scan_file(p)
        self._seen = current

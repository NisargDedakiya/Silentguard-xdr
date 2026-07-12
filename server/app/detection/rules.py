"""Behavioral detection rules (M8).

A rule is a small, declarative object: a predicate over an ``EventContext``
plus the severity, ATT&CK technique, and default response actions to apply when
it fires. Rules are pure and side-effect free — the engine (``engine.py``) runs
them, persists ``Detection`` rows, and dispatches responses.

The seed set covers the M8 scope: reverse shells, suspicious listeners,
PowerShell abuse, encoded commands, and LOLBin execution. The reverse-shell and
suspicious-listener rules fire on telemetry the agent already emits today; the
command-line rules fire once a process/command-line monitor feeds them
(delivered in M12, exercised directly by tests now).
"""
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Base risk contribution per severity (the weighted risk model).
SEVERITY_SCORE: dict[Severity, int] = {
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}


class EventContext:
    """Read-only view of a telemetry event for rule matching."""

    def __init__(self, source: str, action: str, severity: str, summary: str,
                 details: dict[str, Any] | None):
        self.source = source or ""
        self.action = action or ""
        self.severity = severity or ""
        self.summary = summary or ""
        self.details = details or {}

    @property
    def command_line(self) -> str:
        """Best-effort command line / process text to match against."""
        d = self.details
        return str(d.get("command_line") or d.get("cmdline") or d.get("process") or "").lower()

    @property
    def haystack(self) -> str:
        """Everything matchable, lower-cased: summary + serialized details."""
        return (self.summary + " " + json.dumps(self.details, default=str)).lower()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    technique_id: str
    technique_name: str
    description: str
    matches: Callable[[EventContext], bool]
    # Response actions to apply when the rule fires. "alert" is always safe;
    # "isolate" is state-changing and gated by settings.detection_auto_isolate.
    responses: tuple[str, ...] = ("alert",)

    @property
    def risk_score(self) -> int:
        return SEVERITY_SCORE[self.severity]


# -- matchers -------------------------------------------------------------
_LOLBINS = (
    "certutil", "mshta", "regsvr32", "rundll32", "wmic", "bitsadmin",
    "msbuild", "installutil", "cscript", "wscript", "regsvcs", "regasm",
)
_PS_SUSPICIOUS = ("-nop", "-noni", "-w hidden", "-windowstyle hidden", "iex",
                  "invoke-expression", "downloadstring", "-enc", "frombase64string")
_ENCODED_MARKERS = ("-enc", "-encodedcommand", "frombase64string", "-e jab")


def _is_reverse_shell(ctx: EventContext) -> bool:
    return ctx.source == "port_watchdog" and ctx.action in ("killed", "kill_failed") \
        and "port" in ctx.details


def _is_suspicious_listener(ctx: EventContext) -> bool:
    return ctx.source == "port_watchdog" and ctx.action == "detected"


def _is_powershell_abuse(ctx: EventContext) -> bool:
    cl = ctx.command_line
    return "powershell" in cl and any(tok in cl for tok in _PS_SUSPICIOUS)


def _is_encoded_command(ctx: EventContext) -> bool:
    cl = ctx.command_line
    return any(marker in cl for marker in _ENCODED_MARKERS)


def _is_lolbin(ctx: EventContext) -> bool:
    cl = ctx.command_line
    return any(f"{b}." in cl or f"\\{b}" in cl or cl.strip().startswith(b) or f" {b} " in cl
               for b in _LOLBINS)


SEED_RULES: tuple[Rule, ...] = (
    Rule(
        id="reverse_shell", name="Reverse shell / unauthorized listener terminated",
        severity=Severity.CRITICAL, technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        description="A process opened a listener on a suspicious port and was killed.",
        matches=_is_reverse_shell, responses=("alert", "isolate"),
    ),
    Rule(
        id="suspicious_listener", name="New suspicious network listener",
        severity=Severity.MEDIUM, technique_id="T1571", technique_name="Non-Standard Port",
        description="A process opened an unexpected listening port.",
        matches=_is_suspicious_listener,
    ),
    Rule(
        id="powershell_abuse", name="Suspicious PowerShell invocation",
        severity=Severity.HIGH, technique_id="T1059.001", technique_name="PowerShell",
        description="PowerShell launched with evasion/download flags.",
        matches=_is_powershell_abuse,
    ),
    Rule(
        id="encoded_command", name="Encoded command line",
        severity=Severity.HIGH, technique_id="T1027",
        technique_name="Obfuscated Files or Information",
        description="A base64/encoded command was executed.",
        matches=_is_encoded_command,
    ),
    Rule(
        id="lolbin_execution", name="Living-off-the-land binary execution",
        severity=Severity.HIGH, technique_id="T1218",
        technique_name="System Binary Proxy Execution",
        description="A known LOLBin was used to proxy execution.",
        matches=_is_lolbin,
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in SEED_RULES}

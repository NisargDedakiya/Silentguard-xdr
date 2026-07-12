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
        """Everything matchable, lower-cased: summary + the raw command line +
        serialized details. The raw command line is included un-escaped so
        backslash path tokens (e.g. ``hklm\\sam``) match reliably (JSON
        serialization would double the backslashes)."""
        return (self.summary + " " + self.command_line + " "
                + json.dumps(self.details, default=str)).lower()


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


# -- M9 rule-pack matchers (keyword signatures over the event haystack) ---
def _any(text: str, *tokens: str) -> bool:
    return any(t in text for t in tokens)


def _all(text: str, *tokens: str) -> bool:
    return all(t in text for t in tokens)


def _is_credential_dumping(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _any(h, "mimikatz", "sekurlsa", "lsadump", "invoke-mimikatz") \
        or _all(h, "reg", "save", "hklm\\sam") \
        or _all(h, "comsvcs", "minidump")


def _is_lsass_access(ctx: EventContext) -> bool:
    h = ctx.haystack
    return "lsass" in h and _any(h, "procdump", "dump", "minidump", "comsvcs", "rundll32", "taskmgr")


def _is_dll_injection(ctx: EventContext) -> bool:
    return _any(ctx.haystack, "createremotethread", "virtualallocex",
                "writeprocessmemory", "ntmapviewofsection", "queueuserapc")


def _is_process_hollowing(ctx: EventContext) -> bool:
    h = ctx.haystack
    return "zwunmapviewofsection" in h or "process hollow" in h or "processhollow" in h \
        or _all(h, "setthreadcontext", "resumethread")


def _is_reflective_loading(ctx: EventContext) -> bool:
    return _any(ctx.haystack, "reflectivepeinjection", "reflective load",
                "reflectiveloader", "[reflection.assembly]::load")


def _is_wmi_persistence(ctx: EventContext) -> bool:
    return _any(ctx.haystack, "commandlineeventconsumer", "__eventconsumer",
                "__eventfilter", "activescripteventconsumer") \
        or _all(ctx.haystack, "wmi", "subscription")


def _is_task_persistence(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _all(h, "schtasks", "/create") or "new-scheduledtask" in h or "register-scheduledtask" in h


def _is_registry_persistence(ctx: EventContext) -> bool:
    h = ctx.haystack
    return "currentversion\\run" in h or _all(h, "reg", "add", "\\run") \
        or "userinit" in h and "reg" in h


def _is_service_creation(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _all(h, "sc", "create") or "new-service" in h or _all(h, "sc.exe", "binpath")


def _is_privilege_escalation(ctx: EventContext) -> bool:
    return _any(ctx.haystack, "bypassuac", "getsystem", "fodhelper", "eventvwr.exe",
                "sedebugprivilege", "token::elevate", "printnightmare")


def _is_lateral_movement(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _any(h, "psexec", "paexec", "winrs", "\\pipe\\", "smbexec", "wmiexec") \
        or _all(h, "wmic", "/node:") \
        or _all(h, "invoke-command", "-computername")


def _is_fileless_execution(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _any(h, "reflection.assembly", "reflectivepeinjection") \
        or _all(h, "iex", "downloadstring") \
        or _all(h, "invoke-expression", "net.webclient")


def _is_ransomware_behavior(ctx: EventContext) -> bool:
    h = ctx.haystack
    return _all(h, "vssadmin", "delete", "shadows") \
        or _all(h, "wbadmin", "delete") \
        or _all(h, "bcdedit", "recoveryenabled", "no") \
        or _all(h, "wmic", "shadowcopy", "delete")


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
    # -- M9 rule pack ----------------------------------------------------
    Rule(
        id="credential_dumping", name="Credential dumping",
        severity=Severity.CRITICAL, technique_id="T1003",
        technique_name="OS Credential Dumping",
        description="Tooling associated with credential theft was observed.",
        matches=_is_credential_dumping, responses=("alert", "isolate"),
    ),
    Rule(
        id="lsass_access", name="LSASS memory access",
        severity=Severity.CRITICAL, technique_id="T1003.001", technique_name="LSASS Memory",
        description="A process attempted to read/dump LSASS memory.",
        matches=_is_lsass_access, responses=("alert", "isolate"),
    ),
    Rule(
        id="dll_injection", name="Remote process / DLL injection",
        severity=Severity.HIGH, technique_id="T1055.001",
        technique_name="Dynamic-link Library Injection",
        description="Injection primitives (CreateRemoteThread/WriteProcessMemory) observed.",
        matches=_is_dll_injection,
    ),
    Rule(
        id="process_hollowing", name="Process hollowing",
        severity=Severity.HIGH, technique_id="T1055.012",
        technique_name="Process Hollowing",
        description="Section unmapping / thread-context manipulation of a target process.",
        matches=_is_process_hollowing,
    ),
    Rule(
        id="reflective_loading", name="Reflective code loading",
        severity=Severity.HIGH, technique_id="T1620",
        technique_name="Reflective Code Loading",
        description="In-memory reflective PE/assembly loading observed.",
        matches=_is_reflective_loading,
    ),
    Rule(
        id="wmi_persistence", name="WMI event-subscription persistence",
        severity=Severity.HIGH, technique_id="T1546.003",
        technique_name="WMI Event Subscription",
        description="A permanent WMI event consumer/filter was created.",
        matches=_is_wmi_persistence,
    ),
    Rule(
        id="task_persistence", name="Scheduled task persistence",
        severity=Severity.HIGH, technique_id="T1053.005", technique_name="Scheduled Task",
        description="A scheduled task was created for persistence/execution.",
        matches=_is_task_persistence,
    ),
    Rule(
        id="registry_persistence", name="Registry Run-key persistence",
        severity=Severity.HIGH, technique_id="T1547.001",
        technique_name="Registry Run Keys / Startup Folder",
        description="A Run/RunOnce or Userinit registry autostart was written.",
        matches=_is_registry_persistence,
    ),
    Rule(
        id="service_creation", name="Suspicious service creation",
        severity=Severity.HIGH, technique_id="T1543.003", technique_name="Windows Service",
        description="A new Windows service was created (common persistence).",
        matches=_is_service_creation,
    ),
    Rule(
        id="privilege_escalation", name="Privilege escalation attempt",
        severity=Severity.HIGH, technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        description="A known UAC-bypass / elevation technique was observed.",
        matches=_is_privilege_escalation, responses=("alert", "isolate"),
    ),
    Rule(
        id="lateral_movement", name="Lateral movement",
        severity=Severity.HIGH, technique_id="T1021", technique_name="Remote Services",
        description="Remote-execution tooling (PsExec/WMI/WinRM) targeting other hosts.",
        matches=_is_lateral_movement, responses=("alert", "isolate"),
    ),
    Rule(
        id="fileless_execution", name="Fileless / in-memory execution",
        severity=Severity.HIGH, technique_id="T1055",
        technique_name="Process Injection",
        description="Code executed from memory without touching disk.",
        matches=_is_fileless_execution,
    ),
    Rule(
        id="ransomware_behavior", name="Ransomware behavior (recovery inhibition)",
        severity=Severity.CRITICAL, technique_id="T1490",
        technique_name="Inhibit System Recovery",
        description="Shadow copies / backups deleted or recovery disabled — a strong "
                    "ransomware precursor.",
        matches=_is_ransomware_behavior, responses=("alert", "isolate"),
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in SEED_RULES}

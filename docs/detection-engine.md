# Behavioral Detection Engine (Module M8)

The detection engine evaluates ingested telemetry against a set of rules and
produces **detections** — findings with a severity, a weighted risk score, an
ATT&CK technique, and configurable response actions. It runs synchronously in
the telemetry-ingestion path and is side-effect-safe (a broken rule never drops
telemetry).

## Anatomy

- **`app/detection/rules.py`** — declarative `Rule` objects: `matches(ctx)`
  predicate + `severity` + `technique` + `responses`. Rules are pure.
- **`app/detection/engine.py`** — `evaluate_event()` runs every rule over a
  stored `ThreatEvent`, persists `Detection` rows, and `dispatch_responses()`
  applies each detection's response actions.
- **`detections` table** — org-scoped findings with triage `status`
  (`new` → `acknowledged` → `resolved`).

## Risk model

| Severity | Base risk score |
|---|---|
| low | 10 |
| medium | 30 |
| high | 60 |
| critical | 90 |

## Seed rules (M8 scope)

| Rule | Severity | ATT&CK | Fires on |
|---|---|---|---|
| `reverse_shell` | critical | T1059 | `port_watchdog` kill of a listener on a suspicious port |
| `suspicious_listener` | medium | T1571 | `port_watchdog` detects a new listening port |
| `powershell_abuse` | high | T1059.001 | command line contains `powershell` + evasion/download flags |
| `encoded_command` | high | T1027 | `-enc` / `-EncodedCommand` / `FromBase64String` |
| `lolbin_execution` | high | T1218 | a known LOLBin (certutil, mshta, regsvr32, rundll32, wmic, …) |

The first two fire on telemetry the agent **already emits today**; the
command-line rules activate once a process/command-line monitor feeds
`details.command_line` (agent work in M12).

### M9 rule pack

| Rule | Severity | ATT&CK | Signature |
|---|---|---|---|
| `credential_dumping` | critical | T1003 | mimikatz / sekurlsa / lsadump / `reg save hklm\sam` / comsvcs minidump |
| `lsass_access` | critical | T1003.001 | `lsass` + dump/procdump/comsvcs/rundll32 |
| `dll_injection` | high | T1055.001 | CreateRemoteThread / WriteProcessMemory / VirtualAllocEx |
| `process_hollowing` | high | T1055.012 | ZwUnmapViewOfSection / SetThreadContext+ResumeThread |
| `reflective_loading` | high | T1620 | Invoke-ReflectivePEInjection / `[Reflection.Assembly]::Load` |
| `wmi_persistence` | high | T1546.003 | CommandLineEventConsumer / `__EventFilter` |
| `task_persistence` | high | T1053.005 | `schtasks /create` / New-ScheduledTask |
| `registry_persistence` | high | T1547.001 | `CurrentVersion\Run` / `reg add …\Run` |
| `service_creation` | high | T1543.003 | `sc create` / New-Service |
| `privilege_escalation` | high | T1548 | bypassuac / getsystem / fodhelper / SeDebugPrivilege |
| `lateral_movement` | high | T1021 | PsExec / `wmic /node:` / WinRM / smbexec |
| `fileless_execution` | high | T1055 | IEX+DownloadString / Reflection.Assembly |
| `ransomware_behavior` | critical | T1490 | `vssadmin delete shadows` / `wbadmin delete` / `bcdedit … recoveryenabled no` |

Rules match keyword signatures over an event "haystack" (summary + raw command
line + serialized details, lower-cased). The critical rules ship the `isolate`
response (still gated by `SG_DETECTION_AUTO_ISOLATE`).

## Responses

Each rule declares response actions (default `("alert",)`):

- **`alert`** — fires the M5 alerting integration for **critical** detections
  (Slack/Discord/email); always safe and non-blocking.
- **`isolate`** — state-changing; queues device isolation. **Gated** behind
  `SG_DETECTION_AUTO_ISOLATE=1` and only for critical detections. **Off by
  default** so nothing auto-isolates without an explicit opt-in.

## API

| Method | Path | Permission |
|---|---|---|
| GET | `/api/admin/detections?device_id=&status=&severity=&limit=` | `read:fleet` |
| POST | `/api/admin/detections/{id}/ack` | `write:detections` |
| POST | `/api/admin/detections/{id}/resolve` | `write:detections` |

`write:detections` is held by super-admin, SOC manager, analyst, threat hunter,
and responder (not read-only / auditor). Triage transitions are audit-logged.
New detections are broadcast on the dashboard WebSocket as `type: "detection"`.
All detection data is org-scoped (M6).

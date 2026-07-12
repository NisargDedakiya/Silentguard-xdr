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
`details.command_line` (agent work in M12). Additional rule packs
(credential dumping, LSASS, injection, persistence, lateral movement,
ransomware behavior) arrive in **M9**.

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

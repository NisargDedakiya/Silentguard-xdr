# YARA File Scanning (v1.3)

[YARA](https://virustotal.github.io/yara/) is the industry-standard engine for
signature-based malware identification. The agent can scan newly-dropped files
against a YARA rule set and turn matches into detections, so a SOC can ship its
own or vendor rule packs to the fleet.

## Enabling it (agent)

| Variable | Purpose | Default |
|---|---|---|
| `SG_YARA_ENABLED` | Master switch | `0` (off) |
| `SG_YARA_RULES` | Path to a `.yar`/`.yara` file **or** a directory of them | *(empty)* |
| `SG_YARA_QUARANTINE` | Quarantine (move, not delete) a matched file | `1` (on) |

The scanner is **inert** unless enabled with a rules path **and** the
`yara-python` package is installed. Any missing piece — switch off, no rules,
package absent, or a rule that fails to compile — degrades to a clean no-op; the
agent never fails to start because YARA isn't set up. `yara-python` is
intentionally **not** a hard dependency (it needs the native libyara), so it is
installed only where YARA scanning is wanted.

It reuses the file-drop watch directories (`config.file_drop_dirs`) and is
baseline-aware: the first scan records existing files silently, then only
newly-appearing files are scanned each cycle.

## What a match produces

On a match the agent emits telemetry:

```
source="yara" action="quarantined"|"match" severity="critical"
details = { path, rules: [<rule names>], quarantine_id? }
```

The server's built-in **`yara_match`** detection rule turns any such event into a
`critical` detection mapped to **T1105 (Ingress Tool Transfer)** — so YARA hits
flow through triage, alerting, integrations, and AI explanation like any other
detection. When `SG_YARA_QUARANTINE` is on and a quarantine manager is present,
the matched file is moved to the quarantine store (restorable), and the action
is `quarantined`; otherwise it is reported as `match`.

## Testing

- **Agent:** `agent/tests/test_yara_scanner.py` injects a fake compiled-rules
  object (no native libyara needed) to cover the disabled/no-op paths, baseline
  silence, match → report + quarantine, non-match ignore, match-without-
  quarantine, and de-duplication.
- **Server:** `test_detection.py::test_yara_match_telemetry_creates_detection`
  drives a YARA event through ingestion and asserts the `yara_match` detection.

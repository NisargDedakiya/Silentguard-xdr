# Registry Autorun Monitor (v1.3)

Watches the Windows **Run / RunOnce** registry keys — the classic persistence
foothold (MITRE **T1547.001**, Registry Run Keys / Startup Folder) — and reports
new or changed autorun entries. This is the agent-side data source that the
server's `registry_persistence` detection rule was written to consume (the M9
rule comment literally reads "populated by M12").

## Watched keys

| Hive | Subkey |
|---|---|
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` |
| HKCU | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| HKCU | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` |

## Behavior

- **Windows-only:** registry access uses stdlib `winreg`. On Linux/macOS the
  monitor is a clean no-op (`enabled = False`), so the same agent build ships to
  every OS. Toggle with `SG_REGISTRY_ENABLED` (default on; only affects Windows).
- **Baseline-aware:** the first scan records existing autoruns silently, so a
  restart never replays them.
- Each subsequent scan diffs the snapshot and emits telemetry for **added** or
  **changed** values:

```
source="registry_monitor" action="autorun_added"|"autorun_changed" severity="warning"
summary="Registry autorun added: HKCU\...\CurrentVersion\Run\Evil -> C:\temp\evil.exe"
details = { key, name, command_line }
```

The full key path is placed in the **summary** (raw, single-backslash) so the
server rule matches reliably — JSON serialization of `details` would double the
backslashes.

## Detection

No new server rule is needed: the existing **`registry_persistence`** rule
(`T1547.001`, high) matches the `currentversion\run` key path in the event, so a
reported autorun becomes a detection that flows through triage, alerting,
integrations, and AI explanation. The events also populate the **registry**
timeline category in analytics.

## Testing

`agent/tests/test_registry_monitor.py` injects snapshot sequences (no real
`winreg` needed) to cover off-Windows inertness, baseline silence, new/changed
autorun reporting, and the unchanged-is-silent case.
`test_detection.py::test_registry_autorun_creates_persistence_detection` covers
the ingestion → `registry_persistence` detection path.

# Process Execution Monitor (Module M12a)

The keystone that lets the detection engine **catch real attacks**: the agent
enumerates running processes and reports each newly-seen one with its full
command line, so the server-side rule packs actually have data to match.

## Agent side

`silentguard_agent/monitors/process_monitor.py` runs each poll cycle. For every
process not seen in the previous scan it emits:

```
source="process" action="exec" severity="info"
details = { pid, ppid, name, user, command_line, exe }
```

- **Cross-platform (Stage 5):** psutil supplies `cmdline`/`ppid`/`username` on
  Windows, Linux, and macOS, so one monitor serves every OS.
- **Baseline-aware:** the first scan records existing processes silently.
- **Bounded:** at most `max_events_per_scan` (default 50) new processes per
  cycle, so a fork storm can't flood telemetry.

## What it activates (server side, already built)

The `command_line` field feeds the M8/M9 detection rules with no server change:

- PowerShell abuse, encoded commands, LOLBins
- credential dumping, LSASS access
- DLL injection, process hollowing, reflective loading
- WMI/scheduled-task/registry/service persistence
- privilege escalation, lateral movement, fileless execution, ransomware behavior

The `pid`/`ppid` fields populate the **process-tree** view
(`GET /api/admin/analytics/process-tree`) and the `process` **timeline**
category.

## Verified

`tests/test_detection.py::test_process_telemetry_end_to_end_detections` drives a
PowerShell + certutil process event through ingestion and asserts the
`powershell_abuse`, `encoded_command`, and `lolbin_execution` rules all fire —
the full agent-monitor → telemetry → rule-engine → detection path.

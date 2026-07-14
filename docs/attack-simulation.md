# End-to-End Attack Simulation (quality gate)

`server/tests/test_attack_simulation.py` is an integration test that drives a
realistic, multi-stage intrusion through the **entire** platform and asserts the
kill chain is detected end to end — the "realistic attack simulation" quality
gate. It ties every layer together in one run: agent enrolment → telemetry
ingestion → detection engine → triage → analytics → compliance.

## The simulated kill chain

| # | ATT&CK stage | Simulated telemetry | Detection |
|---|---|---|---|
| 1 | Execution | `powershell -nop -w hidden -enc …` | `powershell_abuse`, `encoded_command` |
| 2 | Execution (LOLBin) | `certutil.exe -urlcache -f http://…` | `lolbin_execution` (T1218) |
| 3 | Credential access | `rundll32 … comsvcs.dll, MiniDump … lsass` | `credential_dumping` + Sigma `sigma:custom-lsass-1` |
| 4 | Persistence | Run-key autorun (registry monitor) | `registry_persistence` (T1547.001) |
| 5 | Command & control | Suricata IDS alert | `suricata_alert` (T1071) |
| 6 | Malware on disk | YARA match | `yara_match` (T1105) |
| 7 | Defense evasion | Agent tamper attempt | `tamper_detected` (T1562.001) |
| 8 | Impact | `vssadmin delete shadows /all /quiet` | `ransomware_behavior` (T1490) |
| 9 | Contained | Reverse-shell listener killed | `reverse_shell` (T1059) |

## What it verifies

1. **Detection coverage** — every stage produces its expected detection, including
   the custom-monitor server rules (registry / YARA / Suricata / tamper) and a
   **SOC-supplied Sigma rule** evaluated alongside the built-ins.
2. **MITRE breadth** — the analytics coverage spans execution, credential access,
   persistence, C2, evasion, and impact tactics.
3. **Triage + compliance loop** — the compliance report's `critical_backlog`
   control flips to **fail** while criticals are open, the analyst acknowledges
   and resolves each detection, and the control returns to **pass** — proving the
   operational loop closes, not just that alerts fire.

This test is the regression anchor for the whole detection surface: adding or
changing a rule or monitor is validated against a full attack narrative, not just
a unit case.

# Sigma Rule Support (v1.3)

[Sigma](https://sigmahq.io/) is the open, vendor-neutral signature format SOC
teams use to write and share detections. SilentGuard now **evaluates** Sigma
rules against live telemetry — previously they could be stored and distributed
but never fired a detection.

## Using it

Add a Sigma rule as an intel rule of `kind: "sigma"`:

```
POST /api/admin/intel/rules
{ "kind": "sigma", "name": "ps-enc", "content": "<sigma YAML>", "enabled": true }
```

The rule's YAML is validated on ingestion — an uncompilable rule is rejected
with `400 invalid Sigma rule: …` so bad rules never reach the engine. Enabled
Sigma rules (org-scoped, plus global rules with no org) are evaluated on every
telemetry event by the detection engine. A match produces a normal `Detection`
with `rule_id = "sigma:<rule id or title>"`, the rule's severity, and its ATT&CK
technique — indistinguishable downstream from a built-in detection (triage,
alerting, integrations, AI explanation all work on it).

Evaluation is gated by `SG_SIGMA_ENABLED` (default **on**; inert until rules are
added). Compilation is cached by content hash, so YAML is parsed once per rule
body rather than per event.

## Supported subset

The engine maps the part of Sigma that fits endpoint telemetry:

| Sigma feature | Support |
|---|---|
| `detection` selections (mapping) | ✅ `Field: value`, AND across fields |
| Selection value lists | ✅ OR by default, AND with the `|all` modifier |
| Keyword lists (bare list) | ✅ OR against the whole event |
| Field modifiers | ✅ `contains`, `startswith`, `endswith`, `re`, equality (default) |
| `condition` | ✅ `and` / `or` / `not`, parentheses |
| Aggregate conditions | ✅ `N of them`, `all of them`, `1 of prefix*` |
| `level` | ✅ → severity (`informational/low` → low … `critical` → critical) |
| `tags` | ✅ first `attack.tXXXX` → ATT&CK technique id |
| Correlation / count/timeframe aggregations | ⛔ out of scope (single-event engine) |

String matching is case-insensitive, per the Sigma spec. Fields the agent does
not report (e.g. Windows-only event fields) simply never match — they cannot
raise a false positive.

### Field mapping

Common process fields resolve to the agent's telemetry: `CommandLine`, `cmdline`,
`Image`, `Process`, `OriginalFileName`, `TargetObject`, `TargetFilename` → the
event's command line; `ProcessName` / `Name` → the process name. Any other field
is looked up case-insensitively in the event `details`.

## Example

```yaml
title: Suspicious PowerShell Encoded Command
id: ps-enc-1
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - 'downloadstring'
  condition: selection
```

Feeding a `powershell -nop -enc SQBFAFgA` process event produces a `high`
detection `sigma:ps-enc-1` mapped to `T1059.001`.

## Testing

`server/tests/test_sigma.py` covers metadata extraction, every modifier, `and` /
`or` / `not` and `N of them` conditions, keyword lists, invalid-rule rejection,
the disabled-rule case, and the full ingestion → detection path.

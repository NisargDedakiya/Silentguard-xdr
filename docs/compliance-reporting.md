# Compliance & Executive Reporting (v1.4)

A single, org-scoped posture report a SOC manager or auditor can hand to
leadership — fleet health, detection backlog, threat-intel coverage, and a set
of pass/warn/fail **control checks** with a headline compliance score. No
external GRC tooling required.

## Endpoint

```
GET /api/admin/analytics/compliance-report?days=30
```

- **Permission:** `READ_AUDIT` (held by `auditor`, `soc_manager`, `super_admin`).
  Read-only, org-scoped — a tenant sees only its own posture.
- **`days`** (1–365, default 30) bounds the detection window.

## Report shape

```json
{
  "generated_at": "2026-07-12T10:00:00+00:00",
  "window_days": 30,
  "org_id": "…",
  "score": 75,
  "controls_summary": {"pass": 6, "warn": 2, "fail": 0},
  "fleet": {
    "total_devices": 42, "online": 40, "offline": 2, "isolated": 1,
    "reporting_pct": 95, "agent_versions": {"0.1.0": 42}
  },
  "detections": {
    "window_total": 18, "by_severity": {"critical": 2, "high": 5},
    "by_status": {"new": 3, "resolved": 15}, "open_critical": 0,
    "resolved_rate_pct": 83
  },
  "intel": {"iocs": 12, "sigma_rules": 3, "yara_rules": 1},
  "controls": [{"id": "…", "title": "…", "status": "pass", "detail": "…"}]
}
```

## Control checks

The score is `pass = full, warn = half, fail = none`, averaged over the controls:

| Control | Passes when |
|---|---|
| `strong_authentication` | A dedicated `SG_JWT_SECRET` is set (not derived from the admin token) |
| `transport_security` | HSTS is enabled (`SG_HSTS_ENABLED`) |
| `token_exposure` | Reset/verify tokens are **not** exposed in production responses |
| `request_size_guard` | The request body-size guard is enabled |
| `sigma_detection` | Custom Sigma evaluation is on |
| `fleet_reporting` | Every enrolled device has checked in recently |
| `critical_backlog` | No unresolved (`new`/`acknowledged`) critical detections |
| `detection_content` | At least some IOCs / Sigma / YARA content is loaded |

The first five are configuration controls (derived from `settings`); the last
three are data-driven (derived from the live fleet and detection state), so the
report reflects real operational posture, not just config.

## Testing

`server/tests/test_compliance.py` covers the report structure and score bounds,
the `critical_backlog` control flipping fail→pass as a detection is resolved,
the `detection_content` control reflecting added IOCs, and RBAC (auditor allowed,
read-only denied).

# Response Action Framework (Module M14)

A single endpoint dispatches response actions against a device. **Every action
produces an immutable `ResponseAction` record and an audit-log entry.**

## Actions

| Action | Execution | Effect |
|---|---|---|
| `block_domain` | server (immediate) | add domain to the org blocklist |
| `block_ip` | server (immediate) | add IP as an IOC (confidence 90) |
| `block_hash` | server (immediate) | add SHA-256 as an IOC (confidence 90) |
| `kill_process` | agent (queued) | kill by `pid` or `name` |
| `delete_file` | agent (queued) | **quarantine** the file (move, not destroy) |
| `restore_file` | agent (queued) | restore a quarantined file |
| `remote_scan` | agent (queued) | on-demand host scan |
| `remote_update` | agent (queued) | acknowledge an agent-update request |
| `isolate` / `release` | agent (queued) | network isolation |

Server-executed actions complete synchronously (`status: completed`).
Agent-executed actions queue a check-in command (correlated by `action_id`) and
stay `queued` until the agent reports a `response`/`result` telemetry event,
which transitions them to `completed`/`failed`.

## API

| Method | Path | Permission |
|---|---|---|
| POST | `/api/admin/devices/{id}/respond` (`{action, params}`) | `execute:response` |
| GET | `/api/admin/responses?device_id=&status=` | `read:fleet` |

`execute:response` is part of the responder permission set (super-admin, SOC
manager, responder). All dispatches are org-scoped and audited as
`response:<action>`.

## Agent side

`silentguard_agent/response_handlers.py` executes queued actions best-effort,
honoring `dry_run`, and reports each result back via a
`response`/`result` telemetry event carrying `{action_id, status, …}`.
`delete_file` intentionally routes through quarantine so a destructive response
is still recoverable.

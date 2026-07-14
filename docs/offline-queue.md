# Durable Offline Telemetry Queue (v1.2)

Endpoints do not always have connectivity to the management server — laptops go
offline, links flap, the server restarts. The agent must not lose the security
events it captured during those gaps, **even across an agent restart or a
device reboot**.

## Behavior

The `TelemetryClient` buffers events in memory and flushes them in batches. That
buffer is now mirrored to a disk spool:

- **`~/.silentguard/telemetry_queue.json`** (override the directory with
  `SG_STATE_DIR`), written with owner-only (`0600`) permissions.
- On **every `emit()`** the spool is rewritten, so a crash right after capture
  still leaves the event on disk.
- On **startup** the client recovers the spool into its buffer, so a restart
  mid-outage resumes exactly where it left off.
- On a **successful flush** the spool is shrunk to match what remains
  undelivered (empty once everything is sent), so it never grows without bound.
- Recovery and the live buffer are both bounded to `MAX_BUFFER` (5000) events —
  the oldest are dropped first if an outage runs long, matching the in-memory
  `deque(maxlen=…)` policy.

The spool is best-effort: any file-system error while persisting is swallowed so
telemetry capture never fails because the disk is full or read-only — delivery
simply falls back to the in-memory buffer for that cycle.

## Guarantees

| Scenario | Before | Now |
|---|---|---|
| Server unreachable, agent keeps running | Buffered in memory | Buffered in memory **+ on disk** |
| Agent restarts while offline | Buffered events lost | Recovered from the spool |
| Device reboots mid-outage | Buffered events lost | Recovered from the spool |
| Very long outage | Oldest events dropped past 5000 | Same (bounded), but survives restarts |

## Testing

`agent/tests/test_telemetry_queue.py` verifies emit persists to disk, events
survive a simulated restart while the server is unreachable, a successful flush
clears the spool, and recovery is bounded to `MAX_BUFFER`.

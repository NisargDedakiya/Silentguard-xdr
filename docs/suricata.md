# Suricata IDS Integration (v1.5)

The agent can tail a [Suricata](https://suricata.io/) `eve.json` log and forward
each network **alert** into SilentGuard, so IDS detections appear on the same
timeline as endpoint detections — the network and host pictures land in one XDR
view.

## Enabling it (agent)

| Variable | Purpose | Default |
|---|---|---|
| `SG_SURICATA_ENABLED` | Master switch | `0` (off) |
| `SG_SURICATA_EVE` | Path to Suricata's `eve.json` | `/var/log/suricata/eve.json` |

Run Suricata with the `eve-log` output enabled (its default JSON event log). The
agent reads the file; no Suricata configuration change is needed beyond having
`eve.json` written.

## Behavior

The monitor follows the log incrementally like `tail -f`:

- **First scan seeds the offset at end-of-file**, so historical alerts are not
  replayed when the agent starts.
- Only `event_type: "alert"` records are forwarded; flow/dns/stats events and
  malformed lines are skipped.
- **Log rotation/truncation** (file shrinks below the read offset) resets to the
  top so the new file is read from the beginning.
- Bounded to `max_events_per_scan` (default 100) so an alert storm can't flood
  telemetry.

Each alert becomes telemetry:

```
source="suricata" action="alert" severity="warning"
details = { signature, signature_id, category, suricata_severity,
            src_ip, dest_ip, dest_port, proto }
```

The server's built-in **`suricata_alert`** rule turns it into a `high` detection
mapped to **T1071 (Application Layer Protocol)**, so network IDS hits flow
through triage, alerting, integrations, and AI explanation like any detection.

## Testing

`agent/tests/test_suricata_monitor.py` covers the disabled no-op, baseline
skipping of existing alerts, forwarding a new alert with parsed fields,
ignoring non-alert and malformed lines, no replay across scans, log-rotation
offset reset, and per-scan bounding. `test_detection.py::test_suricata_alert_creates_detection`
covers the server ingestion → detection path.

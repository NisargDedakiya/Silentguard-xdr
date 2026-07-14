# Visibility & Analytics (Module M17)

Server-side aggregations over the telemetry, detection, device, and IOC data,
all read-only (`read:fleet`) and org-scoped. Aggregation is done in Python over
a time-bounded window so it is portable across SQLite and Postgres; DB-side
aggregation for very large fleets is deferred to M20.

## Endpoints (`/api/admin/analytics`)

| Path | Returns |
|---|---|
| `GET /summary` | fleet rollup: device/online/isolated counts, event & detection totals, detections by status/severity, open critical count, IOC count |
| `GET /events-by-day?days=14` | per-day event counts split by severity (threat-trend / heatmap source) |
| `GET /top-devices?limit=10` | devices ranked by summed detection risk score |
| `GET /mitre-coverage` | ATT&CK technique → detection count |
| `GET /timeline?category=…` | events for a category: `usb`, `network`, `registry`, `process`, `quarantine` |
| `GET /process-tree?device_id=…` | best-effort process ancestry from events carrying `pid`/`ppid` |

## Notes

- **Timelines** map a category to its telemetry sources (e.g. `network` →
  arp_guard/dns_sinkhole/port_watchdog). The `registry` category is wired for
  the registry monitor delivered in M12.
- **Process tree** assembles a parent/child forest from any events whose details
  include `pid`/`ppid`; it fully populates once the process monitor (M12) emits
  those fields, and returns whatever is available today.
- These endpoints back the enterprise dashboards (M19) and executive reporting;
  the existing client-side analytics tab continues to work unchanged.

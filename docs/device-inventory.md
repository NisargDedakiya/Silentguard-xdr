# Device Inventory & Posture (Module M13)

Each agent periodically reports a hardware/software/services/users snapshot; the
server stores the latest per device and derives a coarse security posture.

## Agent side

`silentguard_agent/inventory.py` collects (via `psutil` + `platform`, every
`SG_INVENTORY_INTERVAL` seconds, default 300) and POSTs to
`/api/agent/inventory`:

- OS version, kernel, CPU model, logical CPU count
- total RAM (MB), total/free disk (GB)
- running services (process list snapshot), logged-in users

Every probe is defensive — a failing section yields an empty/zero value rather
than aborting the report. (Full installed-software enumeration is OS-specific
and deferred to the OS adapters in M11/M12.)

## Server side

`device_inventory` table (one row per device, upserted). On each report the
posture is recomputed (`app/services/inventory.py`):

| Check | Meaning |
|---|---|
| `disk_ok` | free disk ≥ 10% |
| `agent_up_to_date` | agent version matches the current release |
| `not_isolated` | device is not under isolation |

`health` is `healthy` when all checks pass, else `degraded`; `posture` records
`disk_free_pct`, the check results, and the list of failing `issues`.

## API

`GET /api/admin/devices/{id}/inventory` (`read:fleet`, org-scoped) returns the
latest `InventoryOut`, or 404 if the device has not reported yet.

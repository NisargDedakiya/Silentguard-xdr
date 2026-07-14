# Threat Intelligence (Module M10)

An org-scoped IOC store that doubles as the local match cache, plus YARA/Sigma
rule distribution. Indicators extracted from telemetry are matched against the
store by the detection engine, producing `ioc_match` detections.

## IOC store

`iocs` table — org-scoped, unique per `(org_id, ioc_type, value)`:

| Field | Notes |
|---|---|
| `ioc_type` | `domain` \| `ip` \| `url` \| `sha256` \| `certificate` |
| `value` | normalized (lower-cased except raw IPs) |
| `confidence` | 0–100 |
| `source` | feed name or `manual` |
| `expires_at` | optional; expired IOCs are ignored by lookups and prunable |

## API

| Method | Path | Permission |
|---|---|---|
| GET | `/api/admin/intel/iocs?ioc_type=&limit=` | `read:fleet` |
| POST | `/api/admin/intel/iocs` | `manage:intel` |
| POST | `/api/admin/intel/iocs/import` (`{source, iocs:[…]}`) | `manage:intel` |
| DELETE | `/api/admin/intel/iocs/{id}` | `manage:intel` |
| GET | `/api/admin/intel/rules?kind=&enabled_only=` | `read:fleet` |
| POST | `/api/admin/intel/rules` (YARA/Sigma) | `manage:intel` |
| DELETE | `/api/admin/intel/rules/{id}` | `manage:intel` |

`manage:intel` is held by super-admin, SOC manager, and threat hunter. All
mutations are audit-logged.

## Feed import & auto-update

- **Manual/programmatic:** `POST …/iocs/import` with a list of
  `{type, value, confidence?, description?, expires_at?}`.
- **Startup feed:** set `SG_INTEL_FEED_FILE=/path/feed.json` (a list, or
  `{"iocs":[…]}`) to import into the default org on boot. A scheduled job can
  re-run the same import for "auto-update"; imports are idempotent (upsert).

## Detection integration

On every ingested telemetry event, the engine extracts indicators
(`details.domain`/`url`/`sha256`/`hash`/`ip`/`remote_ip`/`dest_ip`/`gateway`)
and looks each up in the org's IOC store. A hit yields an `ioc_match` detection:

- severity from confidence: ≥80 critical, ≥50 high, else medium;
- ATT&CK technique by indicator type (domain→T1071.004, url→T1071.001,
  sha256→T1105, …);
- the IOC value, source, and confidence recorded in the detection details.

## YARA / Sigma distribution

`intel_rules` stores named YARA/Sigma rule bodies (`kind`, `content`,
`enabled`). Consumers (agent scanners, external tooling) fetch them via
`GET /api/admin/intel/rules`. Storage/serving only — evaluation is the
responsibility of the consuming scanner.

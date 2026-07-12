# Platform Integrations & Exports (Module M18)

Generalizes the M5 critical-only alerting into configurable, per-org outbound
integrations that forward events and detections to SIEM/SOAR/chat/syslog
destinations, plus REST exports for pull-based SIEM ingestion.

## Integrations

`integrations` table (org-scoped). Each has a `kind`, a `config` blob, and a
`min_severity` threshold; enabled integrations at or above the threshold receive
every ingested event and detection.

| Kind | Delivery | Config |
|---|---|---|
| `webhook` | JSON POST | `url`, optional `headers` |
| `slack` / `discord` / `teams` | chat POST (`text`+`content`) | `url` |
| `splunk_hec` | HEC JSON POST | `url`, `token` |
| `syslog` | UDP CEF line | `host`, `port` (default 514) |

Delivery is **best-effort and non-blocking** — every send is wrapped; a failing
destination is logged and swallowed so ingestion never stalls.

## Management API

| Method | Path | Permission |
|---|---|---|
| GET | `/api/admin/integrations` | `read:fleet` |
| POST | `/api/admin/integrations` | `manage:integrations` |
| DELETE | `/api/admin/integrations/{id}` | `manage:integrations` |
| POST | `/api/admin/integrations/{id}/test` | `manage:integrations` |

`manage:integrations` is held by super-admin and SOC manager.

## Exports

`GET /api/admin/export/events?format=ndjson|cef&limit=` (`read:fleet`,
org-scoped) returns recent events as newline-delimited JSON or ArcSight **CEF**
lines — suitable for Splunk/Elastic/Sentinel/QRadar pull ingestion or
file-based forwarding.

## Formatters

`app/services/integrations.py` provides `format_generic` (JSON),
`format_chat` (Slack/Discord/Teams), `format_splunk_hec`, and `format_cef`
(CEF with field escaping). SOAR platforms (Cortex XSOAR, Shuffle, Tines) consume
the generic webhook JSON.

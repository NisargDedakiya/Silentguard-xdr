# Multi-Tenancy (Module M6)

Every piece of domain data (devices, threat events, quarantine items, blocklist
entries, audit records, users) is scoped to an **organization** (`org_id`).
Reads and writes are confined to the caller's org; a cross-org principal
(super-admin or the legacy admin token) spans all organizations, preserving the
pre-M6 single-admin experience.

## Model

- `organizations` table: `id`, `name`, `slug`, `is_active`, `created_at`.
- `org_id` FK column (nullable, indexed) on `devices`, `threat_events`,
  `quarantine_items`, `blocklist`, `audit_log`, `users`.
- Blocklist uniqueness is now **per-org** (`uq_blocklist_org_value`) — the same
  value can be blocked independently in different tenants.

## The default organization

A well-known org (`DEFAULT_ORG_ID = 000…001`, "Default Organization") is created
on startup (`ensure_default_org`) and by the M6 migration. All pre-existing rows
are backfilled into it, and new devices/users join it unless another org is
specified. With a single org present, behavior is identical to before M6.

## Scoping rules

| Principal | Scope |
|---|---|
| super-admin (JWT) | **cross-org** — sees/acts on every organization |
| legacy `X-Admin-Token` | **cross-org** (backward compatibility) |
| any other role | confined to the user's `org_id` |

Implemented by `app/services/tenancy.py`:

- `scope_query(query, org_column, principal)` — adds `WHERE org_id = …` unless
  the principal is cross-org.
- `owning_org(principal)` — the org a write belongs to (the principal's org, or
  the default org for a cross-org caller).

Cross-tenant access to a specific object (e.g. isolating another org's device)
returns **404**, not 403, so object existence does not leak across tenants.

## Agent data path

Devices enroll into the default org; their telemetry, quarantine items, and
`device_unresponsive` alerts inherit the device's `org_id`. A checked-in agent
receives **only its own org's** blocklist.

## Migration & backfill

`3976409257c3_add_organizations_and_org_id_scoping` creates the table + columns,
inserts the default org, and backfills every existing row's `org_id` to it —
verified against a database seeded with pre-M6 data. The migration is additive
and non-destructive.

## Known follow-up

The pre-M6 global `UniqueConstraint('value')` on `blocklist` is retained by the
migration (harmless while only the default org exists, since global-unique and
per-org-unique coincide). When an org-provisioning API is added (enterprise
management module), a follow-up migration will drop the global constraint so the
same value can be blocked in multiple tenants in production too. (The ORM models
and the SQLite `create_all` demo path already use only the per-org constraint.)

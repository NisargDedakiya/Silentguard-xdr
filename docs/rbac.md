# Role-Based Access Control (Module M5)

M5 enforces per-endpoint permissions across the admin API using the seven roles
introduced in M4. Each authenticated caller resolves to a `Principal` (audit
actor + role); endpoints declare the permission they need.

## Permissions

| Permission | Grants |
|---|---|
| `read:fleet` | list devices, events, quarantine, blocklist, device scores |
| `read:audit` | read the audit log |
| `write:isolation` | isolate / release a device |
| `write:blocklist` | add / remove blocklist entries |
| `write:quarantine` | restore a quarantined file |
| `manage:users` | create / list / disable users |

## Role → permission matrix

| Role | read:fleet | read:audit | write:isolation | write:blocklist | write:quarantine | manage:users |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **super_admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **soc_manager** | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| **analyst** | ✅ | ✅ | — | — | — | — |
| **threat_hunter** | ✅ | ✅ | — | — | — | — |
| **responder** | ✅ | — | ✅ | ✅ | ✅ | — |
| **auditor** | ✅ | ✅ | — | — | — | — |
| **read_only** | ✅ | — | — | — | — | — |

Defined in `app/core/permissions.py`; adjust the matrix there.

## Enforcement

Endpoints depend on `require_permission(<Permission>)` (in `app/auth.py`), which
authenticates the caller and returns the `Principal`, or raises:

- **401** when no valid JWT / legacy token is present,
- **403** `Role '<role>' lacks permission '<permission>'` when authenticated but
  unauthorized.

## Backward compatibility

The legacy `X-Admin-Token` resolves to **super_admin**, so every existing
integration keeps full access unchanged. JWT callers get exactly their role's
permissions.

## Managing users

Super-admins (or the legacy token) manage accounts under `/api/admin/users`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/users` | list accounts |
| POST | `/api/admin/users` | create `{email, password, role}` |
| POST | `/api/admin/users/{id}/disable` | deactivate (immediately blocks that user's tokens) |

All three actions are recorded in the audit log.

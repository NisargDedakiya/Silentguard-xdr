# Plans, Organizations & Tenancy — Individual / Team / Enterprise

SilentGuard serves three audiences on one multi-tenant core. The audience is set
by an **organization's plan**, which drives feature entitlements. This keeps a
home user's experience simple while an enterprise gets the full platform.

## The three plans

| Capability | Individual | Team | Enterprise |
|---|---|---|---|
| Max devices | 5 | 50 | unlimited |
| Max members | 1 | 15 | unlimited |
| Device groups (departments) | — | ✅ (≤10) | ✅ unlimited |
| Role-based access (RBAC) | — | ✅ | ✅ |
| SIEM/SOAR/webhook integrations | — | ✅ | ✅ |
| Compliance/executive reports | — | ✅ | ✅ |
| SSO (OIDC) | — | — | ✅ |
| AI Security Assistant | ✅ | ✅ | ✅ |

Limits of `0` mean unlimited. An org-level `max_devices` override wins over the
plan default when set. The matrix lives in `app/core/plans.py`.

> The built-in **default organization is Enterprise**, so a fresh install and all
> existing behavior are fully unlocked; extra orgs choose their own plan. A
> request whose org can't be resolved also falls back to Enterprise (never
> silently gated).

## Feature gating

Endpoints consult the plan before acting; over-limit or out-of-plan actions
return **HTTP 402** ("upgrade your plan"):

- Enroll beyond the device cap → 402
- Add a member beyond the seat cap → 402
- Create a device group on Individual → 402
- Create an integration on Individual → 402
- Compliance report on Individual → 402
- Change a member's role on Individual (no RBAC) → 402

Clients discover what's unlocked via **`GET /api/admin/entitlements`**, which
returns the caller org's plan and feature flags — use it to render the right UI.

## Buying & keys (Individual / Group / Enterprise)

Purchasing provisions an organization and hands the buyer **keys**:

```
POST /api/auth/provision { plan, org_name, admin_email? }
```

| Plan | Keys returned | Meaning |
|---|---|---|
| **Individual** | `admin_key` | Log into the dashboard. One user. |
| **Group** (team) | `admin_key` + `invite_key` | Admin logs in; members **join** with the invite key. |
| **Enterprise** | `admin_key` + `invite_key` | Admin manages + groups devices; invite key adds users. |

- **Admin key** (`sgk_…`) — `POST /api/auth/key-login { admin_key }` signs the
  buyer in as the org **Owner**. Stored hashed.
- **Invite / join key** (`join_…`) — shareable. `POST /api/auth/join
  { invite_key, email, password }` adds a member and signs them in. Shown to the
  admin (so they can share it) and used to **count members** for billing.

### Billing view

`GET /api/admin/subscription` (admin) returns the plan, the **invite key**, the
current **member count**, and the resulting **price**:

- Individual: flat `base_price` (\$9/mo).
- Group: `price_per_seat` (\$6) × members — so the invite-key joins drive the bill.
- Enterprise: `price_per_seat` (\$10) × members.

Enterprise admins group specific devices into departments (`/api/admin/groups`
+ `/api/admin/devices/{id}/group`) and manage each group's policy.

## The SaaS role model (like normal team software)

The lifecycle works the way people expect from Slack/GitHub/etc.:

1. **Sign up** — `POST /api/auth/signup { email, password, org_name, plan }`
   creates a **new organization** and makes you its **Owner**, then signs you in.
   Self-serve plans are `individual` and `team` (Enterprise is sales-led — a
   requested `enterprise` plan is coerced to `individual`).
2. **Owner** (`owner` role) has **full control of their own org** — manage
   members, policies, integrations, response — but is **org-scoped** (sees only
   their tenant) and cannot administer other organizations. The platform
   operator (`super_admin`) is the only cross-org role.
3. **Invite teammates** — `POST /api/admin/users/invite { email, role }` creates
   a pending member and returns a single-use invite token (emailed; also in the
   response outside production). Seat cap is enforced by plan.
4. **Accept** — `POST /api/auth/accept-invite { token, password }` activates the
   member (sets their password) and signs them in.

### Role hierarchy

| Role | Scope | Purpose |
|---|---|---|
| `super_admin` | **All orgs** (cross-org) | Platform operator |
| `owner` | One org (full) | Org owner — manages their whole tenant |
| `soc_manager` | One org | Runs the SOC: response, intel, integrations, policy |
| `threat_hunter` / `analyst` / `responder` | One org | Focused member roles |
| `auditor` / `read_only` | One org | Observers |

Role assignment (`PATCH /api/admin/users/{id}/role`) is a Team/Enterprise
feature; on Individual there is a single owner.

## Organization management (super-admin)

`MANAGE_ORGS` (super-admin only):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/admin/organizations` | List orgs with plan + device/user counts |
| `POST` | `/api/admin/organizations` | Create org (`name`, `slug`, `plan`, `max_devices`) |
| `GET` | `/api/admin/organizations/{id}` | Get one |
| `PATCH` | `/api/admin/organizations/{id}` | Update plan / name / caps / active |

Each org is an isolated tenant; members see only their org's data, a super-admin
sees all. All changes are audited.

## Members (Team / Enterprise)

- `POST /api/admin/users` — invite/create a member (seat cap enforced).
- `PATCH /api/admin/users/{id}/role` — change a member's role (gated to plans
  with RBAC; 402 on Individual).
- `POST /api/admin/users/{id}/disable` — deactivate a member.

## Groups / departments (Team / Enterprise)

- `POST /api/admin/groups` / `GET` / `DELETE` — manage device groups
  (departments, families) — group cap enforced.
- `POST /api/admin/devices/{id}/group` — assign a device to a group.
- Policies resolve **defaults → org → group**, so each department can have its
  own detection/response policy.

## Individual (home) mode

`GET /api/home/summary` collapses the SOC console into a friendly, single-user
view — plan, device count, online/isolated counts, open critical threats, and an
overall `protected` / `attention` status. Org-scoped, so a home user sees only
their own devices. Ideal as the landing screen for the Individual plan.

## Testing

`server/tests/test_plans.py` (entitlements matrix + gating) and
`server/tests/test_orgs.py` (org CRUD, super-admin enforcement, member roles,
home summary).

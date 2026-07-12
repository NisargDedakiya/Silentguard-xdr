# SilentGuard XDR — Enterprise Upgrade Roadmap

Derived from [`AUDIT.md`](./AUDIT.md) and the 16-phase enterprise mandate. The
mandate lists phases by **topic**; this roadmap re-sequences them by
**dependency and risk** so foundations land before the features that need them,
and so the 79 existing tests never regress.

## Principles

- **Upgrade, don't rewrite.** Every existing endpoint keeps working; new auth
  and tenancy are added as backward-compatible layers over the current static
  tokens, then the old path is deprecated (not deleted) behind a flag.
- **Foundation before features.** Config, logging, error handling, migrations,
  and a service layer are prerequisites, not afterthoughts.
- **One module per increment.** Each module ships with logging, config, error
  handling, tests, and docs, and is committed only when the full suite is green.
- **Additive schema.** New columns are nullable / defaulted and backfilled;
  no destructive migrations.

## Build order

Legend — Effort: S/M/L/XL · Risk to existing behavior: Low/Med/High.

### Stage 0 — Foundations (must come first)

| # | Module | Maps to mandate | Effort | Risk | Why first |
|---|---|---|---|---|---|
| **M1** | **Config + observability + web hardening** — `core/config.py` (pydantic-settings), structured JSON logging + request-ID middleware, secure-headers middleware, global exception handlers, tightened CORS | Phase 14 (partial), the "every feature needs logging/config/error-handling" rule | M | Low | Everything below depends on it; zero API change |
| **M2** | **Alembic migrations** — baseline autogenerate against current models, wired into app startup + compose | Phase 7 support for all schema work | S | Low | Unblocks every later table |
| **M3** | **Service/repository layer + shared utils** — extract logic from route handlers, de-dupe `_aware`, event serializer, OS-branch helpers | Clean-architecture mandate; Audit §14 | M | Med | Makes features testable/reusable across REST+WS+workers |

### Stage 1 — Identity, tenancy, access (the security backbone)

| # | Module | Maps to mandate | Effort | Risk |
|---|---|---|---|---|
| **M4** | **Users + JWT auth** — user/session tables, argon2/bcrypt hashing, access+refresh tokens, login/refresh/logout, account lockout, password policy, rate limiting; **legacy admin token still accepted** during transition | Phase 2 (Authentication) | L | Med |
| **M5** | **RBAC** — 7 roles (Super Admin, SOC Manager, Analyst, Threat Hunter, Responder, Auditor, Read Only) + permission decorator/dependency | Phase 5 (RBAC) | M | Med |
| **M6** | **Multi-tenancy** — `org_id` on all domain tables (nullable → backfill "default org" → enforce), org-scoped queries, org isolation tests | Phase 5 (multi-tenant orgs) | L | High |
| **M7** | **Password reset + email verification + OAuth2/OIDC readiness** | Phase 2 (remainder) | M | Low |

### Stage 2 — Detection & intelligence (the XDR core)

| # | Module | Maps to mandate | Effort | Risk |
|---|---|---|---|---|
| **M8** | **Behavioral detection engine** — rule interface + weighted risk model (Low/Med/High/Critical) + configurable responses; seed rules: PowerShell/encoded-cmd/LOLBin/reverse-shell/suspicious-listener; persisted `detections` | Phase 3 | XL | Med |
| **M9** | **Detection rule packs** — credential dumping / LSASS / injection / hollowing / WMI+task+registry+service persistence / priv-esc / lateral movement / fileless / ransomware behavior | Phase 3 (remainder) | XL | Med |
| **M10** | **Threat-intelligence service** — IOC store (domain/IP/URL/SHA-256/cert) with confidence+expiry, feed import, local cache, manual CRUD, YARA/Sigma distribution | Phase 4 | L | Low |

### Stage 3 — Endpoint reach & response

| # | Module | Maps to mandate | Effort | Risk |
|---|---|---|---|---|
| **M11** | **OS-adapter interface** — common monitor/response API with Windows/Linux/macOS adapters; refactor existing monitors behind it | Phase 11 | L | Med |
| **M12** | **Expanded endpoint monitoring** — Event Logs, registry, scheduled tasks, services, startup, FIM, PowerShell logs, DNS, netconns, drivers, autoruns (Windows-first, adapter-gated) | Phase 8 | XL | Med |
| **M13** | **Device inventory + posture** — hardware/software/services/users/health/posture; heartbeat-driven | Phase 6 | M | Low |
| **M14** | **Response action framework** — kill/delete/restore/block-hash/block-ip/block-domain/push-policy/remote-scan/remote-update, each producing an **immutable audit record**; harden isolation (verify, sync, PowerShell/netsh) | Phases 2 (isolation), 9 | L | Med |
| **M15** | **Agent hardening + secure transport** — tamper/self-health, mTLS, cert pinning, message signing, replay protection, compression, queue priority, encrypted offline buffer | Phase 2 (telemetry + agent protection) | XL | High |

### Stage 4 — Management, visibility, integrations

| # | Module | Maps to mandate | Effort | Risk |
|---|---|---|---|---|
| **M16** | **Policy engine + device groups + department policies + licensing placeholders** | Phase 5 (remainder) | L | Med |
| **M17** | **Visibility APIs** — process tree, IOC explorer, registry/USB/network timelines, threat trends, risk heatmaps, executive reports | Phase 7 | L | Low |
| **M18** | **Platform integrations** — SIEM (Splunk/Sentinel/Elastic/QRadar), SOAR (XSOAR/Shuffle/Tines), syslog/CEF, Teams, generic webhook exports (extends existing alerting) | Phase 10 | M | Low |
| **M19** | **Dashboard rebuild** — migrate to TypeScript + app-router structure + shared API client + auth; build the ~15 enterprise dashboards incrementally | Phase 12 | XL | Med |

### Stage 5 — Scale, hardening, assurance (continuous)

| # | Module | Maps to mandate | Effort | Risk |
|---|---|---|---|---|
| **M20** | **Scale-out** — Redis WS fan-out + queues, async processing/workers, batch ingest, indexing, caching, pooling, autoscaling | Phase 13 | XL | High |
| **M21** | **Security hardening (full)** — input validation, SQLi/XSS/CSRF/SSRF/command-injection defenses, secrets management, dependency scanning, SBOM, signed agent updates | Phase 14 (remainder) | L | Low |
| **M22** | **Test + CI depth** — unit/integration/API/WS/load/security/regression tiers + coverage gate in CI | Phase 15 | M | Low |
| **M23** | **Docs automation** — OpenAPI/Swagger, arch diagrams, schema docs, install/deploy/admin/dev guides, security model, changelog, upgrade notes | Phase 16 | M | Low |

## Critical path

```
M1 → M2 → M3 → M4 → M5 → M6 ──► M8/M9 (detection)   ──► M17 (visibility)
                     │           M10 (threat intel)     M19 (dashboards)
                     └► M14 (response) ◄── M11 (OS adapters) ── M12/M13
M20/M21/M22/M23 run continuously alongside every stage.
```

## Milestones

- **MVP-Hardened (M1–M3):** production-shaped foundations, no feature change.
- **Enterprise-Auth (M4–M7):** real identity, RBAC, tenancy — the gate for
  everything customer-facing.
- **XDR-Core (M8–M10):** behavioral detection + threat intel — the reason the
  product exists.
- **Full-Endpoint (M11–M15):** breadth of telemetry + response + agent hardening.
- **Enterprise-Platform (M16–M19):** policy, visibility, integrations, UI.
- **Scale-GA (M20–M23):** 100k-endpoint readiness, assurance, docs.

## What ships this cycle

**M1 is implemented now** as the first increment (see the changelog entry and
`docs/` updates in the same commit). Subsequent modules proceed one at a time,
each gated on a green suite, in the order above — pending your confirmation of
priorities (e.g. jump the detection engine ahead of auth, or vice-versa).

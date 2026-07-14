# SilentGuard XDR — Documentation

Start here. The platform's enterprise upgrade is tracked in the audit and
roadmap; each module has a focused doc below.

## Planning

- [Audit](./AUDIT.md) — pre-implementation codebase audit
- [Roadmap](./ROADMAP.md) — 23-module dependency-ordered plan
- [Architecture](./architecture.md) — system diagram, layering, module map
- [Changelog](../CHANGELOG.md) — per-module change history
- [Upgrade notes](./upgrade-notes.md)

## Foundations & operations

- [Configuration & observability](./configuration.md)
- [Database migrations](./migrations.md)
- [Database schema](./schema.md) _(generated)_
- [Deployment](./deployment.md)
- [Testing & CI](./testing.md)
- [Security hardening](./security-hardening.md)

## Identity & access

- [Authentication (JWT)](./authentication.md)
- [Password reset & email verification](./password-reset.md)
- [RBAC](./rbac.md)
- [Multi-tenancy](./multi-tenancy.md)

## Detection & response

- [Detection engine & rule packs](./detection-engine.md)
- [Threat intelligence / IOCs](./threat-intel.md)
- [Response action framework](./response-framework.md)

## Endpoint & management

- [Device inventory & posture](./device-inventory.md)
- [Policy engine, groups & licensing](./policy-engine.md)
- [Visibility & analytics](./visibility.md)
- [Integrations & exports](./integrations.md)

## Regenerating docs

```bash
make sbom                                   # sbom.json
python scripts/generate_schema_docs.py > docs/schema.md
cd server && python ../scripts/export_openapi.py > openapi.json
```

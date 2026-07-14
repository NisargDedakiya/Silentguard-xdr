"""Subscription plans & feature entitlements.

SilentGuard serves three audiences on the same multi-tenant core, differentiated
by an organization's **plan**:

- **individual** — a person protecting their own handful of devices. No RBAC
  ceremony, small caps, personal features only.
- **team** — a small team / department / family: RBAC, device groups, shared
  policies, integrations, compliance.
- **enterprise** — unlimited scale, SSO, everything on.

Each plan maps to an **entitlements** dict: hard limits (0 = unlimited) plus
feature flags. Endpoints consult these to enforce caps and gate features, so the
same codebase behaves correctly for an individual and a 10,000-seat enterprise.

Legacy/unconfigured orgs (no row) resolve to ``enterprise`` so nothing that
worked before is suddenly gated.
"""

PLANS: dict[str, dict] = {
    "individual": {
        "label": "Individual",
        "max_devices": 5,
        "max_users": 1,
        "max_groups": 1,
        "rbac": False,
        "device_groups": False,
        "integrations": False,
        "compliance_reports": False,
        "sso": False,
        "ai_assistant": True,
    },
    "team": {
        "label": "Team",
        "max_devices": 50,
        "max_users": 15,
        "max_groups": 10,
        "rbac": True,
        "device_groups": True,
        "integrations": True,
        "compliance_reports": True,
        "sso": False,
        "ai_assistant": True,
    },
    "enterprise": {
        "label": "Enterprise",
        "max_devices": 0,   # unlimited
        "max_users": 0,
        "max_groups": 0,
        "rbac": True,
        "device_groups": True,
        "integrations": True,
        "compliance_reports": True,
        "sso": True,
        "ai_assistant": True,
    },
}

PLAN_NAMES = tuple(PLANS)
_LEGACY_PLAN = "enterprise"   # missing org row -> full features (non-breaking)


def get_plan(name: str) -> dict:
    return PLANS.get(name, PLANS[_LEGACY_PLAN])


def entitlements_for(db, org_id: str | None) -> dict:
    """Resolve the effective entitlements for an org (by id). An org-level
    ``max_devices`` override wins over the plan default when set (non-zero)."""
    from ..models import Organization

    org = db.get(Organization, org_id) if org_id else None
    plan = (org.plan if org and org.plan else None) or _LEGACY_PLAN
    ent = dict(get_plan(plan))
    ent["plan"] = plan
    if org is not None and org.max_devices:
        ent["max_devices"] = org.max_devices
    return ent


def feature_enabled(db, org_id: str | None, feature: str) -> bool:
    return bool(entitlements_for(db, org_id).get(feature, True))


def within_limit(db, org_id: str | None, key: str, current_count: int) -> bool:
    """True if adding one more stays within the plan limit (0 = unlimited)."""
    limit = entitlements_for(db, org_id).get(key, 0)
    return limit == 0 or current_count < limit

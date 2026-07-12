"""Multi-tenancy helpers (M6).

All domain data carries an ``org_id``. Reads are scoped to the caller's
organization; a cross-org principal (super-admin / legacy admin token) sees
everything, preserving the pre-M6 single-admin experience. Writes that need a
concrete owning org (blocklist, users) fall back to the default org for
cross-org principals.
"""
from sqlalchemy.orm import Query, Session

from ..core.logging import get_logger
from ..models import DEFAULT_ORG_ID, Organization

log = get_logger("silentguard.tenancy")

DEFAULT_ORG_NAME = "Default Organization"
DEFAULT_ORG_SLUG = "default"


def ensure_default_org(db: Session) -> Organization:
    """Create the well-known default organization if it does not exist. Idempotent."""
    org = db.get(Organization, DEFAULT_ORG_ID)
    if org is None:
        org = Organization(id=DEFAULT_ORG_ID, name=DEFAULT_ORG_NAME, slug=DEFAULT_ORG_SLUG)
        db.add(org)
        db.commit()
        log.info("created default organization", extra={"org_id": DEFAULT_ORG_ID})
    return org


def scope_query(query: Query, org_column, principal) -> Query:
    """Filter `query` to the principal's org, unless the principal is cross-org."""
    if getattr(principal, "cross_org", False):
        return query
    return query.filter(org_column == principal.org_id)


def owning_org(principal) -> str:
    """The org a write should belong to: the principal's own org, or the default
    org for a cross-org principal (legacy admin token)."""
    return principal.org_id or DEFAULT_ORG_ID

"""RBAC role definitions.

The seven enterprise roles from the mandate. M4 attaches a role to every user
and provides admin-vs-not checks; fine-grained per-permission enforcement is
layered on in M5, which is why permissions are modeled here already.
"""
from enum import Enum


class Role(str, Enum):
    SUPER_ADMIN = "super_admin"   # platform operator — sees/manages ALL orgs
    OWNER = "owner"               # owns ONE org — full control of their own tenant
    SOC_MANAGER = "soc_manager"
    ANALYST = "analyst"
    THREAT_HUNTER = "threat_hunter"
    RESPONDER = "responder"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


# Roles permitted to perform administrative/dashboard actions today. This keeps
# M4 backward compatible with the single-admin model while the full permission
# matrix is introduced in M5.
ADMIN_CAPABLE_ROLES: frozenset[Role] = frozenset(
    {Role.SUPER_ADMIN, Role.OWNER, Role.SOC_MANAGER, Role.ANALYST,
     Role.THREAT_HUNTER, Role.RESPONDER, Role.AUDITOR, Role.READ_ONLY}
)

# Roles that may mutate state (isolate, blocklist, quarantine restore). Read-only
# and auditor are observers. Enforced granularly in M5; defined here for clarity.
MUTATING_ROLES: frozenset[Role] = frozenset(
    {Role.SUPER_ADMIN, Role.OWNER, Role.SOC_MANAGER, Role.RESPONDER}
)

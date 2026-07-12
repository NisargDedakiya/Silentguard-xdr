"""RBAC permission matrix (M5).

Maps each of the seven roles to the set of permissions it holds. Endpoints
declare the permission they require; the ``require_permission`` dependency
(in ``app/auth.py``) enforces it. The legacy shared admin token is treated as
``SUPER_ADMIN`` so backward compatibility is preserved.
"""
from enum import Enum

from .roles import Role


class Permission(str, Enum):
    READ_FLEET = "read:fleet"          # devices, events, quarantine list, blocklist, scores
    READ_AUDIT = "read:audit"          # audit log
    WRITE_ISOLATION = "write:isolation"    # isolate / release a device
    WRITE_BLOCKLIST = "write:blocklist"    # add / remove blocklist entries
    WRITE_QUARANTINE = "write:quarantine"  # restore a quarantined file
    MANAGE_USERS = "manage:users"          # create / list / disable users


_ALL = frozenset(Permission)
_READ = frozenset({Permission.READ_FLEET, Permission.READ_AUDIT})
_RESPOND = frozenset(
    {Permission.WRITE_ISOLATION, Permission.WRITE_BLOCKLIST, Permission.WRITE_QUARANTINE}
)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SUPER_ADMIN: _ALL,
    Role.SOC_MANAGER: _READ | _RESPOND,
    Role.ANALYST: _READ,
    Role.THREAT_HUNTER: _READ,
    Role.RESPONDER: frozenset({Permission.READ_FLEET}) | _RESPOND,
    Role.AUDITOR: _READ,
    Role.READ_ONLY: frozenset({Permission.READ_FLEET}),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())

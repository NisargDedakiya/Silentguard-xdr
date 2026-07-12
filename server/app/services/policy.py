"""Policy engine (M16): resolve the effective policy for a device.

Precedence (later overrides earlier):
  1. built-in defaults
  2. the org-default policy (group_id IS NULL, enabled)
  3. the device's group policy (group_id == device.group_id, enabled)
"""
from sqlalchemy.orm import Session

from ..models import Device, Policy

DEFAULT_POLICY: dict = {
    "suspicious_ports": [4444, 5555, 6666, 1337, 31337],
    "blocked_processes": ["mimikatz.exe", "nc.exe", "ncat.exe", "meterpreter"],
    "blocked_domains": [],
    "block_usb_storage": False,
    "file_drop_dirs": [],
    "detection_auto_isolate": False,
}


def _apply(base: dict, settings: dict | None) -> dict:
    if settings:
        base.update({k: v for k, v in settings.items() if v is not None})
    return base


def resolve_effective_policy(db: Session, device: Device) -> dict:
    effective = dict(DEFAULT_POLICY)
    org_default = (
        db.query(Policy)
        .filter(Policy.org_id == device.org_id, Policy.group_id.is_(None),
                Policy.enabled.is_(True))
        .order_by(Policy.id)
        .first()
    )
    _apply(effective, org_default.settings if org_default else None)
    if device.group_id is not None:
        group_policy = (
            db.query(Policy)
            .filter(Policy.org_id == device.org_id, Policy.group_id == device.group_id,
                    Policy.enabled.is_(True))
            .order_by(Policy.id)
            .first()
        )
        _apply(effective, group_policy.settings if group_policy else None)
    return effective

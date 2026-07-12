"""Response action framework (M14).

Dispatches response actions against a device and records each as an immutable
`ResponseAction` plus an audit entry. Two execution paths:

* server-executed (block_hash/ip/domain): applied immediately, status
  ``completed``;
* agent-executed (kill_process, delete_file, remote_scan, remote_update,
  isolate, release, restore_file): a command is queued on the device and the
  action stays ``queued`` until the agent reports a result.
"""
from sqlalchemy.orm import Session

from ..core.logging import get_logger
from ..models import AuditLogEntry, BlocklistEntry, Device, IOC, ResponseAction, utcnow
from ..services import threat_intel

log = get_logger("silentguard.response")

# Actions the agent executes (queued as check-in commands).
AGENT_ACTIONS = {
    "kill_process": "kill_process",
    "delete_file": "delete_file",
    "restore_file": "restore_quarantine",
    "remote_scan": "remote_scan",
    "remote_update": "remote_update",
    "isolate": "isolate",
    "release": "release",
}
# Actions applied server-side immediately.
SERVER_ACTIONS = {"block_domain", "block_ip", "block_hash"}

ALL_ACTIONS = set(AGENT_ACTIONS) | SERVER_ACTIONS


class ResponseError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _queue_command(device: Device, command: str, params: dict, action_id: int) -> None:
    cmds = list(device.pending_commands or [])
    cmds.append({"command": command, "action_id": action_id, **params})
    device.pending_commands = cmds


def _apply_server_action(db: Session, org_id: str | None, action_type: str, params: dict) -> dict:
    if action_type == "block_domain":
        value = params.get("value", "").strip()
        if not value:
            raise ResponseError(400, "block_domain requires 'value'")
        if not db.query(BlocklistEntry).filter(
                BlocklistEntry.value == value, BlocklistEntry.org_id == org_id).first():
            db.add(BlocklistEntry(kind="domain", value=value, org_id=org_id))
        return {"blocked": value}
    if action_type == "block_ip":
        value = params.get("value", "").strip()
        if not value:
            raise ResponseError(400, "block_ip requires 'value'")
        threat_intel.upsert_ioc(db, org_id, "ip", value, confidence=90, source="response")
        return {"blocked_ip": value}
    if action_type == "block_hash":
        value = params.get("value", "").strip()
        if not value:
            raise ResponseError(400, "block_hash requires 'value'")
        threat_intel.upsert_ioc(db, org_id, "sha256", value, confidence=90, source="response")
        return {"blocked_hash": value}
    raise ResponseError(400, f"unknown server action '{action_type}'")


def dispatch(db: Session, device: Device | None, action_type: str, params: dict,
             actor: str, org_id: str | None) -> ResponseAction:
    if action_type not in ALL_ACTIONS:
        raise ResponseError(400, f"unknown action '{action_type}'")

    action = ResponseAction(
        org_id=org_id, device_id=device.id if device else None,
        action_type=action_type, params=params or {}, actor=actor, status="queued",
    )
    db.add(action)
    db.flush()  # assign id for command correlation

    if action_type in SERVER_ACTIONS:
        result = _apply_server_action(db, org_id, action_type, params or {})
        action.status = "completed"
        action.result = result
        action.completed_at = utcnow()
    else:
        if device is None:
            raise ResponseError(400, f"action '{action_type}' requires a device")
        _queue_command(device, AGENT_ACTIONS[action_type], params or {}, action.id)

    db.add(AuditLogEntry(actor=actor, action=f"response:{action_type}",
                         target=device.id if device else "-",
                         org_id=org_id, details={"params": params or {}, "action_id": action.id}))
    db.commit()
    db.refresh(action)
    log.info("response dispatched", extra={"action_type": action_type,
                                           "device_id": device.id if device else None,
                                           "status": action.status})
    return action


def record_result(db: Session, action_id: int, status: str, result: dict) -> None:
    """Update a queued action from an agent-reported result (via telemetry)."""
    action = db.get(ResponseAction, action_id)
    if action is None or action.status != "queued":
        return
    action.status = "completed" if status in ("ok", "completed", "success") else "failed"
    action.result = result or {}
    action.completed_at = utcnow()

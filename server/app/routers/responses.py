"""Response action endpoints (M14)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import Device, ResponseAction
from ..services import response as response_service
from ..services.tenancy import owning_org, scope_query

router = APIRouter(prefix="/api/admin", tags=["responses"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ExecuteResponse = Depends(require_permission(Permission.EXECUTE_RESPONSE))


@router.post("/devices/{device_id}/respond", response_model=schemas.ResponseActionOut,
             status_code=201)
def respond(device_id: str, body: schemas.ResponseRequest, db: Session = Depends(get_db),
            principal: Principal = ExecuteResponse):
    device = db.get(Device, device_id)
    if device is None or (not principal.cross_org and device.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        action = response_service.dispatch(
            db, device, body.action, body.params, principal.actor, owning_org(principal))
    except response_service.ResponseError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    return action


@router.get("/responses", response_model=list[schemas.ResponseActionOut])
def list_responses(device_id: str | None = None, status: str | None = None,
                   limit: int = 100, db: Session = Depends(get_db),
                   principal: Principal = ReadFleet):
    q = scope_query(db.query(ResponseAction), ResponseAction.org_id, principal)
    if device_id:
        q = q.filter(ResponseAction.device_id == device_id)
    if status:
        q = q.filter(ResponseAction.status == status)
    return q.order_by(ResponseAction.created_at.desc()).limit(min(limit, 500)).all()

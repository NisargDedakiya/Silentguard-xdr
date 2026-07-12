"""Integration management + data export endpoints (M18)."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import Principal, require_permission
from ..core.permissions import Permission
from ..database import get_db
from ..models import Integration, ThreatEvent
from ..services import integrations as integ_service
from ..services.tenancy import owning_org, scope_query

router = APIRouter(prefix="/api/admin", tags=["integrations"])

ReadFleet = Depends(require_permission(Permission.READ_FLEET))
ManageIntegrations = Depends(require_permission(Permission.MANAGE_INTEGRATIONS))

VALID_KINDS = {"webhook", "slack", "teams", "discord", "splunk_hec", "syslog"}


@router.get("/integrations", response_model=list[schemas.IntegrationOut])
def list_integrations(db: Session = Depends(get_db), principal: Principal = ReadFleet):
    return scope_query(db.query(Integration), Integration.org_id, principal).all()


@router.post("/integrations", response_model=schemas.IntegrationOut, status_code=201)
def create_integration(body: schemas.IntegrationCreate, db: Session = Depends(get_db),
                       principal: Principal = ManageIntegrations):
    if body.kind not in VALID_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {sorted(VALID_KINDS)}")
    row = Integration(org_id=owning_org(principal), name=body.name, kind=body.kind,
                      config=body.config, min_severity=body.min_severity, enabled=body.enabled)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/integrations/{integration_id}")
def delete_integration(integration_id: int, db: Session = Depends(get_db),
                       principal: Principal = ManageIntegrations):
    row = db.get(Integration, integration_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete(row)
    db.commit()
    return {"deleted": integration_id}


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: int, db: Session = Depends(get_db),
                     principal: Principal = ManageIntegrations):
    row = db.get(Integration, integration_id)
    if row is None or (not principal.cross_org and row.org_id != principal.org_id):
        raise HTTPException(status_code=404, detail="Integration not found")
    integ_service.deliver(row, {"severity": "critical", "summary": "SilentGuard test event",
                                "source": "integration_test", "action": "test"})
    return {"status": "sent"}


# -- exports --------------------------------------------------------------
@router.get("/export/events")
def export_events(format: str = "ndjson", limit: int = 1000, db: Session = Depends(get_db),
                  principal: Principal = ReadFleet):
    """Export recent events as NDJSON or CEF for SIEM ingestion."""
    q = scope_query(db.query(ThreatEvent), ThreatEvent.org_id, principal)
    rows = q.order_by(ThreatEvent.timestamp.desc()).limit(min(limit, 5000)).all()
    payloads = [{"id": r.id, "device_id": r.device_id, "timestamp": r.timestamp.isoformat(),
                 "source": r.source, "action": r.action, "severity": r.severity,
                 "summary": r.summary, "details": r.details or {}} for r in rows]
    if format == "cef":
        lines = [integ_service.format_cef(p) for p in payloads]
        return PlainTextResponse("\n".join(lines), media_type="text/plain")
    if format == "ndjson":
        import json
        body = "\n".join(json.dumps(p, default=str) for p in payloads)
        return PlainTextResponse(body, media_type="application/x-ndjson")
    raise HTTPException(status_code=400, detail="format must be ndjson or cef")

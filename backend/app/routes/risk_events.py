import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user
from app.database import get_db
from app.models import AccessGrant, AccessRequest, RiskEvent, User
from app.mfa.step_up import require_step_up
from app.rbac import is_global_admin, normalized_role, permitted_server_ids


router = APIRouter(prefix="/api/risk-events", tags=["risk-events"])


def _visible_query(db: DBSession, user: User):
    query = db.query(RiskEvent)
    if not is_global_admin(user):
        ids = permitted_server_ids(db, user, "alerts.view") or set()
        query = query.filter((RiskEvent.user_id == user.id) | RiskEvent.server_id.in_(ids))
    return query


def _out(item: RiskEvent) -> dict:
    data = schemas.RiskEventOut.model_validate(item).model_dump()
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


@router.get("", response_model=list[schemas.RiskEventOut])
def list_risk_events(severity: str | None = None, event_type: str | None = None, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = _visible_query(db, current_user)
    if severity:
        query = query.filter(RiskEvent.severity == severity)
    if event_type:
        query = query.filter(RiskEvent.event_type == event_type)
    return [_out(item) for item in query.order_by(RiskEvent.created_at.desc()).limit(1000).all()]


@router.get("/{event_id:int}", response_model=schemas.RiskEventOut)
def get_risk_event(event_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(RiskEvent, event_id)
    if not item or item not in _visible_query(db, current_user).filter(RiskEvent.id == event_id).all():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk event not found")
    return _out(item)


@router.get("/export.csv")
def export_risk_events(request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if normalized_role(current_user.role) in {"admin", "operator"}:
        require_step_up(db, current_user, "export_risk_logs", request, reason="Risk export requires MFA step-up", force=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "risk_score", "event_type", "user_id", "server_id", "grant_id", "session_id", "command_id", "message", "created_at"])
    for item in _visible_query(db, current_user).order_by(RiskEvent.created_at.desc()).all():
        writer.writerow([item.id, item.severity, item.risk_score, item.event_type, item.user_id, item.server_id, item.grant_id, item.session_id, item.command_id, item.message, item.created_at])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=risk_events.csv"})

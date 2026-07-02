import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user
from app.database import get_db
from app.models import AccessGrant, AccessRequest, Alert, User, utcnow


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _visible_query(db: DBSession, user: User):
    query = db.query(Alert)
    if user.role == "user":
        query = query.filter(Alert.user_id == user.id)
    elif user.role == "approver":
        query = query.outerjoin(AccessGrant, Alert.grant_id == AccessGrant.id).outerjoin(AccessRequest, AccessGrant.request_id == AccessRequest.id).filter((Alert.user_id == user.id) | (AccessRequest.approver_id == user.id))
    return query


def _out(item: Alert) -> dict:
    data = schemas.AlertOut.model_validate(item).model_dump()
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


@router.get("", response_model=list[schemas.AlertOut])
def list_alerts(status_value: str | None = None, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = _visible_query(db, current_user)
    if status_value:
        query = query.filter(Alert.status == status_value)
    return [_out(item) for item in query.order_by(Alert.created_at.desc()).limit(1000).all()]


@router.get("/{alert_id:int}", response_model=schemas.AlertOut)
def get_alert(alert_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(Alert, alert_id)
    if not item or item not in _visible_query(db, current_user).filter(Alert.id == alert_id).all():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return _out(item)


@router.post("/{alert_id:int}/acknowledge", response_model=schemas.AlertOut)
def acknowledge_alert(alert_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(Alert, alert_id)
    if not item or item not in _visible_query(db, current_user).filter(Alert.id == alert_id).all():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    item.status = "acknowledged"
    item.acknowledged_by = current_user.id
    item.acknowledged_at = utcnow()
    db.commit()
    db.refresh(item)
    return _out(item)


@router.post("/{alert_id:int}/resolve", response_model=schemas.AlertOut)
def resolve_alert(alert_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(Alert, alert_id)
    if not item or item not in _visible_query(db, current_user).filter(Alert.id == alert_id).all():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if item.severity == "critical" and current_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admin can resolve critical alerts")
    item.status = "resolved"
    item.resolved_by = current_user.id
    item.resolved_at = utcnow()
    db.commit()
    db.refresh(item)
    return _out(item)


@router.post("/{alert_id:int}/dismiss", response_model=schemas.AlertOut)
def dismiss_alert(alert_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admin can dismiss alerts")
    item = db.get(Alert, alert_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    item.status = "dismissed"
    db.commit()
    db.refresh(item)
    return _out(item)


@router.get("/export.csv")
def export_alerts(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "status", "alert_type", "title", "user_id", "server_id", "created_at"])
    for item in _visible_query(db, current_user).order_by(Alert.created_at.desc()).all():
        writer.writerow([item.id, item.severity, item.status, item.alert_type, item.title, item.user_id, item.server_id, item.created_at])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})

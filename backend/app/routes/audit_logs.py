import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import schemas
from app.auth import get_current_user
from app.database import get_db
from app.models import AuditLog, User
from app.mfa.step_up import require_step_up
from app.rbac import active_memberships, has_permission, is_global_admin, permitted_server_ids


router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


def _query(db: Session, current_user: User, user_id: int | None, server_id: int | None, action: str | None):
    query = db.query(AuditLog)
    if not is_global_admin(current_user):
        group_ids = [membership.server_group_id for membership in active_memberships(db, current_user) if has_permission(db, current_user, "audit.view_group", group_id=membership.server_group_id)]
        server_ids = permitted_server_ids(db, current_user, "audit.view_group") or set()
        clauses = [AuditLog.server_id.in_(server_ids)] if server_ids else []
        clauses.extend(AuditLog.metadata_json.contains(f'"group_id": {group_id}') for group_id in group_ids)
        query = query.filter(or_(*clauses)) if clauses else query.filter(AuditLog.id < 0)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if server_id:
        query = query.filter(AuditLog.server_id == server_id)
    if action:
        query = query.filter(AuditLog.action.contains(action))
    return query.order_by(AuditLog.created_at.desc())


def _out(item: AuditLog) -> dict:
    return {
        **schemas.AuditLogOut.model_validate(item).model_dump(),
        "username": item.user.username if item.user else None,
        "server_hostname": item.server.hostname if item.server else None,
    }


@router.get("", response_model=list[schemas.AuditLogOut])
def list_audit_logs(user_id: int | None = None, server_id: int | None = None, action: str | None = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [_out(item) for item in _query(db, current_user, user_id, server_id, action).limit(500).all()]


@router.get("/export.csv")
def export_audit_logs(request: Request, user_id: int | None = None, server_id: int | None = None, action: str | None = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user) and not any(has_permission(db, current_user, "audit.export", group_id=m.server_group_id) for m in active_memberships(db, current_user)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing audit.export permission")
    require_step_up(db, current_user, "export_audit_logs", request, reason="Audit export requires MFA step-up", force=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "user_id", "server_id", "request_id", "grant_id", "session_id", "action", "message", "source_ip", "metadata_json"])
    for item in _query(db, current_user, user_id, server_id, action).all():
        writer.writerow([item.id, item.created_at, item.user_id, item.server_id, item.request_id, item.grant_id, item.session_id, item.action, item.message, item.source_ip, item.metadata_json])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})

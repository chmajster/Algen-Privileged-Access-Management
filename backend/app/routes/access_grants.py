from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.models import AccessGrant, User
from app.mfa.step_up import require_step_up
from app.services import revoke_grant
from app.session_monitor import import_session_logs_for_grant


router = APIRouter(prefix="/api/access-grants", tags=["access-grants"])


def _out(item: AccessGrant) -> dict:
    return {
        **schemas.AccessGrantOut.model_validate(item).model_dump(),
        "username": item.user.username if item.user else None,
        "server_hostname": item.server.hostname if item.server else None,
    }


@router.get("", response_model=list[schemas.AccessGrantOut])
def list_grants(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(AccessGrant)
    if current_user.role == "user":
        query = query.filter(AccessGrant.user_id == current_user.id)
    return [_out(item) for item in query.order_by(AccessGrant.created_at.desc()).all()]


@router.get("/active", response_model=list[schemas.AccessGrantOut])
def active_grants(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(AccessGrant).filter(AccessGrant.status == "active")
    if current_user.role == "user":
        query = query.filter(AccessGrant.user_id == current_user.id)
    return [_out(item) for item in query.order_by(AccessGrant.valid_to.asc()).all()]


@router.post("/{grant_id}/revoke", response_model=schemas.AccessGrantOut)
def revoke(grant_id: int, payload: schemas.RevokeIn, request: Request, current_user: User = Depends(require_roles("approver", "admin")), db: Session = Depends(get_db)):
    grant = db.get(AccessGrant, grant_id)
    if not grant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Grant not found")
    require_step_up(db, current_user, "manual_revoke", request, reason="Manual revoke requires MFA step-up", force=True)
    revoke_grant(db, grant, current_user, payload.reason, source_ip(request))
    db.commit()
    db.refresh(grant)
    return _out(grant)


@router.post("/{grant_id}/import-logs", response_model=schemas.Message)
def import_logs(grant_id: int, request: Request, current_user: User = Depends(require_roles("approver", "admin")), db: Session = Depends(get_db)):
    grant = db.get(AccessGrant, grant_id)
    if not grant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Grant not found")
    if current_user.role == "approver" and grant.request.approver_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    imported = import_session_logs_for_grant(db, grant) if grant.direct_ssh_enabled else 0
    db.commit()
    return {"message": "logs imported", "detail": {"grant_id": grant_id, "imported_commands": imported, "source_ip": source_ip(request)}}

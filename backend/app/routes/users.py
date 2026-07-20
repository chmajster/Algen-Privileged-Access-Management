from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.models import AccessGrant, AccessRequest, GatewayConnection, ServerGroupUserMembership, Session as PamSession, User, utcnow
from app.security import hash_password
from app.rbac import active_memberships, has_permission, is_global_admin, normalized_role
from app.services import revoke_grant
from app.gateway.service import finish_gateway_connection


router = APIRouter(prefix="/api/users", tags=["users"])


def _out(db: Session, user: User) -> dict:
    memberships = active_memberships(db, user)
    return {
        **schemas.UserOut.model_validate(user).model_dump(),
        "access_groups": [{"id": item.group.id, "name": item.group.name, "role": item.group_role, "expires_at": item.valid_to.isoformat() if item.valid_to else None} for item in memberships],
        "active_grant_count": db.query(AccessGrant).filter(AccessGrant.user_id == user.id, AccessGrant.status == "active").count(),
        "active_session_count": db.query(PamSession).filter(PamSession.user_id == user.id, PamSession.status == "active").count(),
    }


@router.get("", response_model=list[schemas.UserOut])
def list_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if normalized_role(current_user.role) == "user" and not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    query = db.query(User)
    if not is_global_admin(current_user):
        group_ids = [membership.server_group_id for membership in active_memberships(db, current_user) if has_permission(db, current_user, "users.view_group", group_id=membership.server_group_id)]
        user_ids = db.query(ServerGroupUserMembership.user_id).filter(ServerGroupUserMembership.server_group_id.in_(group_ids), ServerGroupUserMembership.enabled.is_(True))
        query = query.filter(User.id.in_(user_ids)) if group_ids else query.filter(User.id == current_user.id)
    return [_out(db, user) for user in query.order_by(User.username).all()]


@router.post("", response_model=schemas.UserOut)
def create_user(payload: schemas.UserCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
        ssh_public_key=payload.ssh_public_key,
        mfa_enabled=payload.mfa_enabled,
        mfa_required=payload.mfa_required,
        risk_level=payload.risk_level,
        last_risk_score=payload.last_risk_score,
        auth_provider=payload.auth_provider,
        external_id=payload.external_id,
        display_name=payload.display_name,
        email_verified=payload.email_verified,
    )
    db.add(user)
    db.flush()
    write_audit(db, "user.created", f"Created user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return _out(db, user)


@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if not is_global_admin(current_user) and current_user.id != user_id:
        permitted_groups = {
            membership.server_group_id
            for membership in active_memberships(db, current_user)
            if has_permission(db, current_user, "users.view_group", group_id=membership.server_group_id)
        }
        target_groups = {membership.server_group_id for membership in active_memberships(db, user)}
        if not permitted_groups.intersection(target_groups):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return _out(db, user)


@router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, payload: schemas.UserUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    data = payload.model_dump(exclude_unset=True)
    if current_user.role != "admin":
        data.pop("role", None)
        data.pop("is_active", None)
        data.pop("mfa_enabled", None)
        data.pop("mfa_required", None)
        data.pop("risk_level", None)
        data.pop("last_risk_score", None)
        data.pop("auth_provider", None)
        data.pop("external_id", None)
        data.pop("display_name", None)
        data.pop("email_verified", None)
    if user.role == "admin" and data.get("role") not in {None, "admin"} and db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot demote the last global administrator")
    if user.role == "admin" and data.get("is_active") is False and db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot deactivate the last global administrator")
    if "password" in data:
        user.password_hash = hash_password(data.pop("password"))
    for key, value in data.items():
        setattr(user, key, value)
    write_audit(db, "user.updated", f"Updated user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return _out(db, user)


@router.post("/{user_id}/revoke-grants", response_model=schemas.Message)
def revoke_user_grants(user_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a global administrator can revoke all user grants")
    grants = db.query(AccessGrant).filter(AccessGrant.user_id == user_id, AccessGrant.status == "active").all()
    for grant in grants:
        revoke_grant(db, grant, current_user, "Bulk revoke by administrator", source_ip(request))
    write_audit(db, "user.grants_revoked", f"Revoked all active grants for {user.username}", user_id=current_user.id, source_ip=source_ip(request), metadata={"subject_user_id": user_id, "count": len(grants)})
    db.commit()
    return {"message": f"Revoked {len(grants)} active grants"}


@router.post("/{user_id}/terminate-sessions", response_model=schemas.Message)
def terminate_user_sessions(user_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a global administrator can terminate all user sessions")
    sessions = db.query(PamSession).filter(PamSession.user_id == user_id, PamSession.status == "active").all()
    now = utcnow()
    for session in sessions:
        connection = db.query(GatewayConnection).filter(GatewayConnection.session_id == session.id, GatewayConnection.status == "active").first()
        if connection:
            finish_gateway_connection(db, connection, "bulk_admin_termination")
        else:
            session.status = "terminated"
            session.ended_at = now
            session.termination_reason = "bulk_admin_termination"
    write_audit(db, "user.sessions_terminated", f"Terminated all active sessions for {user.username}", user_id=current_user.id, source_ip=source_ip(request), metadata={"subject_user_id": user_id, "count": len(sessions)})
    db.commit()
    return {"message": f"Terminated {len(sessions)} active sessions"}


@router.delete("/{user_id}", response_model=schemas.Message)
def delete_user(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.role == "admin" and user.is_active and db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot deactivate the last global administrator")
    linked = db.query(AccessGrant).filter(AccessGrant.user_id == user_id).count() + db.query(AccessRequest).filter(AccessRequest.user_id == user_id).count()
    if linked:
        user.is_active = False
        message = "User deactivated because linked records exist"
    else:
        user.is_active = False
        message = "User deactivated"
    write_audit(db, "user.deactivated", f"Deactivated user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    return {"message": message}


@router.put("/{user_id}/ssh-key", response_model=schemas.UserOut)
def update_ssh_key(user_id: int, payload: schemas.SshKeyUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.ssh_public_key = payload.ssh_public_key
    write_audit(db, "user.ssh_key_updated", f"Updated SSH key for {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return _out(db, user)

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.database import get_db
from app.models import (
    AccessGrant, AccessRequest, AuditLog, GroupPermission, Permission, PermissionTemplate, RolePermission, Server, ServerGroup,
    ServerGroupMember, ServerGroupUserMembership, Session as PamSession, User, UserGroupPermission, utcnow,
)
from app.rbac import (
    PERMISSIONS, active_memberships, can_manage_user, canonical_permission, effective_permissions, has_permission,
    is_global_admin, require_permission, visible_server_ids,
)
from app.services import revoke_grant


router = APIRouter(prefix="/api", tags=["server-groups-rbac"])


def _group(db: Session, group_id: int) -> ServerGroup:
    item = db.get(ServerGroup, group_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server group not found")
    return item


def _group_out(db: Session, group: ServerGroup, stats: dict[int, dict] | None = None) -> dict:
    counts = stats.get(group.id, {}) if stats is not None else None
    server_ids = [] if counts is not None else [value for (value,) in db.query(ServerGroupMember.server_id).filter(ServerGroupMember.server_group_id == group.id).all()]
    return {
        "id": group.id, "name": group.name, "description": group.description, "environment": group.environment,
        "is_active": group.enabled, "enabled": group.enabled, "is_system": group.is_system,
        "allowed_access_types": group.allowed_access_types, "max_grant_minutes": group.max_grant_minutes,
        "allowed_durations": group.allowed_durations, "require_approval": group.require_approval,
        "require_mfa": group.require_mfa, "require_gateway": group.require_gateway,
        "deny_direct_ssh": group.deny_direct_ssh, "require_command_logging": group.require_command_logging,
        "require_session_recording": group.require_session_recording, "allowed_hours": group.allowed_hours,
        "allowed_weekdays": group.allowed_weekdays, "max_concurrent_grants": group.max_concurrent_grants,
        "max_active_sessions": group.max_active_sessions, "allow_self_extension": group.allow_self_extension,
        "allow_auto_grant": group.allow_auto_grant, "require_reason": group.require_reason,
        "min_reason_length": group.min_reason_length, "revoke_on_membership_loss": group.revoke_on_membership_loss,
        "terminate_sessions_on_membership_loss": group.terminate_sessions_on_membership_loss,
        "created_at": group.created_at, "updated_at": group.updated_at,
        "user_count": counts.get("users", 0) if counts is not None else db.query(ServerGroupUserMembership).filter_by(server_group_id=group.id, enabled=True).count(),
        "server_count": counts.get("servers", 0) if counts is not None else len(server_ids),
        "active_grant_count": counts.get("grants", 0) if counts is not None else db.query(AccessGrant).filter(AccessGrant.server_id.in_(server_ids), AccessGrant.status == "active").count(),
        "active_session_count": counts.get("sessions", 0) if counts is not None else db.query(PamSession).filter(PamSession.server_id.in_(server_ids), PamSession.status == "active").count(),
    }


def _membership_out(row: ServerGroupUserMembership) -> dict:
    return {
        "id": row.id, "access_group_id": row.server_group_id, "server_group_id": row.server_group_id,
        "user_id": row.user_id, "group_role": row.group_role, "assigned_at": row.created_at,
        "assigned_by_id": row.created_by_id, "expires_at": row.valid_to, "valid_from": row.valid_from,
        "is_active": row.enabled, "enabled": row.enabled, "permission_template_id": row.permission_template_id,
        "username": row.user.username, "email": row.user.email,
    }


def _server_out(db: Session, server: Server) -> dict:
    ids = [value for (value,) in db.query(ServerGroupMember.server_group_id).filter_by(server_id=server.id).all()]
    return {**schemas.ServerOut.model_validate(server).model_dump(), "access_group_ids": ids}


def _permission(db: Session, code: str) -> Permission:
    code = canonical_permission(code)
    item = db.query(Permission).filter(Permission.code == code).first()
    if not item:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown permission: {code}")
    return item


@router.get("/permissions", response_model=list[dict])
def permission_catalog(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [{"id": item.id, "code": item.code, "name": item.name, "description": item.description, "category": item.category, "is_system": item.is_system} for item in db.query(Permission).order_by(Permission.category, Permission.code).all()]


@router.get("/role-permissions", response_model=list[dict])
def role_permissions(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(RolePermission).join(Permission).order_by(RolePermission.role, Permission.code).all()
    return [{"role": row.role, "permission": row.permission.code, "effect": "allow" if row.allowed else "deny"} for row in rows]


@router.get("/permission-templates", response_model=list[schemas.PermissionTemplateOut])
def list_templates(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(PermissionTemplate).order_by(PermissionTemplate.name).all()


@router.post("/permission-templates/{template_id}/copy", response_model=schemas.PermissionTemplateOut, status_code=201)
def copy_template(template_id: int, payload: schemas.PermissionTemplateCopy, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can copy templates")
    source = db.get(PermissionTemplate, template_id)
    if not source:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Permission template not found")
    if db.query(PermissionTemplate).filter_by(name=payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Template name already exists")
    item = PermissionTemplate(name=payload.name, description=f"Copy of {source.name}", permissions_json=source.permissions_json, built_in=False)
    db.add(item); db.flush()
    write_audit(db, "permission_template.copied", "Copied permission template", user_id=current_user.id, source_ip=source_ip(request), metadata={"template_id": item.id, "source_template_id": source.id})
    db.commit(); db.refresh(item)
    return item


@router.patch("/permission-templates/{template_id}", response_model=schemas.PermissionTemplateOut)
def update_template(template_id: int, payload: schemas.PermissionTemplateUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can edit templates")
    item = db.get(PermissionTemplate, template_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Permission template not found")
    if item.built_in:
        raise HTTPException(status.HTTP_409_CONFLICT, "Copy a built-in template before editing it")
    data = payload.model_dump(exclude_unset=True); permissions = data.pop("permissions", None)
    for key, value in data.items(): setattr(item, key, value)
    if permissions is not None:
        for code, effect in permissions.items():
            _permission(db, code)
            if effect not in {"allow", "deny"}: raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid effect")
        item.permissions_json = json.dumps(permissions, ensure_ascii=False, sort_keys=True)
    write_audit(db, "permission_template.updated", "Updated permission template", user_id=current_user.id, source_ip=source_ip(request), metadata={"template_id": item.id, "new": payload.model_dump(exclude_unset=True)})
    db.commit(); db.refresh(item)
    return item


@router.get("/access-groups", response_model=list[schemas.AccessGroupOut])
@router.get("/server-groups", response_model=list[schemas.AccessGroupOut])
def list_groups(search: str | None = None, environment: str | None = None, enabled: bool | None = None, skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(ServerGroup)
    if not is_global_admin(current_user):
        ids = [item.server_group_id for item in active_memberships(db, current_user)]
        query = query.filter(ServerGroup.id.in_(ids))
    if search: query = query.filter(ServerGroup.name.ilike(f"%{search.strip()}%"))
    if environment: query = query.filter(ServerGroup.environment == environment)
    if enabled is not None: query = query.filter(ServerGroup.enabled.is_(enabled))
    groups = query.order_by(ServerGroup.name).offset(skip).limit(limit).all()
    ids = [group.id for group in groups]
    stats = {group_id: {} for group_id in ids}
    if ids:
        for group_id, count in db.query(ServerGroupMember.server_group_id, func.count(ServerGroupMember.id)).filter(ServerGroupMember.server_group_id.in_(ids)).group_by(ServerGroupMember.server_group_id): stats[group_id]["servers"] = count
        for group_id, count in db.query(ServerGroupUserMembership.server_group_id, func.count(ServerGroupUserMembership.id)).filter(ServerGroupUserMembership.server_group_id.in_(ids), ServerGroupUserMembership.enabled.is_(True)).group_by(ServerGroupUserMembership.server_group_id): stats[group_id]["users"] = count
        for group_id, count in db.query(ServerGroupMember.server_group_id, func.count(func.distinct(AccessGrant.id))).join(AccessGrant, AccessGrant.server_id == ServerGroupMember.server_id).filter(ServerGroupMember.server_group_id.in_(ids), AccessGrant.status == "active").group_by(ServerGroupMember.server_group_id): stats[group_id]["grants"] = count
        for group_id, count in db.query(ServerGroupMember.server_group_id, func.count(func.distinct(PamSession.id))).join(PamSession, PamSession.server_id == ServerGroupMember.server_id).filter(ServerGroupMember.server_group_id.in_(ids), PamSession.status == "active").group_by(ServerGroupMember.server_group_id): stats[group_id]["sessions"] = count
    return [_group_out(db, item, stats) for item in groups]


@router.post("/access-groups", response_model=schemas.AccessGroupOut, status_code=201)
@router.post("/server-groups", response_model=schemas.AccessGroupOut, status_code=201)
def create_group(payload: schemas.AccessGroupCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can create groups")
    if db.query(ServerGroup).filter_by(name=payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Group name already exists")
    data = payload.model_dump(); enabled = data.pop("enabled", None); data["enabled"] = data.pop("is_active") if enabled is None else enabled
    group = ServerGroup(**data, created_by_id=current_user.id, updated_by_id=current_user.id)
    db.add(group); db.flush()
    write_audit(db, "server_group.created", "Created server group", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group.id, "new": payload.model_dump(mode="json")})
    db.commit(); db.refresh(group)
    return _group_out(db, group)


@router.get("/access-groups/{group_id}", response_model=schemas.AccessGroupOut)
@router.get("/server-groups/{group_id}", response_model=schemas.AccessGroupOut)
def get_group(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group(db, group_id)
    if not is_global_admin(current_user) and not active_memberships(db, current_user, group_id=group_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server group not found")
    return _group_out(db, group)


@router.patch("/access-groups/{group_id}", response_model=schemas.AccessGroupOut)
@router.put("/server-groups/{group_id}", response_model=schemas.AccessGroupOut)
def update_group(group_id: int, payload: schemas.AccessGroupUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group(db, group_id); require_permission(db, current_user, "group.permissions.manage", group_id=group_id, source_ip=source_ip(request))
    old = _group_out(db, group); data = payload.model_dump(exclude_unset=True)
    if "is_active" in data: data["enabled"] = data.pop("is_active")
    if data.get("name") and db.query(ServerGroup).filter(ServerGroup.name == data["name"], ServerGroup.id != group_id).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Group name already exists")
    for key, value in data.items(): setattr(group, key, value)
    group.updated_by_id = current_user.id
    write_audit(db, "server_group.updated", "Updated server group", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group.id, "old": old, "new": data})
    db.commit(); db.refresh(group)
    return _group_out(db, group)


@router.delete("/access-groups/{group_id}", response_model=schemas.Message)
@router.delete("/server-groups/{group_id}", response_model=schemas.Message)
def delete_group(group_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group(db, group_id); require_permission(db, current_user, "group.permissions.manage", group_id=group_id, source_ip=source_ip(request))
    nonempty = db.query(ServerGroupMember).filter_by(server_group_id=group_id).count() or db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id).count()
    if nonempty or group.is_system:
        group.enabled = False; action = "server_group.disabled"; message = "Group disabled because it contains related data"
    else:
        db.query(GroupPermission).filter_by(server_group_id=group_id).delete(); db.query(UserGroupPermission).filter_by(server_group_id=group_id).delete(); db.delete(group)
        action = "server_group.deleted"; message = "Empty group deleted"
    write_audit(db, action, message, user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id})
    db.commit(); return {"message": message}


@router.get("/access-groups/{group_id}/users", response_model=list[schemas.AccessGroupUserOut])
@router.get("/server-groups/{group_id}/users", response_model=list[schemas.AccessGroupUserOut])
def group_users(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _group(db, group_id); require_permission(db, current_user, "group.members.view", group_id=group_id, conceal=True)
    return [_membership_out(row) for row in db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id).all()]


@router.post("/access-groups/{group_id}/users", response_model=list[schemas.AccessGroupUserOut])
@router.post("/server-groups/{group_id}/users", response_model=list[schemas.AccessGroupUserOut])
def add_users(group_id: int, payload: schemas.AccessGroupUserIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _group(db, group_id); require_permission(db, current_user, "group.members.manage", group_id=group_id, source_ip=source_ip(request))
    users = db.query(User).filter(User.id.in_(payload.user_ids)).all()
    if len(users) != len(set(payload.user_ids)): raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more users do not exist")
    if any(user.role == "admin" for user in users) and not is_global_admin(current_user): raise HTTPException(status.HTTP_403_FORBIDDEN, "Operator cannot manage administrators")
    output = []
    for user in users:
        row = db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id, user_id=user.id).first()
        old = _membership_out(row) if row else None
        if not row:
            row = ServerGroupUserMembership(server_group_id=group_id, user_id=user.id, created_by_id=current_user.id); db.add(row)
        row.group_role = payload.group_role
        if payload.valid_from is not None: row.valid_from = payload.valid_from
        row.valid_to = payload.valid_to if payload.valid_to is not None else payload.expires_at
        row.enabled = payload.is_active
        row.permission_template_id = payload.permission_template_id; row.updated_by_id = current_user.id; db.flush()
        write_audit(db, "server_group.user_assigned", "Assigned user to group", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "subject_user_id": user.id, "old": old, "new": payload.model_dump(mode="json")})
        output.append(row)
    db.commit()
    return [_membership_out(row) for row in output]


@router.patch("/access-groups/{group_id}/users/{user_id}", response_model=schemas.AccessGroupUserOut)
@router.put("/server-groups/{group_id}/users/{user_id}", response_model=schemas.AccessGroupUserOut)
def update_user_membership(group_id: int, user_id: int, payload: schemas.AccessGroupUserUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_permission(db, current_user, "group.members.manage", group_id=group_id, source_ip=source_ip(request))
    target = db.get(User, user_id)
    if not target or not can_manage_user(db, current_user, target, group_id): raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    row = db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id, user_id=user_id).first()
    if not row: raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    old = _membership_out(row); data = payload.model_dump(exclude_unset=True)
    mapping = {"expires_at": "valid_to", "is_active": "enabled"}
    for key, value in data.items(): setattr(row, mapping.get(key, key), value)
    row.updated_by_id = current_user.id
    write_audit(db, "server_group.membership_updated", "Updated group membership", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "subject_user_id": user_id, "old": old, "new": data})
    db.commit(); db.refresh(row); return _membership_out(row)


@router.delete("/access-groups/{group_id}/users/{user_id}", response_model=schemas.Message)
@router.delete("/server-groups/{group_id}/users/{user_id}", response_model=schemas.Message)
def remove_user(group_id: int, user_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group(db, group_id); require_permission(db, current_user, "group.members.manage", group_id=group_id, source_ip=source_ip(request))
    target = db.get(User, user_id)
    if not target or not can_manage_user(db, current_user, target, group_id): raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    row = db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id, user_id=user_id).first()
    if not row: raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    server_ids = [value for (value,) in db.query(ServerGroupMember.server_id).filter_by(server_group_id=group_id).all()]
    row.enabled = False; db.flush()
    lost = [server_id for server_id in server_ids if not has_permission(db, target, "servers.connect", server_id=server_id)]
    db.query(AccessRequest).filter(AccessRequest.user_id == user_id, AccessRequest.server_id.in_(lost), AccessRequest.status == "pending").update({"status": "cancelled"}, synchronize_session=False)
    if group.revoke_on_membership_loss:
        for grant in db.query(AccessGrant).filter(AccessGrant.user_id == user_id, AccessGrant.server_id.in_(lost), AccessGrant.status == "active").all():
            revoke_grant(db, grant, current_user, "Server-group membership removed", source_ip(request))
    if group.terminate_sessions_on_membership_loss:
        db.query(PamSession).filter(PamSession.user_id == user_id, PamSession.server_id.in_(lost), PamSession.status == "active").update({"status": "terminated", "ended_at": utcnow(), "termination_reason": "membership_removed"}, synchronize_session=False)
    db.query(UserGroupPermission).filter_by(server_group_id=group_id, user_id=user_id).delete(); db.delete(row)
    write_audit(db, "server_group.user_removed", "Removed user from group", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "subject_user_id": user_id, "lost_server_ids": lost})
    db.commit(); return {"message": "User removed and inaccessible grants were revoked"}


@router.get("/access-groups/{group_id}/servers", response_model=list[schemas.ServerOut])
@router.get("/server-groups/{group_id}/servers", response_model=list[schemas.ServerOut])
def group_servers(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _group(db, group_id); require_permission(db, current_user, "servers.view", group_id=group_id, conceal=True)
    servers = db.query(Server).join(ServerGroupMember, ServerGroupMember.server_id == Server.id).filter(ServerGroupMember.server_group_id == group_id).order_by(Server.hostname).all()
    return [_server_out(db, server) for server in servers]


def _change_servers(group_id: int, server_ids: list[int], add: bool, request: Request, current_user: User, db: Session) -> dict:
    _group(db, group_id); require_permission(db, current_user, "group.servers.manage", group_id=group_id, source_ip=source_ip(request))
    if db.query(Server).filter(Server.id.in_(server_ids)).count() != len(set(server_ids)): raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more servers do not exist")
    for server_id in set(server_ids):
        row = db.query(ServerGroupMember).filter_by(server_group_id=group_id, server_id=server_id).first()
        if add and not row: db.add(ServerGroupMember(server_group_id=group_id, server_id=server_id, created_by_id=current_user.id))
        if not add and row: db.delete(row)
        write_audit(db, "server_group.server_added" if add else "server_group.server_removed", "Changed group server membership", user_id=current_user.id, server_id=server_id, source_ip=source_ip(request), metadata={"group_id": group_id, "added": add})
    db.commit(); return {"message": f"Processed {len(set(server_ids))} servers"}


@router.post("/access-groups/{group_id}/servers", response_model=list[schemas.ServerOut])
def add_servers_compat(group_id: int, payload: schemas.AccessGroupServersIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _change_servers(group_id, payload.server_ids, True, request, current_user, db)
    return group_servers(group_id, current_user, db)


@router.post("/server-groups/{group_id}/servers/{server_id:int}", response_model=schemas.Message)
def add_server(group_id: int, server_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _change_servers(group_id, [server_id], True, request, current_user, db)


@router.delete("/access-groups/{group_id}/servers/{server_id:int}", response_model=schemas.Message)
@router.delete("/server-groups/{group_id}/servers/{server_id:int}", response_model=schemas.Message)
def remove_server(group_id: int, server_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _change_servers(group_id, [server_id], False, request, current_user, db)


@router.post("/server-groups/{group_id}/servers/bulk-add", response_model=schemas.Message)
def bulk_add(group_id: int, payload: schemas.AccessGroupServersIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _change_servers(group_id, payload.server_ids, True, request, current_user, db)


@router.post("/server-groups/{group_id}/servers/bulk-remove", response_model=schemas.Message)
def bulk_remove(group_id: int, payload: schemas.AccessGroupServersIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _change_servers(group_id, payload.server_ids, False, request, current_user, db)


def _permission_entries(db: Session, group_id: int, user_id: int | None = None) -> list[dict]:
    if user_id is None:
        rows = db.query(GroupPermission).filter_by(server_group_id=group_id).all()
    else:
        rows = db.query(UserGroupPermission).filter_by(server_group_id=group_id, user_id=user_id).all()
    return [{"permission": row.permission.code, "effect": "allow" if row.allowed else "deny", "membership_id": None} for row in rows]


@router.get("/access-groups/{group_id}/permissions", response_model=list[schemas.PermissionEntry])
@router.get("/server-groups/{group_id}/permissions", response_model=list[schemas.PermissionEntry])
def group_permissions(group_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _group(db, group_id); require_permission(db, current_user, "group.permissions.manage", group_id=group_id, conceal=True)
    return _permission_entries(db, group_id)


@router.put("/access-groups/{group_id}/permissions", response_model=list[schemas.PermissionEntry])
@router.put("/server-groups/{group_id}/permissions", response_model=list[schemas.PermissionEntry])
def replace_permissions(group_id: int, payload: list[schemas.PermissionEntry], request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _group(db, group_id); require_permission(db, current_user, "group.permissions.manage", group_id=group_id, source_ip=source_ip(request))
    old = _permission_entries(db, group_id); db.query(GroupPermission).filter_by(server_group_id=group_id).delete()
    for item in payload:
        if item.membership_id:
            member = db.get(ServerGroupUserMembership, item.membership_id)
            if not member or member.server_group_id != group_id: raise HTTPException(status.HTTP_400_BAD_REQUEST, "Membership belongs to another group")
            permission = _permission(db, item.permission)
            db.add(UserGroupPermission(server_group_id=group_id, user_id=member.user_id, permission_id=permission.id, allowed=item.effect == "allow", created_by_id=current_user.id, updated_by_id=current_user.id))
        else:
            permission = _permission(db, item.permission)
            db.add(GroupPermission(server_group_id=group_id, permission_id=permission.id, allowed=item.effect == "allow", created_by_id=current_user.id, updated_by_id=current_user.id))
    write_audit(db, "server_group.permissions_updated", "Updated group permissions", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "old": old, "new": [item.model_dump() for item in payload]})
    db.commit(); return payload


@router.get("/server-groups/{group_id}/users/{user_id}/permissions", response_model=list[schemas.PermissionEntry])
def user_permissions(group_id: int, user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_permission(db, current_user, "group.permissions.manage", group_id=group_id, conceal=True)
    return _permission_entries(db, group_id, user_id)


@router.put("/server-groups/{group_id}/users/{user_id}/permissions", response_model=list[schemas.PermissionEntry])
def replace_user_permissions(group_id: int, user_id: int, payload: list[schemas.PermissionEntry], request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    require_permission(db, current_user, "group.permissions.manage", group_id=group_id, source_ip=source_ip(request))
    if not db.query(ServerGroupUserMembership).filter_by(server_group_id=group_id, user_id=user_id).first(): raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    old = _permission_entries(db, group_id, user_id); db.query(UserGroupPermission).filter_by(server_group_id=group_id, user_id=user_id).delete()
    for item in payload:
        permission = _permission(db, item.permission)
        db.add(UserGroupPermission(server_group_id=group_id, user_id=user_id, permission_id=permission.id, allowed=item.effect == "allow", created_by_id=current_user.id, updated_by_id=current_user.id))
    write_audit(db, "server_group.user_permissions_updated", "Updated user group permissions", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "subject_user_id": user_id, "old": old, "new": [item.model_dump() for item in payload]})
    db.commit(); return payload


@router.get("/server-groups/{group_id}/users/{user_id}/effective-permissions", response_model=list[schemas.EffectivePermissionOut])
def group_user_effective(group_id: int, user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    subject = db.get(User, user_id)
    if not subject: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if current_user.id != user_id: require_permission(db, current_user, "group.members.view", group_id=group_id, conceal=True)
    return effective_permissions(db, subject, group_id=group_id)


@router.post("/access-groups/{group_id}/permissions/from-template/{template_id}", response_model=list[schemas.PermissionEntry])
def apply_template(group_id: int, template_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    template = db.get(PermissionTemplate, template_id)
    if not template: raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    return replace_permissions(group_id, [schemas.PermissionEntry(permission=code, effect=effect) for code, effect in json.loads(template.permissions_json).items()], request, current_user, db)


@router.post("/access-groups/{group_id}/copy-settings/{source_group_id}", response_model=schemas.AccessGroupOut)
def copy_settings(group_id: int, source_group_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if group_id == source_group_id: raise HTTPException(status.HTTP_400_BAD_REQUEST, "Groups must be different")
    target = _group(db, group_id); source = _group(db, source_group_id)
    require_permission(db, current_user, "group.permissions.manage", group_id=group_id); require_permission(db, current_user, "group.permissions.manage", group_id=source_group_id, conceal=True)
    fields = set(schemas.AccessGroupBase.model_fields) - {"name", "description", "environment", "is_active"}
    for field in fields: setattr(target, field, getattr(source, field))
    db.query(GroupPermission).filter_by(server_group_id=group_id).delete()
    for row in db.query(GroupPermission).filter_by(server_group_id=source_group_id).all(): db.add(GroupPermission(server_group_id=group_id, permission_id=row.permission_id, allowed=row.allowed, created_by_id=current_user.id))
    write_audit(db, "server_group.settings_copied", "Copied group settings", user_id=current_user.id, source_ip=source_ip(request), metadata={"group_id": group_id, "source_group_id": source_group_id})
    db.commit(); db.refresh(target); return _group_out(db, target)


@router.get("/users/{user_id}/groups", response_model=list[schemas.AccessGroupOut])
def user_groups(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    subject = db.get(User, user_id)
    if not subject: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    memberships = active_memberships(db, subject)
    if current_user.id != user_id and not is_global_admin(current_user):
        actor_ids = {item.server_group_id for item in active_memberships(db, current_user) if has_permission(db, current_user, "group.members.view", group_id=item.server_group_id)}
        memberships = [item for item in memberships if item.server_group_id in actor_ids]
    return [_group_out(db, item.group) for item in memberships]


@router.get("/users/{user_id}/effective-permissions", response_model=list[schemas.EffectivePermissionOut])
def user_effective(user_id: int, server_id: int | None = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    subject = db.get(User, user_id)
    if not subject: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if current_user.id != user_id and not is_global_admin(current_user):
        shared = {m.server_group_id for m in active_memberships(db, current_user) if has_permission(db, current_user, "group.members.view", group_id=m.server_group_id)} & {m.server_group_id for m in active_memberships(db, subject)}
        if not shared: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return effective_permissions(db, subject, server_id=server_id)


@router.get("/users/{user_id}/available-servers", response_model=list[schemas.ServerOut])
def user_servers(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    subject = db.get(User, user_id)
    if not subject: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if current_user.id != user_id and not is_global_admin(current_user):
        shared = {m.server_group_id for m in active_memberships(db, current_user) if has_permission(db, current_user, "group.members.view", group_id=m.server_group_id)} & {m.server_group_id for m in active_memberships(db, subject)}
        if not shared: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    ids = visible_server_ids(db, subject); query = db.query(Server).filter(Server.enabled.is_(True))
    if ids is not None: query = query.filter(Server.id.in_(ids))
    return [_server_out(db, server) for server in query.order_by(Server.hostname).all()]


@router.put("/users/{user_id}/role", response_model=schemas.UserOut)
def set_user_role(user_id: int, payload: schemas.UserRoleUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user): raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can set global roles")
    target = db.get(User, user_id)
    if not target: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    role = payload.role
    if target.role == "admin" and role != "admin" and db.query(User).filter_by(role="admin", is_active=True).count() <= 1: raise HTTPException(status.HTTP_409_CONFLICT, "Cannot demote the last administrator")
    old = target.role; target.role = role
    write_audit(db, "user.role_updated", "Updated global role", user_id=current_user.id, source_ip=source_ip(request), metadata={"subject_user_id": user_id, "old": old, "new": role})
    db.commit(); db.refresh(target); return schemas.UserOut.model_validate(target)


@router.put("/users/{user_id}/status", response_model=schemas.UserOut)
def set_user_status(user_id: int, payload: schemas.UserStatusUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user): raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can set account status")
    target = db.get(User, user_id)
    if not target: raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    enabled = payload.is_active
    if target.role == "admin" and not enabled and db.query(User).filter_by(role="admin", is_active=True).count() <= 1: raise HTTPException(status.HTTP_409_CONFLICT, "Cannot disable the last administrator")
    old = target.is_active; target.is_active = enabled
    write_audit(db, "user.status_updated", "Updated account status", user_id=current_user.id, source_ip=source_ip(request), metadata={"subject_user_id": user_id, "old": old, "new": enabled})
    db.commit(); db.refresh(target); return schemas.UserOut.model_validate(target)

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.database import get_db
from app.executor import get_executor
from app.models import AccessGrant, AccessRequest, Secret, Server, ServerGroup, ServerGroupMember, User
from app.rbac import has_permission, is_global_admin, require_permission, scope_server_query


router = APIRouter(prefix="/api/servers", tags=["servers"])


def _out(db: Session, server: Server, group_map: dict[int, list[int]] | None = None) -> dict:
    ids = group_map.get(server.id, []) if group_map is not None else [group_id for (group_id,) in db.query(ServerGroupMember.server_group_id).filter(ServerGroupMember.server_id == server.id).all()]
    return {**schemas.ServerOut.model_validate(server).model_dump(), "access_group_ids": ids}


def _group_map(db: Session, server_ids: list[int]) -> dict[int, list[int]]:
    result = {server_id: [] for server_id in server_ids}
    if server_ids:
        for server_id, group_id in db.query(ServerGroupMember.server_id, ServerGroupMember.server_group_id).filter(ServerGroupMember.server_id.in_(server_ids)).all():
            result[server_id].append(group_id)
    return result


@router.get("", response_model=list[schemas.ServerOut])
def list_servers(search: str | None = None, environment: str | None = None, group_id: int | None = None, skip: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=500), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = scope_server_query(db.query(Server), db, current_user).filter(Server.enabled.is_(True) if not is_global_admin(current_user) else Server.id.is_not(None))
    if search: query = query.filter(Server.hostname.ilike(f"%{search.strip()}%") | Server.display_name.ilike(f"%{search.strip()}%") | Server.ip_address.ilike(f"%{search.strip()}%"))
    if environment: query = query.filter(Server.environment == environment)
    if group_id is not None: query = query.join(ServerGroupMember, ServerGroupMember.server_id == Server.id).filter(ServerGroupMember.server_group_id == group_id)
    servers = query.order_by(Server.hostname).offset(skip).limit(limit).all()
    group_map = _group_map(db, [server.id for server in servers])
    return [_out(db, server, group_map) for server in servers]


@router.post("", response_model=schemas.ServerOut)
def create_server(payload: schemas.ServerCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        if not payload.access_group_ids or not all(
            has_permission(db, current_user, "servers.create", group_id=group_id)
            and has_permission(db, current_user, "servers.assign_to_group", group_id=group_id)
            for group_id in payload.access_group_ids
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing servers.create permission")
    groups = db.query(ServerGroup).filter(ServerGroup.id.in_(payload.access_group_ids)).all() if payload.access_group_ids else []
    if len(groups) != len(set(payload.access_group_ids)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more access groups do not exist")
    # Calls made by pre-RBAC clients did not include a group list. Keep those
    # servers visible to migrated users by placing them in the compatibility
    # group; an explicit empty list after creation can still make them unscoped.
    if is_global_admin(current_user) and not payload.access_group_ids:
        legacy_group = db.query(ServerGroup).filter(ServerGroup.name == "Legacy compatibility").first()
        groups = [legacy_group] if legacy_group else []
    if db.query(Server).filter((func.lower(Server.hostname) == payload.hostname.lower()) | ((Server.ip_address == payload.ip_address) & (Server.ssh_port == payload.ssh_port))).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A server with this host and SSH port already exists")
    for secret_id in {payload.secret_ref_id, payload.gateway_secret_ref_id, payload.ssh_auth_secret_id} - {None}:
        if not db.get(Secret, secret_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Secret {secret_id} does not exist")
    server = Server(**payload.model_dump(exclude={"access_group_ids"}))
    db.add(server)
    db.flush()
    for group in groups:
        db.add(ServerGroupMember(server_group_id=group.id, server_id=server.id, created_by_id=current_user.id))
    write_audit(db, "server.created", f"Created server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"group_ids": [group.id for group in groups]})
    db.commit()
    db.refresh(server)
    return _out(db, server)


@router.get("/{server_id}", response_model=schemas.ServerOut)
def get_server(server_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server or (not is_global_admin(current_user) and not server.enabled):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    if not is_global_admin(current_user):
        require_permission(db, current_user, "servers.view", server_id=server_id, conceal=True, source_ip=source_ip(request))
    return _out(db, server)


@router.put("/{server_id}", response_model=schemas.ServerOut)
@router.patch("/{server_id}", response_model=schemas.ServerOut)
def update_server(server_id: int, payload: schemas.ServerUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    require_permission(db, current_user, "servers.edit", server_id=server_id)
    data = payload.model_dump(exclude_unset=True)
    group_ids = data.pop("access_group_ids", None)
    host = data.get("ip_address", server.ip_address); port = data.get("ssh_port", server.ssh_port)
    hostname = data.get("hostname", server.hostname)
    if db.query(Server).filter(Server.id != server.id, (func.lower(Server.hostname) == hostname.lower()) | ((Server.ip_address == host) & (Server.ssh_port == port))).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A server with this host and SSH port already exists")
    for secret_id in {data.get("secret_ref_id"), data.get("gateway_secret_ref_id"), data.get("ssh_auth_secret_id")} - {None}:
        if not db.get(Secret, secret_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Secret {secret_id} does not exist")
    for key, value in data.items():
        setattr(server, key, value)
    if group_ids is not None:
        existing_group_ids = {value for (value,) in db.query(ServerGroupMember.server_group_id).filter(ServerGroupMember.server_id == server.id).all()}
        changed_group_ids = existing_group_ids.symmetric_difference(set(group_ids))
        if not is_global_admin(current_user) and not all(
            has_permission(db, current_user, "groups.manage_servers", group_id=group_id)
            and has_permission(db, current_user, "servers.assign_to_group", group_id=group_id)
            for group_id in changed_group_ids
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot change one or more server group assignments")
        if db.query(ServerGroup).filter(ServerGroup.id.in_(group_ids)).count() != len(set(group_ids)):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more access groups do not exist")
        db.query(ServerGroupMember).filter(ServerGroupMember.server_id == server.id).delete()
        for group_id in set(group_ids):
            db.add(ServerGroupMember(server_group_id=group_id, server_id=server.id, created_by_id=current_user.id))
    write_audit(db, "server.updated", f"Updated server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"new": data, "group_ids": group_ids})
    db.commit()
    db.refresh(server)
    return _out(db, server)


@router.delete("/{server_id}", response_model=schemas.Message)
def delete_server(server_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    require_permission(db, current_user, "servers.delete", server_id=server_id)
    if db.query(AccessGrant).filter(AccessGrant.server_id == server_id, AccessGrant.status == "active").count():
        raise HTTPException(status.HTTP_409_CONFLICT, "Server has active grants and cannot be deleted or archived")
    linked = db.query(AccessGrant).filter(AccessGrant.server_id == server_id).count() + db.query(AccessRequest).filter(AccessRequest.server_id == server_id).count()
    server.enabled = False
    write_audit(db, "server.deactivated", f"Deactivated server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request))
    db.commit()
    return {"message": "Server deactivated because linked records exist" if linked else "Server deactivated"}


@router.post("/{server_id}/test-connection", response_model=schemas.Message)
def test_connection(server_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    require_permission(db, current_user, "servers.test_connection", server_id=server_id)
    result = get_executor().test_connection(server)
    def sanitized(value):
        if isinstance(value, dict):
            return {key: sanitized(item) for key, item in value.items() if not any(token in key.lower() for token in ("password", "secret", "private", "token", "key_material"))}
        if isinstance(value, list):
            return [sanitized(item) for item in value]
        return value
    result = sanitized(result)
    write_audit(db, "server.test_connection", f"Tested connection to {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata=result)
    db.commit()
    return {"message": "Connection test completed", "detail": result}

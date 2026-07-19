import json
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import false
from sqlalchemy.orm import Query, Session, joinedload

from app.config import settings
from app.models import (
    AccessGroup,
    AccessGroupPermission,
    AccessGroupServer,
    AccessGroupUser,
    GroupPermission,
    Permission,
    PermissionTemplate,
    RolePermission,
    Server,
    ServerGroup,
    ServerGroupMember,
    ServerGroupUserMembership,
    User,
    UserGroupPermission,
)


# The catalog contains only the current public vocabulary. Older route codes
# are accepted through PERMISSION_ALIASES without creating duplicate entries.
PERMISSIONS = {
    "servers.view", "servers.create", "servers.update", "servers.delete", "servers.test_connection",
    "servers.connect", "servers.direct_ssh", "servers.gateway_ssh",
    "access.request", "access.approve", "access.reject",
    "access.revoke", "access.extend", "access.ssh_only", "access.limited_sudo", "access.full_sudo",
    "sessions.view_own", "sessions.view_group", "sessions.terminate", "recordings.view_own", "recordings.view_group",
    "commands.view_own", "commands.view_group", "audit.view_group", "audit.export", "group.members.view",
    "group.members.manage", "group.servers.manage", "group.permissions.manage", "alerts.view", "alerts.manage",
    "secrets.use", "policies.view",
}

PERMISSION_ALIASES = {
    "servers.edit": "servers.update",
    "servers.assign_to_group": "group.servers.manage",
    "access.connect": "servers.connect",
    "access.connect_direct": "servers.direct_ssh",
    "access.connect_gateway": "servers.gateway_ssh",
    "groups.manage_members": "group.members.manage",
    "users.manage_group": "group.members.manage",
    "users.view_group": "group.members.view",
    "groups.manage_servers": "group.servers.manage",
    "groups.manage_permissions": "group.permissions.manage",
}

ROLE_PERMISSIONS = {
    "admin": set(PERMISSIONS),
    "group_admin": set(PERMISSIONS),
    "operator": {
        "servers.view", "servers.update", "servers.test_connection", "servers.connect", "servers.gateway_ssh",
        "access.approve", "access.reject", "access.revoke", "access.extend", "sessions.view_group", "sessions.terminate",
        "recordings.view_group", "commands.view_group", "audit.view_group", "group.members.view", "alerts.view",
    },
    "user": {
        "servers.view", "servers.connect", "servers.gateway_ssh", "access.request", "access.ssh_only",
        "sessions.view_own", "recordings.view_own", "commands.view_own",
    },
    "auditor": {
        "servers.view", "sessions.view_group", "recordings.view_group", "commands.view_group", "audit.view_group",
        "audit.export", "alerts.view", "policies.view",
    },
    "custom": set(),
}

TEMPLATES = {
    "Administrator grupy": {permission: "allow" for permission in ROLE_PERMISSIONS["group_admin"]},
    "Operator grupy": {permission: "allow" for permission in ROLE_PERMISSIONS["operator"]},
    "Użytkownik tylko SSH": {permission: "allow" for permission in ROLE_PERMISSIONS["user"]},
    "Użytkownik SSH z ograniczonym sudo": {permission: "allow" for permission in ROLE_PERMISSIONS["user"] | {"access.limited_sudo"}},
    "Użytkownik tylko przez gateway": {permission: "allow" for permission in ROLE_PERMISSIONS["user"] - {"servers.direct_ssh"}},
    "Audytor tylko do odczytu": {permission: "allow" for permission in ROLE_PERMISSIONS["auditor"]},
}


def normalized_role(role: str) -> str:
    return "operator" if role == "approver" else role


def canonical_permission(code: str) -> str:
    return PERMISSION_ALIASES.get(code, code)


def equivalent_permissions(code: str) -> set[str]:
    canonical = canonical_permission(code)
    return {alias for alias, target in PERMISSION_ALIASES.items() if target == canonical} | {canonical}


def is_global_admin(user: User) -> bool:
    return user.role == "admin"


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _active(membership: ServerGroupUserMembership, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return bool(
        membership.enabled
        and membership.group.enabled
        and (_aware(membership.valid_from) is None or _aware(membership.valid_from) <= now)
        and (_aware(membership.valid_to) is None or _aware(membership.valid_to) > now)
    )


def active_memberships(db: Session, user: User, *, group_id: int | None = None, server_id: int | None = None) -> list[ServerGroupUserMembership]:
    if not user.is_active:
        return []
    query = db.query(ServerGroupUserMembership).options(joinedload(ServerGroupUserMembership.group), joinedload(ServerGroupUserMembership.permission_template)).join(ServerGroup).filter(
        ServerGroupUserMembership.user_id == user.id,
        ServerGroupUserMembership.enabled.is_(True),
        ServerGroup.enabled.is_(True),
    )
    if group_id is not None:
        query = query.filter(ServerGroupUserMembership.server_group_id == group_id)
    if server_id is not None:
        query = query.join(ServerGroupMember, ServerGroupMember.server_group_id == ServerGroupUserMembership.server_group_id).filter(ServerGroupMember.server_id == server_id)
    return [membership for membership in query.all() if _active(membership)]


def accessible_group_ids(db: Session, user: User) -> set[int] | None:
    if is_global_admin(user) or not settings.pam_group_scoped_access:
        return None
    return {membership.server_group_id for membership in active_memberships(db, user)}


def visible_server_ids(db: Session, user: User) -> set[int] | None:
    if is_global_admin(user) or not settings.pam_group_scoped_access:
        return None
    group_ids = accessible_group_ids(db, user) or set()
    if not group_ids:
        return set()
    candidates = db.query(ServerGroupMember.server_id).filter(ServerGroupMember.server_group_id.in_(group_ids)).distinct().all()
    return {server_id for (server_id,) in candidates if has_permission(db, user, "servers.view", server_id=server_id)}


def permitted_server_ids(db: Session, user: User, permission: str) -> set[int] | None:
    if is_global_admin(user):
        return None
    group_ids = {membership.server_group_id for membership in active_memberships(db, user)}
    if not group_ids:
        return set()
    candidates = db.query(ServerGroupMember.server_id).filter(ServerGroupMember.server_group_id.in_(group_ids)).distinct().all()
    return {server_id for (server_id,) in candidates if has_permission(db, user, permission, server_id=server_id)}


def scope_permission_query(query: Query, db: Session, user: User, permission: str, server_column) -> Query:
    ids = permitted_server_ids(db, user, permission)
    if ids is None:
        return query
    return query.filter(server_column.in_(ids) if ids else false())


def scope_server_query(query: Query, db: Session, user: User, server_column=Server.id) -> Query:
    ids = visible_server_ids(db, user)
    if ids is None:
        return query
    return query.filter(server_column.in_(ids) if ids else false())


def _template_effects(membership: ServerGroupUserMembership) -> dict[str, str]:
    if not membership.permission_template:
        return {}
    try:
        value = json.loads(membership.permission_template.permissions_json)
        return value if isinstance(value, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def permission_sources(db: Session, user: User, permission: str, *, server_id: int | None = None, group_id: int | None = None) -> list[dict]:
    requested = canonical_permission(permission)
    if is_global_admin(user):
        return [{"permission": permission, "effect": "allow", "group_id": None, "group_name": None, "group_role": "admin", "source": "global_admin"}]
    sources = []
    codes = equivalent_permissions(permission)
    if not settings.pam_group_scoped_access:
        for row in db.query(RolePermission).join(Permission).filter(
            RolePermission.role == normalized_role(user.role), Permission.code.in_(codes)
        ).all():
            sources.append({"permission": permission, "effect": "allow" if row.allowed else "deny", "group_id": None, "group_name": None, "group_role": normalized_role(user.role), "source": "system_role"})
    for membership in active_memberships(db, user, group_id=group_id, server_id=server_id):
        role_rows = db.query(RolePermission).join(Permission).filter(RolePermission.role == membership.group_role, Permission.code.in_(codes)).all()
        for row in role_rows:
            sources.append({"permission": permission, "effect": "allow" if row.allowed else "deny", "group_id": membership.server_group_id, "group_name": membership.group.name, "group_role": membership.group_role, "source": "role_permission"})
        for code, effect in _template_effects(membership).items():
            if canonical_permission(code) == requested and effect in {"allow", "deny"}:
                sources.append({"permission": permission, "effect": effect, "group_id": membership.server_group_id, "group_name": membership.group.name, "group_role": membership.group_role, "source": "membership_template"})
        group_rows = db.query(GroupPermission).join(Permission).filter(GroupPermission.server_group_id == membership.server_group_id, Permission.code.in_(codes)).all()
        for row in group_rows:
            sources.append({"permission": permission, "effect": "allow" if row.allowed else "deny", "group_id": membership.server_group_id, "group_name": membership.group.name, "group_role": membership.group_role, "source": "group_permission"})
        user_rows = db.query(UserGroupPermission).join(Permission).filter(UserGroupPermission.server_group_id == membership.server_group_id, UserGroupPermission.user_id == user.id, Permission.code.in_(codes)).all()
        for row in user_rows:
            sources.append({"permission": permission, "effect": "allow" if row.allowed else "deny", "group_id": membership.server_group_id, "group_name": membership.group.name, "group_role": membership.group_role, "source": "user_override"})
    return sources


def has_permission(db: Session, user: User, permission: str, *, server_id: int | None = None, group_id: int | None = None) -> bool:
    sources = permission_sources(db, user, permission, server_id=server_id, group_id=group_id)
    return not any(item["effect"] == "deny" for item in sources) and any(item["effect"] == "allow" for item in sources)


def require_permission(db: Session, user: User, permission: str, *, server_id: int | None = None, group_id: int | None = None, conceal: bool = False, source_ip: str | None = None) -> None:
    if has_permission(db, user, permission, server_id=server_id, group_id=group_id):
        return
    from app.audit import write_audit
    write_audit(db, "access.denied", f"Denied permission {permission}", user_id=user.id, server_id=server_id, source_ip=source_ip, result="denied", metadata={"group_id": group_id, "permission": permission, "concealed": conceal})
    db.commit()
    raise HTTPException(status.HTTP_404_NOT_FOUND if conceal else status.HTTP_403_FORBIDDEN, "Resource not found" if conceal else f"Missing permission: {permission}")


def effective_permissions(db: Session, user: User, *, server_id: int | None = None, group_id: int | None = None) -> list[dict]:
    result = []
    for permission in sorted(PERMISSIONS):
        sources = permission_sources(db, user, permission, server_id=server_id, group_id=group_id)
        denied = next((item for item in sources if item["effect"] == "deny"), None)
        allowed = next((item for item in sources if item["effect"] == "allow"), None)
        result.append(denied or allowed or {"permission": permission, "effect": "deny", "group_id": None, "group_name": None, "group_role": None, "source": "default_deny", "reason": "No active membership grants this permission"})
    return result


def can_manage_user(db: Session, actor: User, target: User, group_id: int | None = None) -> bool:
    if is_global_admin(actor):
        return True
    if target.role == "admin":
        return False
    return group_id is not None and has_permission(db, actor, "group.members.manage", group_id=group_id)


def constraints_for_request(db: Session, user: User, server_id: int) -> dict:
    memberships = active_memberships(db, user, server_id=server_id)
    if is_global_admin(user) or not settings.pam_group_scoped_access:
        return {"memberships": [], "allowed_access_types": {"ssh_only", "limited_sudo", "full_sudo"}, "allowed_durations": set(), "max_minutes": 10080, "require_approval": False, "require_mfa": False, "require_gateway": False, "deny_direct": False, "recording": False, "command_logging": False, "min_reason_length": 0, "max_concurrent_grants": 100, "max_active_sessions": 100, "time_allowed": True}
    groups = [membership.group for membership in memberships]
    allowed_sets = [{"ssh_only" if item == "ssh" else item for item in group.allowed_access_types.split(",") if item} for group in groups]
    durations = [{int(value) for value in group.allowed_durations.split(",") if value.strip().isdigit()} for group in groups]
    now = datetime.now(timezone.utc)
    time_allowed = all(str(now.weekday()) in {value.strip() for value in group.allowed_weekdays.split(",")} for group in groups)
    for group in groups:
        if group.allowed_hours:
            try:
                start, end = (int(value) for value in group.allowed_hours.split("-", 1))
                time_allowed = time_allowed and (start <= now.hour < end if start <= end else now.hour >= start or now.hour < end)
            except ValueError:
                time_allowed = False
    return {
        "memberships": memberships,
        "allowed_access_types": set.intersection(*allowed_sets) if allowed_sets else set(),
        "allowed_durations": set.intersection(*durations) if durations else set(),
        "max_minutes": min((group.max_grant_minutes for group in groups), default=0),
        "require_approval": any(group.require_approval for group in groups), "require_mfa": any(group.require_mfa for group in groups),
        "require_gateway": any(group.require_gateway for group in groups), "deny_direct": any(group.deny_direct_ssh for group in groups),
        "recording": any(group.require_session_recording for group in groups), "command_logging": any(group.require_command_logging for group in groups),
        "min_reason_length": max((group.min_reason_length if group.require_reason else 0 for group in groups), default=0),
        "max_concurrent_grants": min((group.max_concurrent_grants for group in groups), default=0),
        "max_active_sessions": min((group.max_active_sessions for group in groups), default=0), "time_allowed": time_allowed,
    }


def _permission(db: Session, code: str) -> Permission:
    item = db.query(Permission).filter(Permission.code == code).first()
    if not item:
        item = Permission(code=code, name=code, description=code, category=code.split(".", 1)[0], is_system=True)
        db.add(item); db.flush()
    return item


def seed_access_control(db: Session) -> None:
    for code in sorted(PERMISSIONS):
        _permission(db, code)
    for role, permissions in ROLE_PERMISSIONS.items():
        # Compatibility aliases can collapse to the same catalog permission.
        # Deduplicate before staging rows because queries do not see pending
        # INSERTs until the next flush.
        for code in {canonical_permission(item) for item in permissions}:
            permission = _permission(db, code)
            if not db.query(RolePermission).filter(RolePermission.role == role, RolePermission.permission_id == permission.id).first():
                db.add(RolePermission(role=role, permission_id=permission.id, allowed=True))
        db.flush()
    for name, permissions in TEMPLATES.items():
        item = db.query(PermissionTemplate).filter(PermissionTemplate.name == name).first()
        if not item:
            db.add(PermissionTemplate(name=name, description=name, permissions_json=json.dumps(permissions, ensure_ascii=False, sort_keys=True), built_in=True))
    db.flush()

    # Migrate the previously introduced access_groups tables into ServerGroup.
    for legacy in db.query(AccessGroup).all():
        group = db.query(ServerGroup).filter(ServerGroup.name == legacy.name).first()
        if not group:
            group = ServerGroup(name=legacy.name, description=legacy.description, environment=legacy.environment)
            db.add(group); db.flush()
        for field in ("allowed_access_types", "max_grant_minutes", "allowed_durations", "require_approval", "require_mfa", "require_gateway", "deny_direct_ssh", "require_command_logging", "require_session_recording", "allowed_hours", "allowed_weekdays", "max_concurrent_grants", "max_active_sessions", "allow_self_extension", "allow_auto_grant", "require_reason", "min_reason_length", "revoke_on_membership_loss", "terminate_sessions_on_membership_loss"):
            setattr(group, field, getattr(legacy, field))
        group.enabled = legacy.is_active
        for link in db.query(AccessGroupServer).filter(AccessGroupServer.access_group_id == legacy.id).all():
            if not db.query(ServerGroupMember).filter_by(server_group_id=group.id, server_id=link.server_id).first():
                db.add(ServerGroupMember(server_group_id=group.id, server_id=link.server_id, created_by_id=link.assigned_by_id))
        for old_member in db.query(AccessGroupUser).filter(AccessGroupUser.access_group_id == legacy.id).all():
            member = db.query(ServerGroupUserMembership).filter_by(server_group_id=group.id, user_id=old_member.user_id).first()
            if not member:
                db.add(ServerGroupUserMembership(server_group_id=group.id, user_id=old_member.user_id, group_role=old_member.group_role, enabled=old_member.is_active, valid_from=old_member.assigned_at, valid_to=old_member.expires_at, created_by_id=old_member.assigned_by_id, permission_template_id=old_member.permission_template_id))
        for old_permission in db.query(AccessGroupPermission).filter(AccessGroupPermission.access_group_id == legacy.id).all():
            permission = _permission(db, canonical_permission(old_permission.permission))
            if old_permission.membership_id:
                old_member = db.get(AccessGroupUser, old_permission.membership_id)
                if old_member and not db.query(UserGroupPermission).filter_by(server_group_id=group.id, user_id=old_member.user_id, permission_id=permission.id).first():
                    db.add(UserGroupPermission(server_group_id=group.id, user_id=old_member.user_id, permission_id=permission.id, allowed=old_permission.effect == "allow", created_by_id=old_permission.created_by_id))
            elif not db.query(GroupPermission).filter_by(server_group_id=group.id, permission_id=permission.id).first():
                db.add(GroupPermission(server_group_id=group.id, permission_id=permission.id, allowed=old_permission.effect == "allow", created_by_id=old_permission.created_by_id))

    # server_group_id is legacy input only; membership is the source of truth.
    for server in db.query(Server).filter(Server.server_group_id.is_not(None)).all():
        if db.get(ServerGroup, server.server_group_id) and not db.query(ServerGroupMember).filter_by(server_group_id=server.server_group_id, server_id=server.id).first():
            db.add(ServerGroupMember(server_group_id=server.server_group_id, server_id=server.id))

    # Existing installations retain broad access in an explicit system group.
    compatibility = db.query(ServerGroup).filter(ServerGroup.name == "Legacy compatibility").first()
    if not compatibility and db.query(User).count() and db.query(Server).count() and not db.query(ServerGroupUserMembership).count():
        compatibility = ServerGroup(name="Legacy compatibility", description="Pre-RBAC compatibility scope", environment="legacy", enabled=True, is_system=True, require_approval=False, allow_auto_grant=True, require_reason=False, min_reason_length=0, max_grant_minutes=480, allowed_access_types="ssh_only,limited_sudo,full_sudo", max_concurrent_grants=100, max_active_sessions=100)
        db.add(compatibility); db.flush()
        for server in db.query(Server).all():
            db.add(ServerGroupMember(server_group_id=compatibility.id, server_id=server.id))
        for user in db.query(User).all():
            role = normalized_role(user.role)
            db.add(ServerGroupUserMembership(server_group_id=compatibility.id, user_id=user.id, group_role="group_admin" if role == "admin" else "operator" if role == "operator" else "user"))
        for code in ("access.limited_sudo", "access.full_sudo", "servers.gateway_ssh"):
            permission = _permission(db, canonical_permission(code))
            db.add(GroupPermission(server_group_id=compatibility.id, permission_id=permission.id, allowed=True))

    # Earlier compatibility seeding accidentally made administrative secret
    # and alert capabilities group-wide. Remove only those known seed rows;
    # admins remain global and legacy operators retain the explicit compatibility
    # path in the relevant routes.
    if compatibility:
        privileged_ids = [item.id for item in db.query(Permission).filter(Permission.code.in_(["secrets.use", "alerts.manage"])).all()]
        if privileged_ids:
            db.query(GroupPermission).filter(GroupPermission.server_group_id == compatibility.id, GroupPermission.permission_id.in_(privileged_ids)).delete(synchronize_session=False)

    # New role is persisted; normalized_role keeps accepting old tokens/data.
    db.query(User).filter(User.role == "approver").update({"role": "operator"}, synchronize_session=False)
    db.commit()

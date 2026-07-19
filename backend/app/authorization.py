"""Single public authorization service.

The implementation remains in :mod:`app.rbac` so existing integrations keep
working. New code can use this facade without creating a second permission
engine. A top-level module is used because this project already has a legacy
``app/services.py`` module, which prevents a same-name package.
"""

from app.rbac import (
    PERMISSIONS, accessible_group_ids, active_memberships, can_manage_user,
    constraints_for_request, effective_permissions, has_permission,
    is_global_admin, permitted_server_ids, require_permission,
    scope_permission_query, scope_server_query, visible_server_ids,
)

get_effective_permissions = effective_permissions
get_accessible_server_ids = visible_server_ids
get_accessible_group_ids = accessible_group_ids


def can_access_server(db, user, server) -> bool:
    return bool(server and server.enabled and has_permission(db, user, "servers.view", server_id=server.id))


__all__ = [
    "PERMISSIONS", "active_memberships", "can_access_server", "can_manage_user",
    "constraints_for_request", "get_accessible_group_ids", "get_accessible_server_ids",
    "get_effective_permissions", "has_permission", "is_global_admin", "permitted_server_ids",
    "require_permission", "scope_permission_query", "scope_server_query",
]

from datetime import timedelta

from app.database import SessionLocal
from app.models import AccessGrant, AccessGroup, AccessGroupServer, AccessRequest, AuditLog, Server, ServerGroup, ServerGroupMember, ServerGroupUserMembership, User, utcnow
from app.rbac import seed_access_control
from app.session_monitor import import_jsonl_commands
SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAccessGroupKey rbac@test"


def auth_headers(client, username="admin", password="admin123"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_user(client, headers, username, role="user"):
    response = client.post(
        "/api/users",
        headers=headers,
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "role": role,
            "ssh_public_key": SSH_KEY,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def create_group(client, headers, name, **overrides):
    payload = {
        "name": name,
        "environment": "dev",
        "require_approval": False,
        "require_command_logging": True,
        "allowed_access_types": "ssh_only",
        "allowed_durations": "30,60",
        "max_grant_minutes": 60,
        "min_reason_length": 5,
        **overrides,
    }
    response = client.post("/api/access-groups", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def create_server(client, headers, hostname, address, group_ids):
    response = client.post(
        "/api/servers",
        headers=headers,
        json={
            "hostname": hostname,
            "ip_address": address,
            "ssh_port": 22,
            "environment": "dev",
            "command_logging_enabled": True,
            "access_group_ids": group_ids,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def assign(client, headers, group_id, user_id, role="user", expires_at=None):
    response = client.post(
        f"/api/access-groups/{group_id}/users",
        headers=headers,
        json={"user_ids": [user_id], "group_role": role, "expires_at": expires_at, "is_active": True},
    )
    assert response.status_code == 200, response.text
    return response.json()[0]


def test_group_lifecycle_multi_membership_and_idor_isolation(client):
    admin = auth_headers(client)
    alice = create_user(client, admin, "rbac_alice")
    group_a = create_group(client, admin, "RBAC Linux A")
    group_b = create_group(client, admin, "RBAC Linux B")
    server_a = create_server(client, admin, "rbac-a", "10.31.0.1", [group_a["id"]])
    server_b = create_server(client, admin, "rbac-b", "10.31.0.2", [group_b["id"]])
    alice_headers = auth_headers(client, "rbac_alice", "password123")
    assert client.get("/api/servers", headers=alice_headers).json() == []
    membership = assign(client, admin, group_a["id"], alice["id"])

    assert [item["id"] for item in client.get("/api/servers", headers=alice_headers).json()] == [server_a["id"]]
    assert client.get(f"/api/servers/{server_b['id']}", headers=alice_headers).status_code == 404
    assert client.post(
        "/api/access-requests",
        headers=alice_headers,
        json={"server_id": server_b["id"], "reason": "try foreign server", "requested_duration_minutes": 30, "requested_access_type": "ssh_only"},
    ).status_code == 404

    assign(client, admin, group_b["id"], alice["id"])
    assert {item["id"] for item in client.get("/api/servers", headers=alice_headers).json()} == {server_a["id"], server_b["id"]}
    expired = (utcnow() - timedelta(minutes=1)).isoformat()
    response = client.patch(
        f"/api/access-groups/{group_b['id']}/users/{alice['id']}",
        headers=admin,
        json={"expires_at": expired},
    )
    assert response.status_code == 200, response.text
    assert [item["id"] for item in client.get("/api/servers", headers=alice_headers).json()] == [server_a["id"]]

    response = client.patch(f"/api/access-groups/{group_a['id']}", headers=admin, json={"description": "edited"})
    assert response.status_code == 200 and response.json()["description"] == "edited"
    assert membership["assigned_by_id"] is not None


def test_explicit_deny_wins_across_groups_and_effective_permissions_explain_source(client):
    admin = auth_headers(client)
    user = create_user(client, admin, "rbac_deny")
    allow_group = create_group(client, admin, "RBAC Allow")
    deny_group = create_group(client, admin, "RBAC Deny")
    server = create_server(client, admin, "rbac-shared", "10.32.0.1", [allow_group["id"], deny_group["id"]])
    assign(client, admin, allow_group["id"], user["id"])
    assign(client, admin, deny_group["id"], user["id"])
    source_template = client.get("/api/permission-templates", headers=admin).json()[0]
    copied = client.post(f"/api/permission-templates/{source_template['id']}/copy", headers=admin, json={"name": "RBAC custom deny"})
    assert copied.status_code == 201, copied.text
    assert client.patch(f"/api/permission-templates/{copied.json()['id']}", headers=admin, json={"permissions": {"servers.view": "deny"}}).status_code == 200
    response = client.post(
        f"/api/access-groups/{deny_group['id']}/permissions/from-template/{copied.json()['id']}",
        headers=admin,
    )
    assert response.status_code == 200, response.text

    user_headers = auth_headers(client, "rbac_deny", "password123")
    assert client.get("/api/servers", headers=user_headers).json() == []
    assert client.get(f"/api/servers/{server['id']}", headers=user_headers).status_code == 404
    effective = client.get(f"/api/users/{user['id']}/effective-permissions?server_id={server['id']}", headers=admin).json()
    decision = next(item for item in effective if item["permission"] == "servers.view")
    assert decision["effect"] == "deny"
    assert decision["group_id"] == deny_group["id"]
    assert decision["source"] == "group_permission"


def test_group_constraints_gateway_mfa_duration_and_operator_approval(client):
    admin = auth_headers(client)
    user = create_user(client, admin, "rbac_requester")
    operator = create_user(client, admin, "rbac_operator", role="operator")
    group = create_group(
        client,
        admin,
        "RBAC Gateway",
        require_approval=True,
        require_gateway=True,
        deny_direct_ssh=True,
        allowed_durations="30",
        max_grant_minutes=30,
    )
    server = create_server(client, admin, "rbac-gateway", "10.33.0.1", [group["id"]])
    assign(client, admin, group["id"], user["id"])
    assign(client, admin, group["id"], operator["id"], role="operator")
    permissions = [
        {"permission": "access.connect_gateway", "effect": "allow", "membership_id": None},
        {"permission": "access.request", "effect": "allow", "membership_id": None},
    ]
    assert client.put(f"/api/access-groups/{group['id']}/permissions", headers=admin, json=permissions).status_code == 200

    user_headers = auth_headers(client, "rbac_requester", "password123")
    operator_headers = auth_headers(client, "rbac_operator", "password123")
    too_long = client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": server["id"], "reason": "maintenance work", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    assert too_long.status_code == 400
    request = client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": server["id"], "reason": "maintenance work", "requested_duration_minutes": 30, "requested_access_type": "ssh_only"},
    )
    assert request.status_code == 200, request.text
    assert request.json()["approval_required"] is True
    assert client.post(f"/api/access-requests/{request.json()['id']}/approve", headers=operator_headers, json={}).status_code == 200
    grant = client.get("/api/access-grants/active", headers=user_headers).json()[0]
    assert grant["gateway_session_required"] is True
    assert grant["direct_ssh_enabled"] is False

    db = SessionLocal()
    try:
        own_request = AccessRequest(user_id=operator["id"], server_id=server["id"], reason="operator maintenance", requested_duration_minutes=30, requested_access_type="ssh_only", status="pending", approval_required=True)
        db.add(own_request); db.commit(); db.refresh(own_request)
        own_request_id = own_request.id
    finally:
        db.close()
    assert client.post(f"/api/access-requests/{own_request_id}/approve", headers=operator_headers, json={}).status_code == 403

    mfa_user = create_user(client, admin, "rbac_mfa")
    assign(client, admin, group["id"], mfa_user["id"])
    assert client.patch(f"/api/access-groups/{group['id']}", headers=admin, json={"require_mfa": True}).status_code == 200
    mfa_headers = auth_headers(client, "rbac_mfa", "password123")
    response = client.post(
        "/api/access-requests",
        headers=mfa_headers,
        json={"server_id": server["id"], "reason": "mfa maintenance", "requested_duration_minutes": 30, "requested_access_type": "ssh_only"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "mfa_enrollment_required"


def test_membership_removal_revokes_grant_and_filters_group_audit(client):
    admin = auth_headers(client)
    user_a = create_user(client, admin, "rbac_remove_a")
    user_b = create_user(client, admin, "rbac_remove_b")
    operator = create_user(client, admin, "rbac_auditor", role="operator")
    group_a = create_group(client, admin, "RBAC Removal A")
    group_b = create_group(client, admin, "RBAC Removal B")
    server_a = create_server(client, admin, "rbac-remove-a", "10.34.0.1", [group_a["id"]])
    server_b = create_server(client, admin, "rbac-remove-b", "10.34.0.2", [group_b["id"]])
    assign(client, admin, group_a["id"], user_a["id"])
    assign(client, admin, group_b["id"], user_b["id"])
    assign(client, admin, group_a["id"], operator["id"], role="operator")
    user_a_headers = auth_headers(client, "rbac_remove_a", "password123")
    response = client.post(
        "/api/access-requests",
        headers=user_a_headers,
        json={"server_id": server_a["id"], "reason": "temporary access", "requested_duration_minutes": 30, "requested_access_type": "ssh_only"},
    )
    assert response.status_code == 200, response.text
    assert client.get("/api/access-grants/active", headers=user_a_headers).json()
    user_b_headers = auth_headers(client, "rbac_remove_b", "password123")
    assert client.post(
        "/api/access-requests",
        headers=user_b_headers,
        json={"server_id": server_b["id"], "reason": "separate group", "requested_duration_minutes": 30, "requested_access_type": "ssh_only"},
    ).status_code == 200

    db = SessionLocal()
    try:
        grants = db.query(AccessGrant).filter(AccessGrant.status == "active").all()
        for grant in grants:
            import_jsonl_commands(db, grant, [f'{{"type":"command","timestamp":"2026-07-19T10:00:00Z","grant_id":{grant.id},"session_id":"rbac-{grant.id}","linux_username":"{grant.linux_username}","pwd":"/tmp","command":"hostname"}}'])
        db.commit()
    finally:
        db.close()
    operator_headers = auth_headers(client, "rbac_auditor", "password123")
    assert {item["server_id"] for item in client.get("/api/sessions", headers=operator_headers).json()} == {server_a["id"]}
    assert {item["server_id"] for item in client.get("/api/session-commands", headers=operator_headers).json()} == {server_a["id"]}

    removed = client.delete(f"/api/access-groups/{group_a['id']}/users/{user_a['id']}", headers=admin)
    assert removed.status_code == 200, removed.text
    assert client.get("/api/servers", headers=user_a_headers).json() == []
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).filter(AccessGrant.user_id == user_a["id"], AccessGrant.server_id == server_a["id"]).first()
        assert grant.status == "revoked"
        assert grant.revoke_reason == "Server-group membership removed"
    finally:
        db.close()

    audit = client.get("/api/audit-logs", headers=operator_headers)
    assert audit.status_code == 200, audit.text
    assert all(item["server_id"] in {None, server_a["id"]} for item in audit.json())
    assert all(item["server_id"] != server_b["id"] for item in audit.json())


def test_manual_server_validation_and_connection_report_redacts_secrets(client, monkeypatch):
    admin = auth_headers(client)
    group = create_group(client, admin, "RBAC Server Validation")
    invalid = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "bad host!", "ip_address": "not a host!", "ssh_port": 70000, "access_group_ids": [group["id"]]},
    )
    assert invalid.status_code == 422
    server = create_server(client, admin, "rbac-validation", "host.example.test", [group["id"]])
    duplicate = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "other-name", "ip_address": "host.example.test", "ssh_port": 22, "access_group_ids": [group["id"]]},
    )
    assert duplicate.status_code == 409
    assert client.patch(f"/api/servers/{server['id']}", headers=admin, json={"ssh_port": 0}).status_code == 422

    class UnsafeExecutor:
        def test_connection(self, _server):
            return {"reachable": True, "checks": {"sudo": True}, "password": "leak", "private_key": "leak", "nested": [{"token": "leak", "ok": True}]}

    monkeypatch.setattr("app.routes.servers.get_executor", lambda: UnsafeExecutor())
    report = client.post(f"/api/servers/{server['id']}/test-connection", headers=admin)
    assert report.status_code == 200, report.text
    serialized = str(report.json())
    assert "leak" not in serialized
    assert report.json()["detail"]["checks"]["sudo"] is True


def test_legacy_server_group_migration_is_idempotent(client):
    db = SessionLocal()
    try:
        old_group = ServerGroup(name="Legacy taxonomy", environment="dev")
        db.add(old_group)
        db.flush()
        db.add(ServerGroupMember(server_group_id=old_group.id, server_id=1))
        db.commit()
        seed_access_control(db)
        seed_access_control(db)
        migrated = db.query(ServerGroup).filter(ServerGroup.name == "Legacy taxonomy").one()
        links = db.query(ServerGroupMember).filter(ServerGroupMember.server_group_id == migrated.id, ServerGroupMember.server_id == 1).count()
        assert links == 1
    finally:
        db.close()


def test_server_group_api_user_override_disabled_scope_and_safe_delete(client):
    admin = auth_headers(client)
    subject = create_user(client, admin, "rbac_override")
    group = create_group(client, admin, "RBAC Unified API")
    server = create_server(client, admin, "rbac-unified", "10.41.0.1", [group["id"]])
    assign(client, admin, group["id"], subject["id"], role="custom")

    assert client.get(f"/api/server-groups/{group['id']}", headers=admin).status_code == 200
    response = client.put(
        f"/api/server-groups/{group['id']}/users/{subject['id']}/permissions",
        headers=admin,
        json=[{"permission": "servers.view", "effect": "allow"}],
    )
    assert response.status_code == 200, response.text
    subject_headers = auth_headers(client, "rbac_override", "password123")
    assert [item["id"] for item in client.get("/api/servers", headers=subject_headers).json()] == [server["id"]]

    assert client.put(f"/api/server-groups/{group['id']}", headers=admin, json={"enabled": False}).status_code == 200
    assert client.get("/api/servers", headers=subject_headers).json() == []
    deleted = client.delete(f"/api/server-groups/{group['id']}", headers=admin)
    assert deleted.status_code == 200
    db = SessionLocal()
    try:
        assert db.get(Server, server["id"]) is not None
        assert db.get(User, subject["id"]) is not None
    finally:
        db.close()


def test_operator_without_member_permission_and_audit_context(client):
    admin = auth_headers(client)
    operator = create_user(client, admin, "rbac_limited_operator", role="operator")
    target = create_user(client, admin, "rbac_operator_target")
    group = create_group(client, admin, "RBAC Operator Boundary")
    assign(client, admin, group["id"], operator["id"], role="operator")
    operator_headers = auth_headers(client, "rbac_limited_operator", "password123")
    denied = client.post(
        f"/api/server-groups/{group['id']}/users",
        headers={**operator_headers, "User-Agent": "rbac-security-test"},
        json={"user_ids": [target["id"]], "group_role": "user"},
    )
    assert denied.status_code == 403
    db = SessionLocal()
    try:
        audit = db.query(AuditLog).filter(AuditLog.action == "access.denied", AuditLog.user_id == operator["id"]).order_by(AuditLog.id.desc()).first()
        assert audit and audit.result == "denied"
        assert audit.user_agent == "rbac-security-test"
        assert audit.object_type == "server_group" and audit.object_id == str(group["id"])
    finally:
        db.close()


def test_approver_migration_and_server_response_never_exposes_key_paths(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").one()
        user.role = "approver"
        server = db.get(Server, 1)
        server.ssh_private_key_path = "C:/sensitive/private-key"
        server.gateway_private_key_path = "C:/sensitive/gateway-key"
        db.commit()
        seed_access_control(db)
        assert user.role == "operator"
    finally:
        db.close()
    response = client.get("/api/servers/1", headers=auth_headers(client))
    assert response.status_code == 200
    assert "ssh_private_key_path" not in response.json()
    assert "gateway_private_key_path" not in response.json()
    assert "sensitive" not in response.text

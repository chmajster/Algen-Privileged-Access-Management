import json
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.gateway.proxy import target_connection_settings
from app.models import AuditLog, GroupPermission, Permission, Secret, Server, ServerGroup, ServerGroupUserMembership, User, utcnow
from app.database import SessionLocal


def auth_headers(client, username="admin", password="admin123"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def registration_payload(**updates):
    value = {
        "address": "192.168.44.10",
        "username": "root",
        "password": "NeverStoreThisPlaintext!",
        "hostname": "registered-dev.example",
        "description": "API registered target",
        "template_name": "linux-development",
        "test_connection": True,
    }
    value.update(updates)
    return value


def register(client, **updates):
    return client.post("/api/servers/register", headers=auth_headers(client), json=registration_payload(**updates))


def grant_user_registration_permissions(*codes):
    with SessionLocal() as db:
        group = db.query(ServerGroup).filter(ServerGroup.name == "Development").one()
        for code in codes:
            permission = db.query(Permission).filter(Permission.code == code).one()
            if not db.query(GroupPermission).filter_by(server_group_id=group.id, permission_id=permission.id).first():
                db.add(GroupPermission(server_group_id=group.id, permission_id=permission.id, allowed=True))
        db.commit()


def test_01_admin_registers_server(client):
    response = register(client)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "approved"
    assert response.json()["group_ids"]


def test_02_idempotency_returns_same_server(client):
    headers = {**auth_headers(client), "Idempotency-Key": "same-registration"}
    first = client.post("/api/servers/register", headers=headers, json=registration_payload())
    second = client.post("/api/servers/register", headers=headers, json=registration_payload())
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    with SessionLocal() as db:
        assert db.query(Server).filter(Server.hostname == "registered-dev.example").count() == 1


def test_03_idempotency_key_cannot_change_request(client):
    headers = {**auth_headers(client), "Idempotency-Key": "fixed-key"}
    assert client.post("/api/servers/register", headers=headers, json=registration_payload()).status_code == 201
    response = client.post("/api/servers/register", headers=headers, json=registration_payload(hostname="different.example"))
    assert response.status_code == 409


def test_04_duplicate_hostname_is_rejected(client):
    assert register(client).status_code == 201
    response = register(client, address="192.168.44.11")
    assert response.status_code == 409


def test_05_duplicate_address_and_port_is_rejected(client):
    assert register(client).status_code == 201
    response = register(client, hostname="other.example")
    assert response.status_code == 409


def test_06_password_is_only_encrypted_in_vault(client):
    response = register(client)
    assert response.status_code == 201
    with SessionLocal() as db:
        server = db.get(Server, response.json()["id"])
        secret = db.get(Secret, server.ssh_auth_secret_id)
        assert secret.secret_type == "ssh_password"
        assert secret.backend_type == "local_encrypted"
        assert "NeverStoreThisPlaintext" not in (secret.encrypted_value or "")
        assert "NeverStoreThisPlaintext" not in json.dumps({column.name: getattr(server, column.name) for column in Server.__table__.columns}, default=str)


def test_07_password_is_absent_from_api_response(client):
    response = register(client)
    assert response.status_code == 201
    assert "NeverStoreThisPlaintext" not in response.text


def test_08_failed_connection_rolls_back_server_and_secret(client, monkeypatch):
    monkeypatch.setattr("app.routes.server_registrations.test_password_connection", lambda **_: {"ok": False, "status": "authentication_failed"})
    response = register(client)
    assert response.status_code == 400
    assert response.headers["x-connection-status"] == "authentication_failed"
    with SessionLocal() as db:
        assert not db.query(Server).filter(Server.hostname == "registered-dev.example").first()
        assert not db.query(Secret).filter(Secret.name.like("server-registration-registered-dev.example-%")).first()


def test_09_success_writes_required_audit_events(client):
    response = register(client)
    assert response.status_code == 201
    with SessionLocal() as db:
        actions = {row.action for row in db.query(AuditLog).filter(AuditLog.server_id == response.json()["id"]).all()}
    assert {"server_registration_requested", "server_connection_test_succeeded", "server_credential_created", "server_registered"}.issubset(actions)


def test_10_production_template_creates_pending_registration(client):
    response = register(client, address="10.55.0.10", hostname="pending-prod.example", template_name="linux-production")
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "pending_approval"
    assert response.json()["enabled"] is False


def test_11_pending_registration_can_be_approved(client):
    created = register(client, address="10.55.0.11", hostname="approve-prod.example", template_name="linux-production").json()
    response = client.post(f"/api/server-registrations/{created['id']}/approve", headers=auth_headers(client), json={"reason": "verified"})
    assert response.status_code == 200
    assert response.json()["status"] == "approved" and response.json()["enabled"] is True


def test_12_rejection_disables_credential(client):
    created = register(client, address="10.55.0.12", hostname="reject-prod.example", template_name="linux-production").json()
    response = client.post(f"/api/server-registrations/{created['id']}/reject", headers=auth_headers(client), json={"reason": "not managed"})
    assert response.status_code == 200 and response.json()["status"] == "rejected"
    with SessionLocal() as db:
        server = db.get(Server, created["id"])
        assert db.get(Secret, server.ssh_auth_secret_id).status == "disabled"


def test_13_pending_registration_is_not_visible_to_regular_user(client):
    created = register(client, address="10.55.0.13", hostname="hidden-prod.example", template_name="linux-production").json()
    response = client.get("/api/servers", headers=auth_headers(client, "user", "user123"))
    assert response.status_code == 200
    assert created["id"] not in {item["id"] for item in response.json()}


@pytest.mark.parametrize(
    "template_fields",
    [
        {},
        {"template_id": 1, "template_name": "linux-development"},
        {"template_name": "missing-template"},
    ],
)
def test_14_16_exactly_one_existing_template_is_required(client, template_fields):
    payload = registration_payload()
    payload.pop("template_name")
    payload.update(template_fields)
    response = client.post("/api/servers/register", headers=auth_headers(client), json=payload)
    assert response.status_code in {404, 422}


@pytest.mark.parametrize(
    ("updates", "expected_status"),
    [
        ({"ssh_port": 0}, 422),
        ({"username": "root;rm"}, 422),
        ({"address": "127.0.0.1", "ssh_port": 2222}, 400),
        ({"unexpected": "value"}, 422),
    ],
)
def test_17_20_registration_input_is_strictly_validated(client, updates, expected_status):
    response = client.post("/api/servers/register", headers=auth_headers(client), json=registration_payload(**updates))
    assert response.status_code == expected_status


def test_user_with_explicit_permissions_can_register(client):
    grant_user_registration_permissions("servers.register_via_api", "servers.use_template", "servers.provide_credentials", "servers.test_connection")
    response = client.post("/api/servers/register", headers=auth_headers(client, "user", "user123"), json=registration_payload())
    assert response.status_code == 201, response.text


def test_user_without_registration_permission_gets_403(client):
    response = client.post("/api/servers/register", headers=auth_headers(client, "user", "user123"), json=registration_payload(test_connection=False))
    assert response.status_code == 403


def test_user_cannot_use_template_outside_scope(client):
    grant_user_registration_permissions("servers.register_via_api", "servers.use_template", "servers.provide_credentials")
    response = client.post("/api/servers/register", headers=auth_headers(client, "user", "user123"), json=registration_payload(address="10.70.0.1", hostname="prod-forbidden.example", template_name="linux-production", test_connection=False))
    assert response.status_code == 403


def test_user_cannot_assign_foreign_group(client):
    grant_user_registration_permissions("servers.register_via_api", "servers.use_template", "servers.provide_credentials", "servers.assign_to_group")
    with SessionLocal() as db:
        production_id = db.query(ServerGroup.id).filter(ServerGroup.name == "Production").scalar()
    response = client.post("/api/servers/register", headers=auth_headers(client, "user", "user123"), json=registration_payload(group_ids=[production_id], test_connection=False))
    assert response.status_code == 403


def test_password_never_appears_in_audit_log(client):
    assert register(client).status_code == 201
    with SessionLocal() as db:
        serialized = "\n".join((row.message or "") + (row.metadata_json or "") for row in db.query(AuditLog).all())
    assert "NeverStoreThisPlaintext" not in serialized


def test_template_security_cannot_be_overridden(client):
    response = client.post("/api/servers/register", headers=auth_headers(client), json=registration_payload(require_mfa=False))
    assert response.status_code == 422


def test_expired_group_membership_cannot_use_template(client):
    grant_user_registration_permissions("servers.register_via_api", "servers.use_template", "servers.provide_credentials")
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "user").one()
        group = db.query(ServerGroup).filter(ServerGroup.name == "Development").one()
        membership = db.query(ServerGroupUserMembership).filter_by(user_id=user.id, server_group_id=group.id).one()
        membership.valid_to = utcnow() - timedelta(minutes=1)
        db.commit()
    response = client.post("/api/servers/register", headers=auth_headers(client, "user", "user123"), json=registration_payload(test_connection=False))
    assert response.status_code == 403


def test_gateway_rejects_pending_registration(client):
    created = register(client, address="10.55.1.1", hostname="gateway-pending.example", template_name="linux-production").json()
    with SessionLocal() as db:
        server = db.get(Server, created["id"])
        with pytest.raises(RuntimeError, match="not approved"):
            target_connection_settings(SimpleNamespace(server=server))


def test_host_key_mismatch_blocks_registration_without_private_error(client, monkeypatch):
    monkeypatch.setattr("app.routes.server_registrations.test_password_connection", lambda **_: {"ok": False, "status": "host_key_mismatch"})
    response = register(client)
    assert response.status_code == 400
    assert response.headers["x-connection-status"] == "host_key_mismatch"
    assert "NeverStoreThisPlaintext" not in response.text

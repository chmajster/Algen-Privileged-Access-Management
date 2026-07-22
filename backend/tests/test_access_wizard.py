from app.database import SessionLocal
from app.models import (
    AccessWizardDraft,
    AccessWizardSubmission,
    Secret,
    Server,
    ServerGroup,
    ServerGroupMember,
    ServerGroupUserMembership,
)
from app.wizard_schemas import CheckResult


def auth_headers(client, username="admin", password="admin123"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_user(client, headers, username):
    response = client.post(
        "/api/users",
        headers=headers,
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "password123",
            "role": "user",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def wizard_data(hostname="wizard-target.example.test"):
    return {
        "resource": {
            "name": "Serwer rozliczeniowy",
            "description": "Dostęp administracyjny",
            "environment": "prod",
            "owner": "Platform Team",
            "criticality": "high",
            "tags": ["finance", "linux"],
            "enabled": True,
            "new_group_name": "Zasoby kreatora",
        },
        "connection": {
            "hostname": hostname,
            "port": 22,
            "target_username": "operator",
            "administrative_username": "pam-broker",
            "authentication_type": "password",
            "secret_input_key": "ssh_password",
            "host_key_policy": "strict",
            "expected_host_key_fingerprint": "SHA256:test",
            "connection_timeout_seconds": 10,
            "gateway_enabled": True,
            "direct_access_enabled": False,
            "sudo_mode": "none",
        },
        "access_profile": {
            "name": "Profil kreatora",
            "description": "Profil utworzony atomowo",
            "access_option": "ssh_only",
            "allowed_durations": [30, 60],
        },
        "policy": {
            "require_approval": True,
            "require_mfa": True,
            "require_recording": True,
            "require_command_logging": True,
            "maximum_duration_minutes": 60,
        },
        "assignments": [
            {"subject_type": "role", "subject_identifier": "admin", "assignment_mode": "request_required"}
        ],
        "connection_test": {"passed": True},
    }


async def successful_ssh_test(*_args, **_kwargs):
    return [
        CheckResult(name=name, status="success", message="OK")
        for name in ("dns", "tcp", "host_key", "authentication", "required_privileges")
    ]


def create_wizard_draft(client, headers, data=None):
    response = client.post(
        "/api/access-wizard/drafts",
        headers=headers,
        json={"mode": "create_resource", "resource_type": "ssh", "data": data or wizard_data()},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_presets_and_drafts_are_safe(client):
    headers = auth_headers(client)
    response = client.get("/api/access-wizard/presets", headers=headers)
    assert response.status_code == 200
    presets = response.json()
    assert set(presets) == {
        "ssh_standard", "ssh_limited_sudo", "ssh_full_sudo",
        "web_no_auth", "web_form", "web_manual", "custom",
    }
    assert presets["ssh_standard"]["connection"]["host_key_policy"] == "strict"
    assert presets["ssh_standard"]["connection"]["direct_access_enabled"] is False
    assert presets["ssh_full_sudo"]["policy"]["require_mfa"] is True

    rejected = client.post(
        "/api/access-wizard/drafts",
        headers=headers,
        json={"mode": "create_resource", "resource_type": "ssh", "data": {"password": "do-not-store-me"}},
    )
    assert rejected.status_code == 422
    assert "do-not-store-me" not in rejected.text

    draft = create_wizard_draft(client, headers)
    assert draft["completed_steps"] == []
    patched = client.patch(
        f"/api/access-wizard/drafts/{draft['id']}",
        headers=headers,
        json={"completed_steps": [3, 1, 3, 2]},
    )
    assert patched.status_code == 200
    assert patched.json()["completed_steps"] == [1, 2, 3]
    assert "do-not-store-me" not in patched.text


def test_non_admin_gets_request_only_wizard(client):
    admin = auth_headers(client)
    create_user(client, admin, "wizard_requester")
    user = auth_headers(client, "wizard_requester", "password123")

    forbidden = client.post(
        "/api/access-wizard/drafts",
        headers=user,
        json={"mode": "create_resource", "resource_type": "ssh", "data": {}},
    )
    assert forbidden.status_code == 403
    request_draft = client.post(
        "/api/access-wizard/drafts",
        headers=user,
        json={"mode": "request_access", "data": {}},
    )
    assert request_draft.status_code == 201, request_draft.text
    assert request_draft.json()["mode"] == "request_access"


def test_complete_is_atomic_idempotent_and_encrypts_transient_secret(client, monkeypatch):
    import app.routes.access_wizard as wizard_routes

    monkeypatch.setattr(wizard_routes, "test_ssh_connection", successful_ssh_test)
    headers = auth_headers(client)
    draft = create_wizard_draft(client, headers)
    payload = {
        "draft_id": draft["id"],
        "submission_key": "wizard-success-001",
        "secret_inputs": {
            "ssh_password": {
                "name": "Sekret SSH kreatora",
                "secret_type": "password",
                "value": "NeverStoreThisInDraft!",
            }
        },
    }
    response = client.post("/api/access-wizard/complete", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["duplicate"] is False

    with SessionLocal() as db:
        server = db.get(Server, result["server_id"])
        group = db.get(ServerGroup, result["access_group_id"])
        secret = db.query(Secret).filter_by(name="Sekret SSH kreatora").one()
        assert server.display_name == "Serwer rozliczeniowy"
        assert server.host_key_policy == "strict"
        assert server.direct_access_enabled is False
        assert server.ssh_auth_secret_id == secret.id
        assert "NeverStoreThisInDraft!" not in (secret.encrypted_value or "")
        assert group.name == "PROD-ENV-CUSTOM-PROFIL-KREATORA"
        assert result["safe_name"] == group.name
        assert group.require_mfa is True and group.require_session_recording is True
        assert db.query(ServerGroupMember).filter_by(server_group_id=group.id, server_id=server.id).count() == 1
        assert db.query(ServerGroupUserMembership).filter_by(server_group_id=group.id).count() >= 1
        assert db.get(AccessWizardDraft, draft["id"]) is None
        assert db.query(AccessWizardSubmission).filter_by(submission_key="wizard-success-001").count() == 1

    repeated = client.post("/api/access-wizard/complete", headers=headers, json=payload)
    assert repeated.status_code == 200
    assert repeated.json()["duplicate"] is True
    assert repeated.json()["server_id"] == result["server_id"]


def test_complete_rolls_back_every_created_object(client, monkeypatch):
    import app.routes.access_wizard as wizard_routes
    import app.wizard_service as wizard_service

    monkeypatch.setattr(wizard_routes, "test_ssh_connection", successful_ssh_test)
    headers = auth_headers(client)
    data = wizard_data("rollback-target.example.test")
    data["resource"]["new_group_name"] = "Rollback resource group"
    data["access_profile"]["name"] = "Rollback access profile"
    draft = create_wizard_draft(client, headers, data)

    def fail_before_commit():
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(wizard_service, "_before_commit_hook", fail_before_commit)
    response = client.post(
        "/api/access-wizard/complete",
        headers=headers,
        json={
            "draft_id": draft["id"],
            "submission_key": "wizard-rollback-001",
            "secret_inputs": {
                "ssh_password": {
                    "name": "Rollback secret",
                    "secret_type": "password",
                    "value": "must-not-survive",
                }
            },
        },
    )
    assert response.status_code == 500
    assert "simulated database failure" not in response.text
    assert "must-not-survive" not in response.text

    with SessionLocal() as db:
        assert db.query(Server).filter_by(hostname="rollback-target.example.test").count() == 0
        assert db.query(ServerGroup).filter(ServerGroup.name.in_(["Rollback resource group", "PROD-ENV-CUSTOM-ROLLBACK-ACCESS-PROFILE"])).count() == 0
        assert db.query(Secret).filter_by(name="Rollback secret").count() == 0
        assert db.query(AccessWizardSubmission).filter_by(submission_key="wizard-rollback-001").count() == 0
        assert db.get(AccessWizardDraft, draft["id"]) is not None


def test_url_validation_rejects_unsafe_schemes(client):
    headers = auth_headers(client)
    payload = {
        "mode": "create_resource",
        "resource_type": "web",
        "step": 3,
        "data": {
            "connection": {
                "start_url": "file:///etc/passwd",
                "allowed_domains": ["example.test"],
            }
        },
    }
    response = client.post("/api/access-wizard/validate-step", headers=headers, json=payload)
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"][0]["field"] == "connection.start_url"

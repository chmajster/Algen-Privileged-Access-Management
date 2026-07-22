import json

from app.database import SessionLocal
from app.models import MfaChallenge, PamPolicy, StepUpSession, User

from .conftest import auth_headers


def test_seeded_policies_and_mfa_are_disabled_by_default(client):
    with SessionLocal() as db:
        policies = db.query(PamPolicy).all()
        assert policies
        assert all(policy.status == "disabled" for policy in policies)

        users = db.query(User).all()
        assert users
        assert all(user.mfa_required is False for user in users)
        assert db.query(MfaChallenge).count() == 0
        assert db.query(StepUpSession).count() == 0

    response = client.get("/api/policies/definitions", headers=auth_headers(client))
    assert response.status_code == 200, response.text
    boolean_definitions = [item for item in response.json() if item["value_type"] == "boolean"]
    assert boolean_definitions
    assert all(item["default_value"] is False for item in boolean_definitions)


def test_policy_create_and_update_persist(client):
    headers = auth_headers(client)
    payload = {
        "policy_id": "test.ip_policy",
        "category": "Authentication & Access",
        "name": "Test IP policy",
        "status": "enabled",
        "value_json": '"10.20.30.40"',
        "scope": "global",
        "priority": 100,
        "exceptions_json": "[]",
    }
    created = client.post("/api/policies", headers=headers, json=payload)
    assert created.status_code == 200, created.text

    policy_id = created.json()["id"]
    updated = client.put(
        f"/api/policies/{policy_id}",
        headers=headers,
        json={"value_json": '"10.20.30.41"', "scope": "resource", "scope_target": "1"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["value_json"] == '"10.20.30.41"'
    assert updated.json()["scope"] == "resource"


def test_request_connect_form_is_built_and_enforced_from_policy(client):
    with SessionLocal() as db:
        policy = db.query(PamPolicy).filter(PamPolicy.policy_id == "request.form_schema").one()
        policy.status = "enabled"
        policy.value_json = json.dumps({
            "title": "Poproś o połączenie",
            "submit_label": "Wyślij",
            "access_types": ["ssh_only"],
            "durations": [30, 60],
            "show_reason": False,
            "default_reason": "Request utworzony z formularza polityki",
            "warning": "Dostęp wymaga akceptacji.",
        })
        db.commit()

    headers = auth_headers(client)
    config = client.get("/api/access-requests/form-config", headers=headers)
    assert config.status_code == 200, config.text
    assert config.json()["title"] == "Poproś o połączenie"
    assert config.json()["access_types"] == ["ssh_only"]
    assert config.json()["durations"] == [30, 60]
    assert config.json()["show_reason"] is False

    rejected = client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "test", "requested_duration_minutes": 15, "requested_access_type": "full_sudo"},
    )
    assert rejected.status_code == 400
    assert "Request connect form policy" in rejected.json()["detail"]

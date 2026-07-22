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

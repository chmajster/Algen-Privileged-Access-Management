from .conftest import auth_headers


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

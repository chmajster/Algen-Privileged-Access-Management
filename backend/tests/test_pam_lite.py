from datetime import timedelta
import importlib
from types import SimpleNamespace

from app.config import settings
from app.database import SessionLocal
from app.gateway.auth import find_user_for_gateway_login
from app.gateway.command_detector import CommandDetector
from app.gateway.proxy import target_connection_settings
from app.gateway.policy import active_gateway_grants, choose_gateway_grant, parse_gateway_username
from app.models import AccessGrant, Alert, AuditLog, AuthEvent, GatewayConnection, GatewayRecording, PolicyRule, RiskEvent, Secret, SecretAccessLog, SecretRotationJob, SecretVersion, Server, ServerGroup, SessionCommand, StepUpSession, User, utcnow
from app.mfa.recovery_codes import generate_recovery_codes
from app.mfa.totp import current_totp, encrypt_mfa_secret, generate_secret, verify_totp
from app.scheduler import enforce_gateway_sessions, expire_due_grants
from app.security import sanitize_linux_username, validate_linux_username
from app.session_monitor import detect_sudo_command, import_jsonl_commands, import_session_logs_for_grant, parse_command_logs, parse_session_logs
from app.vault import get_vault_backend_for_secret
from app.vault.crypto import decrypt_secret
from app.vault.rotation import rotate_secret_value

from .conftest import auth_headers


def grant_step_up(username: str = "admin", context: str = "edit_policy"):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user.mfa_enabled:
            user.mfa_enabled = True
            user.mfa_required = True
            user.mfa_secret_encrypted = encrypt_mfa_secret(generate_secret())
        db.add(StepUpSession(user_id=user.id, context=context, valid_until=utcnow() + timedelta(minutes=15)))
        db.commit()
    finally:
        db.close()


def test_login(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_local_os_account_login_and_auto_provision(client, monkeypatch):
    from app.identity import local_provider

    monkeypatch.setattr(settings, "pam_local_auth_mode", "os")
    monkeypatch.setattr(settings, "pam_os_admin_users", "root")
    monkeypatch.setattr(local_provider, "_os_account", lambda username: SimpleNamespace(pw_uid=1001, pw_gecos="System User"))
    monkeypatch.setattr(local_provider, "authenticate_os_account", lambda username, password: username == "system_user" and password == "os-password")

    response = client.post("/api/auth/login", json={"username": "system_user", "password": "os-password", "provider": "local"})
    assert response.status_code == 200, response.text
    assert response.json()["access_token"]
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "system_user").first()
        assert user is not None
        assert user.external_id == "uid:1001"
        assert user.display_name == "System User"
        assert user.role == "user"
    finally:
        db.close()


def test_local_os_backend_error_returns_503(client, monkeypatch):
    from app.identity import local_provider

    monkeypatch.setattr(settings, "pam_local_auth_mode", "os")
    monkeypatch.setattr(local_provider, "_os_account", lambda username: SimpleNamespace(pw_uid=1001, pw_gecos="System User"))

    def unavailable(username, password):
        raise local_provider.LocalAuthenticationBackendError("unavailable")

    monkeypatch.setattr(local_provider, "authenticate_os_account", unavailable)
    response = client.post("/api/auth/login", json={"username": "system_user", "password": "password", "provider": "local"})
    assert response.status_code == 503
    assert "PAM" in response.json()["detail"]


def test_health_returns_503_when_os_pam_is_unavailable(client, monkeypatch):
    from app.identity.local_provider import LocalAuthenticationBackendError

    main_module = importlib.import_module("app.main")
    monkeypatch.setattr(settings, "pam_local_auth_mode", "os")

    def unavailable():
        raise LocalAuthenticationBackendError("libpam missing")

    monkeypatch.setattr(main_module, "validate_os_auth_backend", unavailable)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert "PAM" in response.json()["detail"]


def test_local_login_with_mfa(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        secret = generate_secret()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        db.commit()
    finally:
        db.close()
    response = client.post("/api/auth/login", json={"username": "user", "password": "user123", "provider": "local"})
    assert response.status_code == 200
    assert response.json()["mfa_required"] is True
    verified = client.post("/api/mfa/verify", json={"mfa_token": response.json()["mfa_token"], "challenge_id": response.json()["challenge_id"], "code": current_totp(secret)})
    assert verified.status_code == 200, verified.text
    assert verified.json()["access_token"]


def test_bad_mfa_code_rejects_login(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(generate_secret())
        db.commit()
    finally:
        db.close()
    response = client.post("/api/auth/login", json={"username": "user", "password": "user123"})
    rejected = client.post("/api/mfa/verify", json={"mfa_token": response.json()["mfa_token"], "challenge_id": response.json()["challenge_id"], "code": "000000"})
    assert rejected.status_code == 401


def test_mfa_failures_lock_account(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(generate_secret())
        db.commit()
    finally:
        db.close()
    for _ in range(5):
        response = client.post("/api/auth/login", json={"username": "user", "password": "user123"})
        client.post("/api/mfa/verify", json={"mfa_token": response.json()["mfa_token"], "challenge_id": response.json()["challenge_id"], "code": "000000"})
    locked = client.post("/api/auth/login", json={"username": "user", "password": "user123"})
    assert locked.status_code == 401


def test_recovery_code_works_once(client):
    headers = auth_headers(client, "user", "user123")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        code = generate_recovery_codes(db, user, count=1)[0]
        db.commit()
    finally:
        db.close()
    challenge = client.post("/api/mfa/step-up", headers=headers, json={"context": "manual_revoke"}).json()
    assert client.post("/api/mfa/recovery-codes/verify", json={"challenge_id": challenge["id"], "code": code, "recovery_code": True}).status_code == 200
    second = client.post("/api/mfa/recovery-codes/verify", json={"challenge_id": challenge["id"], "code": code, "recovery_code": True})
    assert second.status_code in {400, 401}


def test_admin_step_up_required_for_policy_change(client):
    headers = auth_headers(client)
    response = client.post("/api/policy-rules", headers=headers, json={"name": "Needs MFA", "rule_type": "command", "condition_json": "{}", "action_json": "{}", "risk_score_delta": 0})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "mfa_enrollment_required"


def test_role_access_control(client):
    headers = auth_headers(client, "user", "user123")
    response = client.get("/api/users", headers=headers)
    assert response.status_code == 403


def test_automatic_grant_without_approval(client):
    headers = auth_headers(client, "user", "user123")
    response = client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "dev work", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"
    grants = client.get("/api/access-grants/active", headers=headers).json()
    assert len(grants) == 1
    assert grants[0]["linux_username"] == "pam_user"


def test_create_request_requiring_approval_and_approve(client):
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "test-linux", "ip_address": "10.0.0.5", "environment": "test", "command_logging_enabled": True},
    ).json()
    user = auth_headers(client, "user", "user123")
    request = client.post(
        "/api/access-requests",
        headers=user,
        json={"server_id": server["id"], "reason": "read logs", "requested_duration_minutes": 60, "requested_access_type": "limited_sudo"},
    )
    assert request.status_code == 200, request.text
    assert request.json()["status"] == "pending"
    approver = auth_headers(client, "approver", "approver123")
    approved = client.post(f"/api/access-requests/{request.json()['id']}/approve", headers=approver, json={"approver_comment": "ok"})
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"


def test_user_cannot_approve_own_request(client):
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "self-approval-linux", "ip_address": "10.0.0.6", "environment": "dev", "command_logging_enabled": True, "session_recording_enabled": True},
    ).json()
    admin_request = client.post(
        "/api/access-requests",
        headers=admin,
        json={"server_id": server["id"], "reason": "self approval check", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    assert admin_request.status_code == 200
    blocked = client.post(f"/api/access-requests/{admin_request.json()['id']}/approve", headers=admin, json={})
    assert blocked.status_code == 403


def test_scheduler_expires_access(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "short task", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        grant.valid_to = utcnow() - timedelta(minutes=1)
        db.commit()
        assert expire_due_grants(db) == 1
        db.refresh(grant)
        assert grant.status == "expired"
    finally:
        db.close()


def test_audit_log_created_after_action(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "audit", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(AuditLog.action == "request.created").count() >= 1
        assert db.query(AuditLog).filter(AuditLog.action == "grant.created").count() >= 1
    finally:
        db.close()


def test_linux_username_validation():
    username = sanitize_linux_username("User.Name+Admin_12345678901234567890")
    assert username.startswith("pam_")
    assert len(username) <= 32
    assert validate_linux_username(username)


def test_mock_mode_creates_session_and_commands(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "mock", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    sessions = client.get("/api/sessions", headers=headers).json()
    commands = client.get("/api/session-commands", headers=headers).json()
    assert len(sessions) == 1
    assert len(commands) >= 3


def test_import_commands_and_export(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "import", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        imported = import_jsonl_commands(db, grant, ['{"command":"sudo id","pwd":"/tmp","exit_code":0}'])
        db.commit()
        assert imported == 1
    finally:
        db.close()
    exported = client.get("/api/session-commands/export.csv", headers=headers)
    assert exported.status_code == 200
    assert "sudo id" in exported.text


def test_parser_jsonl_logs():
    commands = parse_command_logs(
        '{"type":"command","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"abc","linux_username":"pam_user","pwd":"/tmp","command":"sudo id","ssh_connection":"10.0.0.1 555 10.0.0.2 22"}'
    )
    sessions = parse_session_logs(
        '{"type":"session_started","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"abc","linux_username":"pam_user","ssh_connection":"10.0.0.1 555 10.0.0.2 22"}'
    )
    assert commands[0]["command"] == "sudo id"
    assert commands[0]["is_sudo"] is True
    assert sessions[0]["type"] == "session_started"
    assert detect_sudo_command("cd /tmp && sudo systemctl status nginx")


def test_deduplicates_commands(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "dedupe", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    line = '{"type":"command","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"manual","linux_username":"pam_user","pwd":"/tmp","command":"whoami"}'
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        assert import_jsonl_commands(db, grant, [line]) == 1
        assert import_jsonl_commands(db, grant, [line]) == 0
        db.commit()
    finally:
        db.close()


def test_user_sees_only_own_commands_and_admin_sees_all(client):
    user_headers = auth_headers(client, "user", "user123")
    admin_headers = auth_headers(client)
    client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": 1, "reason": "user commands", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    client.post(
        "/api/access-requests",
        headers=admin_headers,
        json={"server_id": 1, "reason": "admin commands", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    user_commands = client.get("/api/session-commands", headers=user_headers).json()
    admin_commands = client.get("/api/session-commands", headers=admin_headers).json()
    assert user_commands
    assert {item["username"] for item in user_commands} == {"user"}
    assert len(admin_commands) > len(user_commands)


def test_sessions_export_csv(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "sessions export", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    exported = client.get("/api/sessions/export.csv", headers=headers)
    assert exported.status_code == 200
    assert "linux_username" in exported.text


def test_revoke_imports_logs_before_access_removed(client):
    user_headers = auth_headers(client, "user", "user123")
    approver_headers = auth_headers(client, "approver", "approver123")
    client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": 1, "reason": "revoke import", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    grant = client.get("/api/access-grants/active", headers=user_headers).json()[0]
    response = client.post(f"/api/access-grants/{grant['id']}/revoke", headers=approver_headers, json={"reason": "test"})
    assert response.status_code == 200
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(AuditLog.action == "session_log_imported").count() >= 1
        assert db.query(AuditLog).filter(AuditLog.action == "grant.revoked").count() == 1
    finally:
        db.close()


def test_session_log_import_failed_creates_audit_log(client, monkeypatch):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "failed import", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.session_monitor.fetch_session_logs", broken)
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        try:
            import_session_logs_for_grant(db, grant)
        except RuntimeError:
            pass
        assert db.query(AuditLog).filter(AuditLog.action == "session_log_import_failed").count() >= 1
    finally:
        db.close()


def test_dashboard_sudo_count_source_data(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "sudo dashboard", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        assert db.query(SessionCommand).filter(SessionCommand.is_sudo.is_(True)).count() >= 1
    finally:
        db.close()


def test_policy_engine_scores_prod_full_sudo_request(client):
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "risk-prod", "ip_address": "10.10.0.10", "environment": "prod", "criticality": "critical", "command_logging_enabled": True, "session_recording_enabled": True},
    ).json()
    user_headers = auth_headers(client, "user", "user123")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        secret = generate_secret()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(secret)
        db.add(StepUpSession(user_id=user.id, context="prod_full_sudo_request", valid_until=utcnow() + timedelta(minutes=15)))
        db.commit()
    finally:
        db.close()
    response = client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": server["id"], "reason": "emergency fix", "requested_duration_minutes": 60, "requested_access_type": "full_sudo"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["calculated_risk_score"] >= 60
    assert body["approval_required"] is True
    assert body["session_recording_required"] is True


def test_prod_request_requires_mfa_without_step_up(client):
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "prod-mfa", "ip_address": "10.10.0.11", "environment": "prod", "command_logging_enabled": True, "session_recording_enabled": True},
    ).json()
    user_headers = auth_headers(client, "user", "user123")
    response = client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": server["id"], "reason": "prod", "requested_duration_minutes": 60, "requested_access_type": "limited_sudo"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "mfa_enrollment_required"


def test_approve_high_risk_requires_step_up(client):
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "high-risk-approve", "ip_address": "10.10.0.12", "environment": "prod", "command_logging_enabled": True, "session_recording_enabled": True},
    ).json()
    user_headers = auth_headers(client, "user", "user123")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(generate_secret())
        db.add(StepUpSession(user_id=user.id, context="prod_full_sudo_request", valid_until=utcnow() + timedelta(minutes=15)))
        db.commit()
    finally:
        db.close()
    request = client.post("/api/access-requests", headers=user_headers, json={"server_id": server["id"], "reason": "high risk", "requested_duration_minutes": 60, "requested_access_type": "full_sudo"}).json()
    approver_headers = auth_headers(client, "approver", "approver123")
    blocked = client.post(f"/api/access-requests/{request['id']}/approve", headers=approver_headers, json={"approver_comment": "ok"})
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "mfa_enrollment_required"


def test_secret_rotation_requires_step_up(client):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "rotate needs mfa", "secret_type": "generic", "backend_type": "local_encrypted", "value": "old"}).json()
    response = client.post(f"/api/secrets/{secret['id']}/rotate", headers=headers)
    assert response.status_code == 403


def test_audit_export_requires_step_up(client):
    headers = auth_headers(client)
    response = client.get("/api/audit-logs/export.csv", headers=headers)
    assert response.status_code == 403


def test_recording_access_requires_step_up_for_admin(client):
    user_headers = auth_headers(client, "user", "user123")
    client.post("/api/access-requests", headers=user_headers, json={"server_id": 1, "reason": "recording mfa", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"})
    admin_headers = auth_headers(client)
    session_id = client.get("/api/sessions", headers=admin_headers).json()[0]["id"]
    response = client.get(f"/api/sessions/{session_id}/recording", headers=admin_headers)
    assert response.status_code == 403


def test_gateway_login_without_step_up_is_denied(client, monkeypatch):
    from app.gateway.auth import authorize_gateway_login

    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    headers = auth_headers(client, "user", "user123")
    client.post("/api/access-requests", headers=headers, json={"server_id": 1, "reason": "gateway mfa", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"})
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        user.mfa_enabled = True
        user.mfa_required = True
        user.mfa_secret_encrypted = encrypt_mfa_secret(generate_secret())
        db.commit()
        assert authorize_gateway_login(db, "pam_user", user.ssh_public_key, "127.0.0.1") is None
        db.add(StepUpSession(user_id=user.id, context="gateway_login", valid_until=utcnow() + timedelta(minutes=15)))
        db.commit()
        assert authorize_gateway_login(db, "pam_user", user.ssh_public_key, "127.0.0.1") is not None
    finally:
        db.close()


def test_ldap_and_oidc_mock_role_mapping(client):
    ldap = client.post("/api/auth/login", json={"provider": "ldap", "username": "ldap_user", "password": "anything"})
    assert ldap.status_code == 200
    oidc = client.get("/api/auth/oidc/callback?mock=1&username=oidc_test&role=pam_approver")
    assert oidc.status_code == 200
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.username == "ldap_user", User.auth_provider == "ldap").first()
        assert db.query(User).filter(User.username == "oidc_test", User.role == "approver").first()
    finally:
        db.close()


def test_auth_events_record_login_and_mfa(client):
    test_local_login_with_mfa(client)
    db = SessionLocal()
    try:
        assert db.query(AuthEvent).filter(AuthEvent.event_type == "login_attempt").count() >= 1
        assert db.query(AuthEvent).filter(AuthEvent.event_type == "mfa_success").count() >= 1
    finally:
        db.close()


def test_user_cannot_view_auth_events(client):
    headers = auth_headers(client, "user", "user123")
    assert client.get("/api/identity/auth-events", headers=headers).status_code == 403


def test_admin_cannot_read_plaintext_mfa_secret(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        user.mfa_enabled = True
        user.mfa_secret_encrypted = encrypt_mfa_secret("PLAINTEXTSECRET")
        db.commit()
    finally:
        db.close()
    headers = auth_headers(client)
    response = client.get("/api/identity/users", headers=headers)
    assert response.status_code == 200
    assert "PLAINTEXTSECRET" not in response.text
    assert "mfa_secret" not in response.text


def test_dangerous_command_creates_risk_event_and_alert(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "dangerous command", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        imported = import_jsonl_commands(db, grant, ['{"type":"command","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"danger","linux_username":"pam_user","pwd":"/tmp","command":"rm -rf /"}'])
        db.commit()
        assert imported == 1
        assert db.query(RiskEvent).filter(RiskEvent.event_type == "command_risk_detected").count() >= 1
        assert db.query(Alert).filter(Alert.status == "open", Alert.severity == "critical").count() >= 1
    finally:
        db.close()


def test_policy_rule_can_deny_matching_command(client):
    admin = auth_headers(client)
    grant_step_up("admin", "edit_policy")
    rule = client.post(
        "/api/policy-rules",
        headers=admin,
        json={
            "name": "Block history wipe",
            "rule_type": "command",
            "priority": 1,
            "condition_json": '{"command_regex":"history\\\\s+-c"}',
            "action_json": '{"deny":true}',
            "risk_score_delta": 20,
        },
    )
    assert rule.status_code == 200, rule.text
    user_headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": 1, "reason": "blocked command", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        import_jsonl_commands(db, grant, ['{"type":"command","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"deny","linux_username":"pam_user","pwd":"/tmp","command":"history -c"}'])
        db.commit()
        command = db.query(SessionCommand).filter(SessionCommand.command == "history -c").first()
        assert command.blocked_by_policy is True
        assert command.matched_policy_rule_id == rule.json()["id"]
    finally:
        db.close()


def test_alert_acknowledge_and_resolve_flow(client):
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "alert flow", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        import_jsonl_commands(db, grant, ['{"type":"command","timestamp":"2026-01-01T12:00:00Z","grant_id":1,"session_id":"alert","linux_username":"pam_user","pwd":"/tmp","command":"mkfs /dev/sda"}'])
        db.commit()
        alert = db.query(Alert).first()
        alert_id = alert.id if alert else None
    finally:
        db.close()
    assert alert_id is not None
    assert client.post(f"/api/alerts/{alert_id}/acknowledge", headers=headers).json()["status"] == "acknowledged"
    resolved = client.post(f"/api/alerts/{alert_id}/resolve", headers=auth_headers(client))
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"


def test_server_group_policy_rule_matches_evaluate_test(client):
    admin = auth_headers(client)
    group = client.post("/api/server-groups", headers=admin, json={"name": "production-core", "environment": "prod"}).json()
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "core-prod", "ip_address": "10.10.0.20", "environment": "prod", "command_logging_enabled": True, "session_recording_enabled": True},
    ).json()
    assert client.post(f"/api/server-groups/{group['id']}/servers/{server['id']}", headers=admin).status_code == 200
    grant_step_up("admin", "edit_policy")
    client.post(
        "/api/policy-rules",
        headers=admin,
        json={"name": "Core requires gateway", "rule_type": "access_request", "priority": 1, "server_group": "production-core", "action_json": '{"requires_gateway":true}', "risk_score_delta": 15},
    )
    result = client.post(
        "/api/policy-rules/evaluate-test",
        headers=admin,
        json={"user_id": 3, "server_id": server["id"], "access_type": "ssh_only", "duration": 60, "reason": "core maintenance"},
    )
    assert result.status_code == 200, result.text
    assert result.json()["requires_gateway"] is True


def test_gateway_auth_success_for_active_grant(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "gateway", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        found, login = find_user_for_gateway_login(db, "pam_user", user.ssh_public_key, "127.0.0.1")
        grant = choose_gateway_grant(db, found, login.requested_server_id)
        assert found.username == "user"
        assert grant is not None
        assert grant.gateway_session_required is True
    finally:
        db.close()


def test_gateway_auth_denied_without_grant(client):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        found, login = find_user_for_gateway_login(db, "pam_user", user.ssh_public_key, "127.0.0.1")
        assert found.username == "user"
        assert active_gateway_grants(db, found, login.requested_server_id) == []
    finally:
        db.close()


def test_gateway_auth_denied_for_expired_grant(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "expired gateway", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        grant = db.query(AccessGrant).first()
        grant.valid_to = utcnow() - timedelta(minutes=1)
        db.commit()
        user = db.get(User, grant.user_id)
        assert active_gateway_grants(db, user) == []
    finally:
        db.close()


def test_gateway_multiple_grant_selection_and_username_server_syntax(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    admin = auth_headers(client)
    server = client.post(
        "/api/servers",
        headers=admin,
        json={"hostname": "gateway-two", "ip_address": "10.0.0.9", "environment": "dev", "gateway_enabled": True},
    ).json()
    headers = auth_headers(client, "user", "user123")
    for server_id in [1, server["id"]]:
        client.post(
            "/api/access-requests",
            headers=headers,
            json={"server_id": server_id, "reason": "multi gateway", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
        )
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "user").first()
        assert choose_gateway_grant(db, user) is None
        parsed = parse_gateway_username(f"pam_user+{server['id']}")
        selected = choose_gateway_grant(db, user, parsed.requested_server_id)
        assert selected.server_id == server["id"]
    finally:
        db.close()


def test_gateway_recording_permissions(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    user_headers = auth_headers(client, "user", "user123")
    admin_headers = auth_headers(client)
    client.post(
        "/api/access-requests",
        headers=user_headers,
        json={"server_id": 1, "reason": "recording", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    assert client.get("/api/gateway/recordings", headers=user_headers).status_code == 200
    assert client.get("/api/gateway/recordings", headers=admin_headers).status_code == 200


def test_command_detector_detects_commands_and_backspace():
    detector = CommandDetector()
    detected = detector.feed("sudoo\b systemctl status nginx\r")
    assert detected[0]["command"] == "sudo systemctl status nginx"
    assert detected[0]["is_sudo"] is True


def test_gateway_idle_timeout_and_grant_expired_close_sessions(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    monkeypatch.setattr(settings, "pam_gateway_idle_timeout_seconds", 1)
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "timeout", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    db = SessionLocal()
    try:
        connection = db.query(GatewayConnection).first()
        connection.updated_at = utcnow() - timedelta(seconds=5)
        db.commit()
        assert enforce_gateway_sessions(db) == 1
        db.refresh(connection)
        assert connection.termination_reason == "idle_timeout"
    finally:
        db.close()


def test_gateway_events_reach_audit_logs_and_mock_data_visible(client, monkeypatch):
    monkeypatch.setattr(settings, "pam_access_mode", "gateway")
    headers = auth_headers(client, "user", "user123")
    client.post(
        "/api/access-requests",
        headers=headers,
        json={"server_id": 1, "reason": "events", "requested_duration_minutes": 60, "requested_access_type": "ssh_only"},
    )
    assert client.get("/api/gateway/connections", headers=headers).json()
    assert client.get("/api/gateway/events", headers=headers).json()
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(AuditLog.action == "gateway_session_started").count() >= 1
        assert db.query(GatewayRecording).count() >= 1
    finally:
        db.close()


def test_create_local_encrypted_secret_and_no_plaintext_in_api(client):
    headers = auth_headers(client)
    response = client.post(
        "/api/secrets",
        headers=headers,
        json={"name": "api token", "secret_type": "api_token", "backend_type": "local_encrypted", "value": "super-secret-token"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "super-secret-token" not in response.text
    assert "encrypted_value" not in body
    db = SessionLocal()
    try:
        secret = db.get(Secret, body["id"])
        assert decrypt_secret(secret.encrypted_value) == "super-secret-token"
    finally:
        db.close()


def test_secret_used_creates_access_log(client):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "internal key", "secret_type": "generic", "backend_type": "local_encrypted", "value": "value"}).json()
    db = SessionLocal()
    try:
        item = db.get(Secret, secret["id"])
        assert get_vault_backend_for_secret(db, item).get_secret_value(item.id, {"access_context": "test"}) == "value"
        db.commit()
        assert db.query(SecretAccessLog).filter(SecretAccessLog.secret_id == item.id, SecretAccessLog.action == "secret_used").count() == 1
    finally:
        db.close()


def test_secret_permissions(client):
    admin = auth_headers(client)
    secret = client.post("/api/secrets", headers=admin, json={"name": "metadata only", "secret_type": "generic", "backend_type": "local_encrypted", "value": "hidden"}).json()
    user_headers = auth_headers(client, "user", "user123")
    approver_headers = auth_headers(client, "approver", "approver123")
    assert client.get("/api/secrets", headers=user_headers).status_code == 403
    approver_response = client.get(f"/api/secrets/{secret['id']}", headers=approver_headers)
    assert approver_response.status_code == 200
    assert "hidden" not in approver_response.text


def test_admin_rotates_secret_and_creates_new_version(client):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "rotate me", "secret_type": "ssh_private_key", "backend_type": "local_encrypted", "value": "old"}).json()
    grant_step_up("admin", "rotate_secret")
    rotated = client.post(f"/api/secrets/{secret['id']}/rotate", headers=headers)
    assert rotated.status_code == 200, rotated.text
    versions = client.get(f"/api/secrets/{secret['id']}/versions", headers=headers).json()
    assert len(versions) >= 2
    assert any(v["status"] == "active" for v in versions)


def test_inactive_version_is_not_used(client):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "versions", "secret_type": "generic", "backend_type": "local_encrypted", "value": "old"}).json()
    client.put(f"/api/secrets/{secret['id']}", headers=headers, json={"value": "new"})
    db = SessionLocal()
    try:
        item = db.get(Secret, secret["id"])
        versions = db.query(SecretVersion).filter(SecretVersion.secret_id == item.id).all()
        versions[0].status = "revoked"
        db.commit()
        value = get_vault_backend_for_secret(db, item).get_secret_value(item.id, {"access_context": "version_test"})
        assert value == "new"
    finally:
        db.close()


def test_failed_rotation_does_not_disable_old_secret(client, monkeypatch):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "fail rotation", "secret_type": "generic", "backend_type": "local_encrypted", "value": "old"}).json()

    def broken():
        raise RuntimeError("boom")

    monkeypatch.setattr("app.vault.rotation.generate_mock_private_key", broken)
    db = SessionLocal()
    try:
        item = db.get(Secret, secret["id"])
        job = rotate_secret_value(db, item)
        db.commit()
        db.refresh(item)
        assert job.status == "failed"
        assert item.version == 1
    finally:
        db.close()


def test_executor_and_gateway_secret_lookup_create_access_logs(client):
    headers = auth_headers(client)
    secret = client.post("/api/secrets", headers=headers, json={"name": "target key", "secret_type": "target_connection_key", "backend_type": "local_encrypted", "value": "key-value"}).json()
    db = SessionLocal()
    try:
        server = db.get(Server, 1)
        server.ssh_auth_secret_id = secret["id"]
        server.gateway_secret_ref_id = secret["id"]
        db.commit()
        item = db.get(Secret, secret["id"])
        assert get_vault_backend_for_secret(db, item).get_secret_value(item.id, {"server_id": server.id, "access_context": "executor_ssh_key"}) == "key-value"
        grant = AccessGrant(
            request_id=1,
            user_id=3,
            server_id=server.id,
            linux_username="pam_user",
            access_type="ssh_only",
            ssh_public_key="ssh-ed25519 demo",
            valid_from=utcnow(),
            valid_to=utcnow() + timedelta(minutes=5),
            status="active",
        )
        grant.server = server
        target_connection_settings(grant)
        db.commit()
        assert db.query(SecretAccessLog).filter(SecretAccessLog.secret_id == item.id, SecretAccessLog.action == "secret_used").count() >= 2
    finally:
        db.close()


def test_mock_rotation_job_visible(client):
    headers = auth_headers(client)
    grant_step_up("admin", "rotate_secret")
    response = client.post("/api/secret-rotation/servers/1/rotate-ssh-key", headers=headers)
    assert response.status_code == 200, response.text
    jobs = client.get("/api/secret-rotation/jobs", headers=headers).json()
    assert jobs
    assert any(job["status"] in {"completed", "failed"} for job in jobs)


def test_user_cannot_delete_history(client):
    headers = auth_headers(client, "user", "user123")
    response = client.delete("/api/session-commands/1", headers=headers)
    assert response.status_code == 405


def test_admin_can_deactivate_user_and_server(client):
    headers = auth_headers(client)
    assert client.delete("/api/users/3", headers=headers).status_code == 200
    assert client.delete("/api/servers/1", headers=headers).status_code == 200
    db = SessionLocal()
    try:
        assert db.get(User, 3).is_active is False
        assert db.get(Server, 1).enabled is False
    finally:
        db.close()

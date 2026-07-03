from datetime import timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.identity.sync import upsert_external_user
from app.models import Alert, AuthEvent, MfaChallenge, Policy, PolicyRule, RiskEvent, Secret, SecretVersion, Server, StepUpSession, User, utcnow
from app.policy.default_rules import seed_default_policy_rules
from app.security import hash_password


DEMO_SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPamLiteDemoKey user@pam-lite"


def seed_demo_data(db: Session) -> None:
    users = [
        (settings.pam_default_admin_user, settings.pam_default_admin_email, settings.pam_default_admin_password, "admin"),
        ("approver", "approver@example.local", "approver123", "approver"),
        ("user", "user@example.local", "user123", "user"),
    ]
    for username, email, password, role in users:
        existing = db.query(User).filter(User.username == username).first()
        if not existing:
            db.add(
                User(
                    username=username,
                    email=email,
                    password_hash=hash_password(password),
                    role=role,
                    is_active=True,
                    ssh_public_key=DEMO_SSH_KEY,
                    auth_provider="local",
                    mfa_required=role == "admin",
                )
            )
    if not db.query(User).filter(User.username == "ldap_user").first():
        upsert_external_user(db, provider="ldap", external_id="mock-ldap-user", username="ldap_user", email="ldap_user@example.local", display_name="Mock LDAP User", role="user", groups=[{"name": settings.pam_ldap_role_user_group, "source": "mock"}], claims={"mock": True})
    if not db.query(User).filter(User.username == "oidc_user").first():
        upsert_external_user(db, provider="oidc", external_id="mock-oidc-user", username="oidc_user", email="oidc_user@example.local", display_name="Mock OIDC User", role="user", groups=[{"name": settings.pam_oidc_user_role, "source": "mock"}], claims={"mock": True})

    if not db.query(Server).filter(Server.hostname == "demo-linux").first():
        db.add(
            Server(
                hostname="demo-linux",
                ip_address="127.0.0.1",
                ssh_port=22,
                environment="dev",
                owner="platform",
                description="Demo Linux target for mock workflow",
                enabled=True,
                ssh_admin_user="root",
                ssh_private_key_path=settings.pam_executor_ssh_key_path,
                command_logging_enabled=True,
                session_recording_enabled=False,
            )
        )
        db.flush()

    demo_server = db.query(Server).filter(Server.hostname == "demo-linux").first()
    if not db.query(Secret).filter(Secret.name == "demo executor key").first():
        executor_secret = Secret(
            name="demo executor key",
            secret_type="ssh_private_key",
            backend_type="file_reference",
            environment="dev",
            owner="platform",
            description="Demo executor SSH key reference",
            file_path=settings.pam_executor_ssh_key_path,
            fingerprint="sha256:demo-executor-fingerprint",
            public_key=DEMO_SSH_KEY,
            status="active",
        )
        db.add(executor_secret)
        db.flush()
        db.add(SecretVersion(secret_id=executor_secret.id, version=1, file_path=executor_secret.file_path, fingerprint=executor_secret.fingerprint, public_key=executor_secret.public_key, status="active", activated_at=utcnow(), rotation_reason="demo_seed"))
        if demo_server:
            demo_server.ssh_auth_secret_id = executor_secret.id
            demo_server.secret_ref_id = executor_secret.id
    if not db.query(Secret).filter(Secret.name == "demo gateway key").first():
        gateway_secret = Secret(
            name="demo gateway key",
            secret_type="target_connection_key",
            backend_type="file_reference",
            environment="dev",
            owner="platform",
            description="Demo gateway target key reference",
            file_path=settings.pam_executor_ssh_key_path,
            fingerprint="sha256:demo-gateway-fingerprint",
            public_key=DEMO_SSH_KEY,
            status="active",
        )
        db.add(gateway_secret)
        db.flush()
        db.add(SecretVersion(secret_id=gateway_secret.id, version=1, file_path=gateway_secret.file_path, fingerprint=gateway_secret.fingerprint, public_key=gateway_secret.public_key, status="active", activated_at=utcnow(), rotation_reason="demo_seed"))
        if demo_server:
            demo_server.gateway_secret_ref_id = gateway_secret.id

    policies = [
        ("user dev ssh", "user", "dev", "ssh_only", 240, False, True, False),
        ("user test limited sudo", "user", "test", "limited_sudo", 120, True, True, False),
        ("user prod limited sudo", "user", "prod", "limited_sudo", 60, True, True, True),
        ("user prod full sudo", "user", "prod", "full_sudo", 60, True, True, True),
        ("approver dev limited sudo", "approver", "dev", "limited_sudo", 480, False, True, False),
        ("approver test limited sudo", "approver", "test", "limited_sudo", 480, False, True, False),
        ("admin all full sudo", "admin", "all", "full_sudo", 480, False, True, True),
        ("admin all ssh", "admin", "all", "ssh_only", 480, False, True, False),
        ("admin all limited sudo", "admin", "all", "limited_sudo", 480, False, True, False),
    ]
    for name, role, environment, access_type, max_duration, requires_approval, command_logging, recording in policies:
        if not db.query(Policy).filter(Policy.name == name).first():
            db.add(
                Policy(
                    name=name,
                    role=role,
                    environment=environment,
                    access_type=access_type,
                    max_duration_minutes=max_duration,
                    requires_approval=requires_approval,
                    command_logging_required=command_logging,
                    session_recording_required=recording,
                    enabled=True,
                )
            )
    seed_default_policy_rules(db, PolicyRule)
    demo_user = db.query(User).filter(User.username == "user").first()
    demo_server = db.query(Server).filter(Server.hostname == "demo-linux").first()
    if demo_user and demo_server and not db.query(RiskEvent).filter(RiskEvent.event_type == "dangerous_command").first():
        event = RiskEvent(
            user_id=demo_user.id,
            server_id=demo_server.id,
            event_type="dangerous_command",
            severity="high",
            risk_score=70,
            message="Demo high risk command detected: systemctl stop nginx",
        )
        db.add(event)
        db.flush()
        db.add(
            Alert(
                risk_event_id=event.id,
                user_id=demo_user.id,
                server_id=demo_server.id,
                alert_type="command",
                severity="high",
                status="open",
                title="Demo high risk command",
                message=event.message,
            )
        )
    if demo_user and not db.query(RiskEvent).filter(RiskEvent.event_type == "suspicious_gateway_login").first():
        event = RiskEvent(user_id=demo_user.id, event_type="suspicious_gateway_login", severity="medium", risk_score=40, message="Demo denied gateway login without active grant")
        db.add(event)
    if not db.query(Alert).filter(Alert.title == "Demo secret rotation failed").first():
        db.add(Alert(alert_type="secret", severity="high", status="open", title="Demo secret rotation failed", message="A demo secret rotation failed without exposing secret material."))
    admin = db.query(User).filter(User.username == settings.pam_default_admin_user).first()
    if admin and not db.query(AuthEvent).first():
        db.add(AuthEvent(user_id=admin.id, provider="local", event_type="login_success", success=True, message="Demo login event"))
        db.add(AuthEvent(user_id=admin.id, provider="local", event_type="mfa_required", success=True, message="Demo MFA enrollment prompt"))
    if admin and not db.query(MfaChallenge).filter(MfaChallenge.context == "gateway_login").first():
        db.add(MfaChallenge(user_id=admin.id, challenge_type="step_up", context="gateway_login", status="pending", expires_at=utcnow() + timedelta(minutes=5), metadata_json='{"demo": true}'))
    if demo_user and not db.query(StepUpSession).filter(StepUpSession.context == "demo_step_up").first():
        db.add(StepUpSession(user_id=demo_user.id, context="demo_step_up", valid_until=utcnow() + timedelta(minutes=15)))
    db.commit()

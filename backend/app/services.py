import json
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.executor import get_executor
from app.config import settings
from app.gateway.service import finish_gateway_connection, gateway_connection_string, seed_mock_gateway_for_grant
from app.models import AccessGrant, AccessRequest, GatewayConnection, Policy, Server, User, utcnow
from app.policy.engine import PolicyDecision, PolicyEngine
from app.rbac import has_permission
from app.security import sanitize_linux_username, validate_linux_username
from app.session_monitor import (
    configure_command_logging,
    configure_session_recording,
    import_session_logs_for_grant,
    remove_monitoring_hooks,
)


VALID_DURATIONS = {15, 30, 60, 120, 240, 480}
ACCESS_TYPES = {"ssh_only", "limited_sudo", "full_sudo"}


def _monitoring_level(decision: PolicyDecision, server: Server) -> str:
    if decision.requires_session_recording or server.session_recording_enabled or server.require_session_recording:
        return "full_session"
    if server.command_logging_enabled:
        return "command"
    return "basic"


def find_policy(db: Session, user: User, server: Server, access_type: str) -> Policy | None:
    roles = ["operator", "approver"] if user.role in {"operator", "approver"} else [user.role]
    policies = (
        db.query(Policy)
        .filter(
            Policy.enabled.is_(True),
            Policy.role.in_(roles),
            Policy.access_type == access_type,
        )
        .all()
    )
    for policy in policies:
        if policy.environment in {server.environment, "all", "*"}:
            return policy
    return None


def validate_request_against_policy(db: Session, user: User, server: Server, duration: int, access_type: str) -> Policy:
    if duration not in VALID_DURATIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsupported duration")
    if access_type not in ACCESS_TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unsupported access type")
    if not server.enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Server is disabled")
    policy = find_policy(db, user, server, access_type)
    if not policy:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No policy allows this access")
    if duration > policy.max_duration_minutes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Requested duration exceeds policy")
    if policy.command_logging_required and not server.command_logging_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Command logging is required by policy")
    if policy.session_recording_required and not server.session_recording_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Session recording is required by policy")
    return policy


def evaluate_request_policy(db: Session, user: User, server: Server, duration: int, access_type: str, reason: str | None) -> tuple[Policy, PolicyDecision]:
    legacy_policy = validate_request_against_policy(db, user, server, duration, access_type)
    decision = PolicyEngine(db).evaluate_access_request(user, server, access_type, duration, reason)
    if server.require_approval:
        decision.requires_approval = True
    if server.require_session_recording:
        decision.requires_session_recording = True
    if server.require_mfa:
        decision.requires_mfa = True
        decision.mfa_context = decision.mfa_context or "server_required_mfa"
        decision.mfa_reason = decision.mfa_reason or "Server policy requires MFA"
    if decision.requires_mfa and not getattr(user, "mfa_enabled", False):
        decision.denied = True
        decision.allowed = False
        decision.message = "MFA is required by policy"
    if legacy_policy.requires_approval:
        decision.requires_approval = True
    if legacy_policy.session_recording_required:
        decision.requires_session_recording = True
    return legacy_policy, decision


def sudo_policy_for(access_type: str, linux_username: str) -> str | None:
    if access_type == "ssh_only":
        return None
    if access_type == "limited_sudo":
        return (
            f"{linux_username} ALL=(root) NOPASSWD: /bin/systemctl status *, /bin/journalctl *, "
            "/bin/df, /bin/free, /usr/bin/top, /usr/bin/htop"
        )
    return f"{linux_username} ALL=(ALL) NOPASSWD: ALL"


def create_grant_for_request(db: Session, access_request: AccessRequest, actor: User, source_ip: str | None = None) -> AccessGrant:
    user = db.get(User, access_request.user_id)
    server = db.get(Server, access_request.server_id)
    if not user or not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request user or server not found")
    if not user.ssh_public_key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User has no SSH public key")

    linux_username = sanitize_linux_username(user.username)
    if not validate_linux_username(linux_username):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Generated Linux username is invalid")

    now = utcnow()
    valid_to = now + timedelta(minutes=access_request.requested_duration_minutes)
    request_decision = json.loads(access_request.policy_decision_json or "{}")
    force_gateway = bool(request_decision.get("requires_gateway"))
    if access_request.session_recording_required and not server.session_recording_enabled:
        force_gateway = True
    can_connect = has_permission(db, user, "servers.connect", server_id=server.id)
    can_direct = can_connect and server.direct_access_enabled and has_permission(db, user, "servers.direct_ssh", server_id=server.id)
    can_gateway = can_connect and server.gateway_enabled and has_permission(db, user, "servers.gateway_ssh", server_id=server.id)
    if force_gateway or settings.pam_access_mode == "gateway" or not can_direct:
        if not can_gateway:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Gateway connection is not permitted")
        access_mode = "gateway"
    else:
        access_mode = "direct"
    grant = AccessGrant(
        request_id=access_request.id,
        user_id=user.id,
        server_id=server.id,
        linux_username=linux_username,
        access_type=access_request.requested_access_type,
        ssh_public_key=user.ssh_public_key,
        sudo_policy=sudo_policy_for(access_request.requested_access_type, linux_username),
        valid_from=now,
        valid_to=valid_to,
        status="active",
        access_mode=access_mode,
        gateway_username=linux_username,
        gateway_session_required=access_mode == "gateway",
        direct_ssh_enabled=access_mode == "direct",
        calculated_risk_score=access_request.calculated_risk_score or 0,
        policy_decision_json=access_request.policy_decision_json,
        monitoring_level=_monitoring_level(PolicyDecision(risk_score=access_request.calculated_risk_score or 0), server),
    )
    access_request.status = "approved"
    access_request.valid_from = now
    access_request.valid_to = valid_to
    db.add(grant)
    db.flush()
    grant_decision = PolicyEngine(db).evaluate_grant(grant)
    if access_request.session_recording_required:
        grant_decision.requires_session_recording = True
    if access_request.policy_decision_json:
        grant.policy_decision_json = access_request.policy_decision_json
    else:
        grant.policy_decision_json = grant_decision.to_json()
    grant.calculated_risk_score = max(access_request.calculated_risk_score or 0, grant_decision.risk_score)
    grant.monitoring_level = _monitoring_level(grant_decision, server)
    grant.gateway_connection_string = gateway_connection_string(grant)

    executor = get_executor()
    try:
        if grant.direct_ssh_enabled:
            executor.grant_ssh_access(server, linux_username, user.ssh_public_key)
            executor.grant_sudo_access(server, linux_username, grant.access_type)
            configure_command_logging(server, linux_username, grant.id)
            write_audit(
                db,
                "command_logging_configured",
                f"Command logging configured for {linux_username}",
                user_id=actor.id,
                server_id=server.id,
                request_id=access_request.id,
                grant_id=grant.id,
                source_ip=source_ip,
            )
            if server.session_recording_enabled:
                configure_session_recording(server, linux_username, grant.id)
                write_audit(
                    db,
                    "session_recording_configured",
                    f"Session recording configured for {linux_username}",
                    user_id=actor.id,
                    server_id=server.id,
                    request_id=access_request.id,
                    grant_id=grant.id,
                    source_ip=source_ip,
                )
        write_audit(
            db,
            "grant.created",
            f"Granted {grant.access_type} on {server.hostname} to {user.username}",
            user_id=actor.id,
            server_id=server.id,
            request_id=access_request.id,
            grant_id=grant.id,
            source_ip=source_ip,
        )
        PolicyEngine(db).record_risk_event(
            grant_decision,
            "grant_created",
            f"Grant created for {user.username} on {server.hostname}",
            user_id=user.id,
            server_id=server.id,
            grant_id=grant.id,
        )
        if grant.access_type == "full_sudo":
            write_audit(
                db,
                "grant.full_sudo_warning",
                "Full sudo can bypass bash history logging; prefer tlog/auditd/sudo I/O log/SSH gateway",
                user_id=actor.id,
                server_id=server.id,
                request_id=access_request.id,
                grant_id=grant.id,
                source_ip=source_ip,
            )
        if grant.gateway_session_required and settings.pam_executor_mode == "mock":
            seed_mock_gateway_for_grant(db, grant)
        elif grant.direct_ssh_enabled:
            import_session_logs_for_grant(db, grant, mock_seed=True)
    except Exception as exc:
        grant.status = "failed"
        write_audit(
            db,
            "executor.error",
            "Executor failed while granting access",
            user_id=actor.id,
            server_id=server.id,
            request_id=access_request.id,
            grant_id=grant.id,
            source_ip=source_ip,
            metadata={"error": str(exc)[:500]},
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Executor failed") from exc
    return grant


def revoke_grant(db: Session, grant: AccessGrant, actor: User | None, reason: str, source_ip: str | None = None, expired: bool = False) -> AccessGrant:
    if grant.status != "active":
        return grant
    server = db.get(Server, grant.server_id)
    user = db.get(User, grant.user_id)
    if not server or not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Grant user or server not found")

    if grant.direct_ssh_enabled:
        import_session_logs_for_grant(db, grant, mock_seed=False, finalize=True)
    executor = get_executor()
    try:
        for connection in db.query(GatewayConnection).filter(GatewayConnection.grant_id == grant.id, GatewayConnection.status == "active").all():
            finish_gateway_connection(db, connection, "grant_revoked" if not expired else "grant_expired")
        if grant.direct_ssh_enabled:
            executor.revoke_ssh_access(server, grant.linux_username, grant.ssh_public_key)
            executor.revoke_sudo_access(server, grant.linux_username)
        active_other_grants = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.id != grant.id,
                AccessGrant.linux_username == grant.linux_username,
                AccessGrant.status == "active",
            )
            .count()
        )
        if grant.direct_ssh_enabled and active_other_grants == 0:
            remove_monitoring_hooks(server, grant.linux_username)
            write_audit(
                db,
                "monitoring_hook_removed",
                f"Monitoring hook removed for {grant.linux_username}",
                user_id=actor.id if actor else user.id,
                server_id=server.id,
                grant_id=grant.id,
                source_ip=source_ip,
            )
            executor.disable_linux_user(server, grant.linux_username)
    except Exception as exc:
        write_audit(
            db,
            "executor.error",
            "Executor failed while revoking access",
            user_id=actor.id if actor else user.id,
            server_id=server.id,
            grant_id=grant.id,
            source_ip=source_ip,
            metadata={"error": str(exc)[:500]},
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Executor failed") from exc

    grant.status = "expired" if expired else "revoked"
    grant.revoked_at = utcnow()
    grant.revoke_reason = reason
    write_audit(
        db,
        "grant.expired" if expired else "grant.revoked",
        f"Access for {user.username} on {server.hostname} was {grant.status}",
        user_id=actor.id if actor else user.id,
        server_id=server.id,
        grant_id=grant.id,
        request_id=grant.request_id,
        source_ip=source_ip,
    )
    decision = PolicyEngine(db).evaluate_revoke(grant, reason)
    PolicyEngine(db).record_risk_event(
        decision,
        "grant_expired" if expired else "grant_revoked",
        f"Access for {user.username} on {server.hostname} was {grant.status}",
        user_id=user.id,
        server_id=server.id,
        grant_id=grant.id,
    )
    return grant

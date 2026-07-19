import json
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import SecretStr
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.config import settings
from app.database import get_db
from app.models import (
    Secret,
    Server,
    ServerGroup,
    ServerGroupMember,
    ServerRegistrationIdempotency,
    ServerRegistrationIdentity,
    ServerTemplate,
    ServerTemplateAllowedGroup,
    ServerTemplateDefaultGroup,
    User,
    utcnow,
)
from app.rbac import active_memberships, has_permission, is_global_admin
from app.server_registration import request_fingerprint, test_password_connection, validate_target_address
from app.vault.local_encrypted import LocalEncryptedBackend


register_router = APIRouter(prefix="/api/servers", tags=["server-registration"])
approval_router = APIRouter(prefix="/api/server-registrations", tags=["server-registration"])


def _audit_failure(db: Session, action: str, message: str, user: User, request: Request, *, result: str, metadata: dict | None = None) -> None:
    db.rollback()
    write_audit(db, "server_registration_requested", "Server registration request received", user_id=user.id, source_ip=source_ip(request), result=result, object_type="server_registration", metadata=metadata)
    write_audit(db, action, message, user_id=user.id, source_ip=source_ip(request), result=result, object_type="server_registration", metadata=metadata)
    db.commit()


def _template(db: Session, payload: schemas.ServerRegistrationIn) -> ServerTemplate:
    query = db.query(ServerTemplate).filter(ServerTemplate.enabled.is_(True))
    item = query.filter(ServerTemplate.id == payload.template_id).first() if payload.template_id is not None else query.filter(func.lower(ServerTemplate.name) == payload.template_name.lower()).first()
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server template not found")
    return item


def _ids(db: Session, model, template_id: int) -> set[int]:
    return {value for (value,) in db.query(model.server_group_id).filter(model.template_id == template_id).all()}


def _registration_out(db: Session, server: Server) -> dict:
    groups = db.query(ServerGroup).join(ServerGroupMember, ServerGroupMember.server_group_id == ServerGroup.id).filter(ServerGroupMember.server_id == server.id).order_by(ServerGroup.id).all()
    template = db.get(ServerTemplate, server.server_template_id)
    return {
        "id": server.id,
        "hostname": server.hostname,
        "address": server.ip_address,
        "port": server.ssh_port,
        "ssh_port": server.ssh_port,
        "template_id": server.server_template_id,
        "template": {"id": template.id, "name": template.name},
        "group_ids": [group.id for group in groups],
        "groups": [{"id": group.id, "name": group.name} for group in groups],
        "status": server.registration_status,
        "enabled": server.enabled,
        "connection_status": server.registration_connection_status,
        "connection_test": {"status": server.registration_connection_status or "not_tested"},
        "credential": {"type": "ssh_password", "stored_in_vault": True},
        "registered_at": server.registered_at,
    }


def _https_ok(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    return request.url.scheme == "https" or forwarded == "https" or settings.pam_executor_mode == "mock"


@register_router.post("/register", response_model=schemas.ServerRegistrationOut, status_code=status.HTTP_201_CREATED)
def register_server(
    payload: schemas.ServerRegistrationIn,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", min_length=1, max_length=128),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if settings.pam_registration_require_https and not _https_ok(request):
        _audit_failure(db, "server_registration_denied", "Server registration requires HTTPS", current_user, request, result="denied", metadata={"reason": "https_required"})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "HTTPS is required")

    fingerprint = request_fingerprint(payload)
    if idempotency_key:
        previous = db.query(ServerRegistrationIdempotency).filter_by(user_id=current_user.id, idempotency_key=idempotency_key).first()
        if previous:
            if previous.request_hash != fingerprint:
                raise HTTPException(status.HTTP_409_CONFLICT, "Idempotency-Key was already used for another request")
            response = json.loads(previous.response_json)
            response["registered_at"] = db.get(Server, previous.server_id).registered_at
            return response

    template = _template(db, payload)
    defaults = _ids(db, ServerTemplateDefaultGroup, template.id)
    allowed = _ids(db, ServerTemplateAllowedGroup, template.id)
    target_ids = defaults | set(payload.group_ids)
    if not target_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The template or request must select at least one server group")
    groups = db.query(ServerGroup).filter(ServerGroup.id.in_(target_ids), ServerGroup.enabled.is_(True)).all()
    if len(groups) != len(target_ids) or not target_ids.issubset(allowed):
        _audit_failure(db, "server_registration_denied", "Server registration group scope denied", current_user, request, result="denied", metadata={"template_id": template.id, "reason": "group_scope"})
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Template cannot be used with one or more selected groups")

    if not is_global_admin(current_user):
        member_ids = {item.server_group_id for item in active_memberships(db, current_user)}
        base_permissions = ("servers.register_via_api", "servers.use_template", "servers.provide_credentials")
        authorized = target_ids.issubset(member_ids) and all(has_permission(db, current_user, permission, group_id=group_id) for group_id in target_ids for permission in base_permissions)
        additional = set(payload.group_ids) - defaults
        authorized = authorized and all(has_permission(db, current_user, "servers.assign_to_group", group_id=group_id) for group_id in additional)
        if payload.test_connection:
            authorized = authorized and all(has_permission(db, current_user, "servers.test_connection", group_id=group_id) for group_id in target_ids)
        if not authorized:
            _audit_failure(db, "server_registration_denied", "Server registration permission denied", current_user, request, result="denied", metadata={"template_id": template.id, "reason": "permission"})
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing server registration permission")

    cutoff = utcnow() - timedelta(minutes=settings.pam_registration_rate_limit_window_minutes)
    recent = db.query(Server).filter(Server.created_by_id == current_user.id, Server.registration_source == "api", Server.registered_at >= cutoff).count()
    if recent >= settings.pam_registration_rate_limit_count:
        _audit_failure(db, "server_registration_denied", "Server registration rate limit exceeded", current_user, request, result="denied", metadata={"reason": "rate_limit"})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Registration rate limit exceeded")

    port = payload.ssh_port or template.default_ssh_port
    if db.query(Server).filter((func.lower(Server.hostname) == payload.hostname.lower()) | ((Server.ip_address == payload.address) & (Server.ssh_port == port))).first():
        _audit_failure(db, "server_registration_duplicate", "Duplicate server registration", current_user, request, result="denied", metadata={"reason": "duplicate"})
        raise HTTPException(status.HTTP_409_CONFLICT, "A server with this hostname or address and port already exists")
    try:
        validate_target_address(payload.address, template.allowed_cidrs, template.allow_special_addresses, resolve_dns=payload.test_connection and settings.pam_executor_mode == "ssh")
    except ValueError as exc:
        reason = str(exc) if str(exc) in {"address_not_allowed", "address_outside_allowed_cidrs", "host_unreachable"} else "address_not_allowed"
        _audit_failure(db, "server_registration_denied", "Server registration address denied", current_user, request, result="denied", metadata={"reason": reason, "template_id": template.id})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Target address is not allowed") from exc

    if payload.host_key_policy and payload.host_key_policy != template.host_key_policy:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The template enforces its host key policy")
    host_key_policy = template.host_key_policy
    expected_fingerprint = template.expected_host_key_fingerprint or payload.expected_host_key_fingerprint
    if host_key_policy == "manual_fingerprint" and not expected_fingerprint:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A host key fingerprint is required")
    password = payload.password.get_secret_value()
    connection = {"ok": True, "status": "not_tested"}
    if payload.test_connection:
        connection = test_password_connection(address=payload.address, port=port, username=payload.username, password=password, timeout=template.connection_timeout_seconds, host_key_policy=host_key_policy, expected_fingerprint=expected_fingerprint)
        if not connection.get("ok"):
            _audit_failure(db, "server_connection_test_failed", "Server connection test failed", current_user, request, result="failed", metadata={"template_id": template.id, "status": connection.get("status", "ssh_error")})
            password = ""; payload.password = SecretStr("")
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSH connection test failed", headers={"X-Connection-Status": connection.get("status", "connection_error")})

    try:
        now = utcnow()
        registration_status = "pending_approval" if template.registration_requires_approval else "approved"
        secret = LocalEncryptedBackend(db).create_secret(
            name=f"server-registration-{payload.hostname}-{now.timestamp()}",
            secret_type="ssh_password",
            value=password,
            metadata={"environment": template.environment, "owner": current_user.username, "description": "Managed SSH password", "actor_id": current_user.id, "fingerprint": "managed-credential"},
        )
        server = Server(
            hostname=payload.hostname, display_name=payload.hostname, ip_address=payload.address, ssh_port=port,
            environment=template.environment, description=payload.description, enabled=registration_status == "approved",
            ssh_admin_user=payload.username, ssh_auth_type="vault_secret", ssh_auth_secret_id=secret.id,
            gateway_enabled=template.gateway_enabled, direct_access_enabled=template.direct_access_enabled,
            command_logging_enabled=template.command_logging_enabled, session_recording_enabled=template.require_session_recording,
            criticality=template.criticality, require_session_recording=template.require_session_recording,
            require_approval=template.require_approval, require_mfa=template.require_mfa,
            server_template_id=template.id, created_by_id=current_user.id, registered_at=now,
            registration_source="api", registration_status=registration_status,
            registration_connection_status=connection["status"], host_key_policy=host_key_policy,
            expected_host_key_fingerprint=expected_fingerprint,
        )
        db.add(server); db.flush()
        db.add(ServerRegistrationIdentity(server_id=server.id, address=payload.address.lower(), ssh_port=port, hostname=payload.hostname.lower()))
        for group_id in target_ids:
            db.add(ServerGroupMember(server_group_id=group_id, server_id=server.id, created_by_id=current_user.id))
        write_audit(db, "server_registration_requested", f"Requested registration of server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"template_id": template.id, "group_ids": sorted(target_ids), "test_connection": payload.test_connection})
        if payload.test_connection:
            write_audit(db, "server_connection_test_succeeded", "Server connection test succeeded", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"status": "connection_successful"})
        write_audit(db, "server_credential_created", "Created encrypted SSH credential", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"secret_id": secret.id, "secret_type": "ssh_password"})
        write_audit(db, "server_registered" if registration_status == "approved" else "server_registration_pending_approval", f"Server registration status: {registration_status}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"template_id": template.id, "group_ids": sorted(target_ids)})
        response = _registration_out(db, server)
        if idempotency_key:
            safe_json = {**response, "registered_at": now.isoformat()}
            db.add(ServerRegistrationIdempotency(user_id=current_user.id, idempotency_key=idempotency_key, request_hash=fingerprint, server_id=server.id, response_json=json.dumps(safe_json)))
        db.commit(); db.refresh(server)
        return _registration_out(db, server)
    except IntegrityError as exc:
        _audit_failure(db, "server_registration_duplicate", "Concurrent duplicate server registration", current_user, request, result="denied", metadata={"reason": "duplicate"})
        raise HTTPException(status.HTTP_409_CONFLICT, "A concurrent request registered this server first") from exc
    finally:
        password = ""
        payload.password = SecretStr("")


def _can_approve(db: Session, user: User, server: Server) -> bool:
    if is_global_admin(user):
        return True
    group_ids = [value for (value,) in db.query(ServerGroupMember.server_group_id).filter(ServerGroupMember.server_id == server.id).all()]
    return any(has_permission(db, user, "servers.approve_registration", group_id=group_id) for group_id in group_ids)


@approval_router.get("", response_model=list[schemas.ServerRegistrationOut])
def list_registrations(registration_status: str | None = Query(default="pending_approval"), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Server).filter(Server.registration_source == "api")
    if registration_status:
        query = query.filter(Server.registration_status == registration_status)
    return [_registration_out(db, item) for item in query.order_by(Server.registered_at.desc()).all() if _can_approve(db, current_user, item)]


@approval_router.post("/{server_id}/approve", response_model=schemas.ServerRegistrationOut)
def approve_registration(server_id: int, payload: schemas.ServerRegistrationDecisionIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server or server.registration_source != "api" or not _can_approve(db, current_user, server):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Registration not found")
    if server.registration_status != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Registration is not pending approval")
    server.registration_status = "approved"; server.enabled = True; server.registration_rejection_reason = None
    write_audit(db, "server_registration_approved", f"Approved registration of {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"reason": payload.reason})
    db.commit(); db.refresh(server)
    return _registration_out(db, server)


@approval_router.post("/{server_id}/reject", response_model=schemas.ServerRegistrationOut)
def reject_registration(server_id: int, payload: schemas.ServerRegistrationDecisionIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server or server.registration_source != "api" or not _can_approve(db, current_user, server):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Registration not found")
    if server.registration_status != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Registration is not pending approval")
    server.registration_status = "rejected"; server.enabled = False; server.registration_rejection_reason = payload.reason
    secret = db.get(Secret, server.ssh_auth_secret_id) if server.ssh_auth_secret_id else None
    if secret:
        secret.status = "disabled"
    write_audit(db, "server_registration_rejected", f"Rejected registration of {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata={"reason": payload.reason})
    db.commit(); db.refresh(server)
    return _registration_out(db, server)

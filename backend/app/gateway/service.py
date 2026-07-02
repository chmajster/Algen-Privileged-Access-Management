import json
import uuid

from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.config import settings
from app.models import AccessGrant, GatewayConnection, GatewayEvent, GatewayRecording, Session, SessionCommand, utcnow
from app.session_monitor import detect_sudo_command

from .recorder import GatewayRecorder


def write_gateway_event(
    db: DBSession,
    event_type: str,
    message: str,
    *,
    session: Session | None = None,
    grant: AccessGrant | None = None,
    metadata: dict | None = None,
) -> GatewayEvent:
    item = GatewayEvent(
        session_id=session.id if session else None,
        grant_id=grant.id if grant else None,
        user_id=(grant.user_id if grant else session.user_id if session else None),
        server_id=(grant.server_id if grant else session.server_id if session else None),
        event_type=event_type,
        message=message,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(item)
    write_audit(
        db,
        event_type,
        message,
        user_id=item.user_id,
        server_id=item.server_id,
        grant_id=item.grant_id,
        session_id=item.session_id,
        metadata=metadata,
    )
    return item


def gateway_username_for(grant: AccessGrant) -> str:
    return grant.gateway_username or grant.linux_username


def gateway_connection_string(grant: AccessGrant) -> str:
    return f"ssh {gateway_username_for(grant)}+{grant.server_id}@{settings.pam_gateway_host} -p {settings.pam_gateway_port}"


def create_gateway_session(
    db: DBSession,
    grant: AccessGrant,
    *,
    client_ip: str = "127.0.0.1",
    client_port: int = 55000,
    mock: bool = False,
) -> GatewayConnection:
    now = utcnow()
    server = grant.server
    gateway_session_id = f"gw-{grant.id}-{uuid.uuid4().hex[:12]}"
    target_user = server.gateway_target_user or server.ssh_admin_user or "root"
    session = Session(
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        linux_username=grant.linux_username,
        source_ip=client_ip,
        started_at=now,
        status="active",
        session_record_type="gateway_jsonl" if settings.pam_gateway_session_recording else "none",
        access_mode="gateway",
        gateway_session_id=gateway_session_id,
        target_host=server.ip_address,
        target_port=server.ssh_port,
        target_user=target_user,
        client_ip=client_ip,
        client_port=client_port,
        recording_enabled=settings.pam_gateway_session_recording,
        idle_timeout_seconds=settings.pam_gateway_idle_timeout_seconds,
        max_session_seconds=settings.pam_gateway_max_session_seconds,
    )
    db.add(session)
    db.flush()

    connection = GatewayConnection(
        session_id=session.id,
        grant_id=grant.id,
        user_id=grant.user_id,
        server_id=grant.server_id,
        gateway_username=gateway_username_for(grant),
        target_host=server.ip_address,
        target_port=server.ssh_port,
        target_user=target_user,
        client_ip=client_ip,
        client_port=client_port,
        started_at=now,
        status="active",
    )
    db.add(connection)
    db.flush()

    write_gateway_event(db, "gateway_login_success", "Gateway login accepted", session=session, grant=grant)
    write_gateway_event(db, "gateway_session_started", "Gateway session started", session=session, grant=grant)

    if settings.pam_gateway_session_recording:
        recorder = GatewayRecorder()
        path = recorder.path_for(session.id)
        session.recording_path = str(path)
        session.session_record_path = str(path)
        recording = GatewayRecording(
            session_id=session.id,
            grant_id=grant.id,
            user_id=grant.user_id,
            server_id=grant.server_id,
            recording_path=str(path),
            recording_type="jsonl",
            started_at=now,
        )
        db.add(recording)
        db.flush()
        write_gateway_event(db, "gateway_recording_started", "Gateway recording started", session=session, grant=grant, metadata={"recording_id": recording.id})
        if mock:
            recorder.append(session, "stdout", f"Connected to {server.hostname}\n", 1)
            recorder.append(session, "stdin", "whoami\n", 2)
            recorder.append(session, "stdout", "pam gateway user\n", 3)
            size, checksum = recorder.checksum(path)
            recording.size_bytes = size
            recording.checksum_sha256 = checksum
            session.recording_size_bytes = size

    if mock and settings.pam_gateway_command_logging:
        add_gateway_command(db, session, grant, "whoami", 1, stdout="pam gateway user\n")
        add_gateway_command(db, session, grant, "hostname", 2, stdout=f"{server.hostname}\n")
        add_gateway_command(db, session, grant, "sudo systemctl status nginx", 3, stdout="nginx.service active\n")
        connection.bytes_in = 128
        connection.bytes_out = 512

    return connection


def add_gateway_command(
    db: DBSession,
    session: Session,
    grant: AccessGrant,
    command: str,
    command_index: int,
    *,
    stdin: str | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
) -> SessionCommand:
    item = SessionCommand(
        session_id=session.id,
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        linux_username=grant.linux_username,
        command=command,
        working_directory=None,
        is_sudo=detect_sudo_command(command),
        executed_at=utcnow(),
        raw_log=json.dumps({"source": "gateway", "command": command, "index": command_index}, ensure_ascii=False),
        source="gateway",
        command_index=command_index,
        stdin_fragment=stdin or command,
        stdout_fragment=stdout,
        stderr_fragment=stderr,
        terminal_output_preview=(stdout or stderr or "")[:500],
    )
    db.add(item)
    db.flush()
    from app.policy.engine import PolicyEngine

    engine = PolicyEngine(db)
    decision = engine.evaluate_command(item)
    item.risk_score = decision.risk_score
    item.risk_severity = decision.severity
    item.matched_policy_rule_id = decision.matched_rules[0]["id"] if decision.matched_rules else None
    item.blocked_by_policy = decision.denied
    engine.record_risk_event(
        decision,
        "gateway_command_denied" if decision.denied else "gateway_command_risk_detected",
        f"Gateway command risk detected: {command[:160]}",
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        session_id=session.id,
        command_id=item.id,
    )
    write_gateway_event(db, "gateway_command_detected", f"Gateway command detected: {command[:120]}", session=session, grant=grant, metadata={"command_index": command_index, "is_sudo": item.is_sudo})
    if settings.pam_auto_revoke_on_critical_risk and decision.severity == "critical" and grant.status == "active":
        from app.services import revoke_grant

        revoke_grant(db, grant, None, "auto revoked after critical gateway command risk")
    return item


def finish_gateway_connection(db: DBSession, connection: GatewayConnection, reason: str = "completed") -> GatewayConnection:
    if connection.status != "active":
        return connection
    now = utcnow()
    connection.status = "closed" if reason == "completed" else "terminated"
    connection.ended_at = now
    connection.termination_reason = reason
    session = connection.session
    session.status = "closed" if reason == "completed" else "terminated"
    session.ended_at = now
    session.duration_seconds = max(0, int((now - session.started_at).total_seconds()))
    session.termination_reason = reason

    recording = db.query(GatewayRecording).filter(GatewayRecording.session_id == session.id).first()
    if recording:
        recorder = GatewayRecorder()
        recorder.finalize_model(recording)
        session.recording_size_bytes = recording.size_bytes
        write_gateway_event(db, "gateway_recording_finished", "Gateway recording finished", session=session, grant=connection.grant, metadata={"recording_id": recording.id, "size_bytes": recording.size_bytes})

    event_type = "gateway_session_finished" if reason == "completed" else "gateway_session_terminated"
    write_gateway_event(db, event_type, f"Gateway session ended: {reason}", session=session, grant=connection.grant, metadata={"termination_reason": reason})
    return connection


def seed_mock_gateway_for_grant(db: DBSession, grant: AccessGrant) -> GatewayConnection | None:
    existing = db.query(GatewayConnection).filter(GatewayConnection.grant_id == grant.id).first()
    if existing:
        return existing
    return create_gateway_session(db, grant, mock=True)

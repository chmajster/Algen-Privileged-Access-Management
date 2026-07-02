from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="user", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    ssh_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local", index=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    last_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_password_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_identity_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)


class UserIdentity(Base, TimestampMixin):
    __tablename__ = "user_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_claims_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User")


class UserGroup(Base, TimestampMixin):
    __tablename__ = "user_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    group_name: Mapped[str] = mapped_column(String(255), index=True)
    group_dn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship("User")


class MfaChallenge(Base):
    __tablename__ = "mfa_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    challenge_type: Mapped[str] = mapped_column(String(64), index=True)
    context: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User] = relationship("User")


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(255))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship("User")


class StepUpSession(Base):
    __tablename__ = "step_up_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    context: Mapped[str] = mapped_column(String(128), index=True)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship("User")


class AuthEvent(Base):
    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User | None] = relationship("User")


class Server(Base, TimestampMixin):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str] = mapped_column(String(64))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    environment: Mapped[str] = mapped_column(String(64), index=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    ssh_admin_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssh_private_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    session_recording_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    command_logging_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    gateway_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    gateway_target_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway_auth_type: Mapped[str] = mapped_column(String(32), default="key")
    gateway_private_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    direct_access_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_ref_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    gateway_secret_ref_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    ssh_auth_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    rotation_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_secret_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_secret_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    server_group_id: Mapped[int | None] = mapped_column(ForeignKey("server_groups.id"), nullable=True, index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="low", index=True)
    require_session_recording: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)


class AccessRequest(Base, TimestampMixin):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    requested_duration_minutes: Mapped[int] = mapped_column(Integer)
    requested_access_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approver_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    calculated_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    policy_decision_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    session_recording_required: Mapped[bool] = mapped_column(Boolean, default=False)
    denied_by_policy: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    approver: Mapped[User | None] = relationship("User", foreign_keys=[approver_id])
    server: Mapped[Server] = relationship("Server")


class AccessGrant(Base, TimestampMixin):
    __tablename__ = "access_grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("access_requests.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    linux_username: Mapped[str] = mapped_column(String(32), index=True)
    access_type: Mapped[str] = mapped_column(String(32))
    ssh_public_key: Mapped[str] = mapped_column(Text)
    sudo_policy: Mapped[str | None] = mapped_column(Text, nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    access_mode: Mapped[str] = mapped_column(String(32), default="direct", index=True)
    gateway_username: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    gateway_connection_string: Mapped[str | None] = mapped_column(String(512), nullable=True)
    gateway_session_required: Mapped[bool] = mapped_column(Boolean, default=False)
    direct_ssh_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    calculated_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    policy_decision_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    monitoring_level: Mapped[str] = mapped_column(String(32), default="basic")

    request: Mapped[AccessRequest] = relationship("AccessRequest")
    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), index=True)
    environment: Mapped[str] = mapped_column(String(64), index=True)
    access_type: Mapped[str] = mapped_column(String(32), index=True)
    max_duration_minutes: Mapped[int] = mapped_column(Integer)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    command_logging_required: Mapped[bool] = mapped_column(Boolean, default=True)
    session_recording_required: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True, index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    message: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User | None] = relationship("User")
    server: Mapped[Server | None] = relationship("Server")


class Session(Base, TimestampMixin):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    linux_username: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    session_record_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    session_record_type: Mapped[str] = mapped_column(String(32), default="none")
    access_mode: Mapped[str] = mapped_column(String(32), default="direct", index=True)
    gateway_session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recording_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recording_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    recording_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    idle_timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_session_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    termination_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)

    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")
    commands: Mapped[list["SessionCommand"]] = relationship("SessionCommand", back_populates="session")


class SessionCommand(Base):
    __tablename__ = "session_commands"
    __table_args__ = (UniqueConstraint("session_id", "raw_log", name="uq_session_command_raw"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    linux_username: Mapped[str] = mapped_column(String(32), index=True)
    command: Mapped[str] = mapped_column(Text)
    working_directory: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_sudo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(32), default="bash_hook", index=True)
    command_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdin_fragment: Mapped[str | None] = mapped_column(Text, nullable=True)
    stdout_fragment: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_fragment: Mapped[str | None] = mapped_column(Text, nullable=True)
    terminal_output_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_severity: Mapped[str] = mapped_column(String(32), default="low", index=True)
    matched_policy_rule_id: Mapped[int | None] = mapped_column(ForeignKey("policy_rules.id"), nullable=True, index=True)
    blocked_by_policy: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[Session] = relationship("Session", back_populates="commands")
    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")


class LogImportOffset(Base):
    __tablename__ = "log_import_offsets"
    __table_args__ = (UniqueConstraint("server_id", "grant_id", "linux_username", "log_path", name="uq_log_import_offset"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    linux_username: Mapped[str] = mapped_column(String(32), index=True)
    log_path: Mapped[str] = mapped_column(String(512), index=True)
    last_offset: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    server: Mapped[Server] = relationship("Server")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")


class GatewayConnection(Base, TimestampMixin):
    __tablename__ = "gateway_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    gateway_username: Mapped[str] = mapped_column(String(64), index=True)
    target_host: Mapped[str] = mapped_column(String(255))
    target_port: Mapped[int] = mapped_column(Integer, default=22)
    target_user: Mapped[str] = mapped_column(String(64))
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    termination_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)

    session: Mapped[Session] = relationship("Session")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")
    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")


class GatewayRecording(Base):
    __tablename__ = "gateway_recordings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    recording_path: Mapped[str] = mapped_column(String(512))
    recording_type: Mapped[str] = mapped_column(String(32), default="jsonl")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    checksum_sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    encryption_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    session: Mapped[Session] = relationship("Session")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")
    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")
    encryption_secret: Mapped["Secret | None"] = relationship("Secret")


class GatewayEvent(Base):
    __tablename__ = "gateway_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    message: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    session: Mapped[Session | None] = relationship("Session")
    grant: Mapped[AccessGrant | None] = relationship("AccessGrant")
    user: Mapped[User | None] = relationship("User")
    server: Mapped[Server | None] = relationship("Server")


class Secret(Base, TimestampMixin):
    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    secret_type: Mapped[str] = mapped_column(String(64), index=True)
    backend_type: Mapped[str] = mapped_column(String(64), index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(64), default="active", index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    versions: Mapped[list["SecretVersion"]] = relationship("SecretVersion", back_populates="secret")


class SecretVersion(Base):
    __tablename__ = "secret_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int] = mapped_column(ForeignKey("secrets.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="active", index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    secret: Mapped[Secret] = relationship("Secret", back_populates="versions")


class SecretAccessLog(Base):
    __tablename__ = "secret_access_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    secret_version_id: Mapped[int | None] = mapped_column(ForeignKey("secret_versions.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    access_context: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    secret: Mapped[Secret | None] = relationship("Secret")
    secret_version: Mapped[SecretVersion | None] = relationship("SecretVersion")
    user: Mapped[User | None] = relationship("User")
    server: Mapped[Server | None] = relationship("Server")


class SecretRotationJob(Base, TimestampMixin):
    __tablename__ = "secret_rotation_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    job_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(64), default="pending", index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    old_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    new_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    secret: Mapped[Secret | None] = relationship("Secret")
    server: Mapped[Server | None] = relationship("Server")


class PolicyRule(Base, TimestampMixin):
    __tablename__ = "policy_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(64), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_role: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    server_group: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    access_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    condition_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    action_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score_delta: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    command_id: Mapped[int | None] = mapped_column(ForeignKey("session_commands.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("policy_rules.id"), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User | None] = relationship("User")
    server: Mapped[Server | None] = relationship("Server")
    rule: Mapped[PolicyRule | None] = relationship("PolicyRule")


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_event_id: Mapped[int | None] = mapped_column(ForeignKey("risk_events.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id"), nullable=True, index=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    risk_event: Mapped[RiskEvent | None] = relationship("RiskEvent")
    user: Mapped[User | None] = relationship("User", foreign_keys=[user_id])
    server: Mapped[Server | None] = relationship("Server")


class ServerGroup(Base, TimestampMixin):
    __tablename__ = "server_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class ServerGroupMember(Base):
    __tablename__ = "server_group_members"
    __table_args__ = (UniqueConstraint("server_group_id", "server_id", name="uq_server_group_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    group: Mapped[ServerGroup] = relationship("ServerGroup")
    server: Mapped[Server] = relationship("Server")

"""Database model for the protocol-independent PAM schema (version 3).

Protocol credentials and connection options deliberately live in the typed
connection-profile tables.  Grants and sessions only describe authorization
and lifecycle state.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Environment(Base, TimestampMixin):
    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


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
    auth_provider: Mapped[str] = mapped_column(String(32), default="local_db", index=True)
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
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(64))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    environment: Mapped[str] = mapped_column(String(64), index=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    ssh_admin_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssh_auth_type: Mapped[str] = mapped_column(String(32), default="vault_secret")
    ssh_private_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    rotation_admin_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rotation_auth_type: Mapped[str] = mapped_column(String(32), default="password")
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
    rotation_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True, index=True)
    rotation_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_secret_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_secret_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    server_group_id: Mapped[int | None] = mapped_column(ForeignKey("server_groups.id"), nullable=True, index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="low", index=True)
    require_session_recording: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    server_template_id: Mapped[int | None] = mapped_column(ForeignKey("server_templates.id"), nullable=True, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    registration_source: Mapped[str] = mapped_column(String(32), default="manual", index=True)
    registration_status: Mapped[str] = mapped_column(String(32), default="approved", index=True)
    registration_rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    registration_connection_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host_key_policy: Mapped[str] = mapped_column(String(32), default="strict")
    expected_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    protocol: Mapped[str] = mapped_column(String(32), default="ssh", index=True)
    allowed_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
    allow_private_network: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_subdomains: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    connection_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)


class AccessWizardDraft(Base, TimestampMixin):
    __tablename__ = "access_wizard_drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    mode: Mapped[str] = mapped_column(String(32), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    completed_steps_json: Mapped[str] = mapped_column(Text, default="[]")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AccessWizardSubmission(Base):
    __tablename__ = "access_wizard_submissions"
    __table_args__ = (UniqueConstraint("user_id", "submission_key", name="uq_access_wizard_submission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    submission_key: Mapped[str] = mapped_column(String(64), index=True)
    result_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


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


class PamPolicy(Base, TimestampMixin):
    __tablename__ = "pam_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="disabled", index=True)
    value_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str] = mapped_column(String(32), default="global", index=True)
    scope_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    exceptions_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    creator: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_id])
    updater: Mapped["User | None"] = relationship("User", foreign_keys=[updated_by_id])


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
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    object_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    result: Mapped[str] = mapped_column(String(32), default="success", index=True)
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
    protocol: Mapped[str] = mapped_column(String(32), default="ssh", index=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    authentication_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    absolute_timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    user: Mapped[User] = relationship("User")
    server: Mapped[Server] = relationship("Server")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")
    commands: Mapped[list["SessionCommand"]] = relationship("SessionCommand", back_populates="session")


class WebConnectionProfile(Base, TimestampMixin):
    __tablename__ = "web_connection_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), unique=True, index=True)
    initial_url: Mapped[str] = mapped_column(Text)
    authentication_mode: Mapped[str] = mapped_column(String(32), default="none")
    username_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    password_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    auth_secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    username_selector: Mapped[str | None] = mapped_column(String(512), nullable=True)
    password_selector: Mapped[str | None] = mapped_column(String(512), nullable=True)
    submit_selector: Mapped[str | None] = mapped_column(String(512), nullable=True)
    success_url_pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    success_dom_selector: Mapped[str | None] = mapped_column(String(512), nullable=True)
    header_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cookie_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    blocked_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
    upload_policy: Mapped[str] = mapped_column(String(32), default="deny")
    download_policy: Mapped[str] = mapped_column(String(32), default="deny")
    clipboard_policy: Mapped[str] = mapped_column(String(32), default="deny")
    popup_policy: Mapped[str] = mapped_column(String(32), default="same_origin")
    max_upload_bytes: Mapped[int] = mapped_column(Integer, default=10_485_760)
    max_download_bytes: Mapped[int] = mapped_column(Integer, default=52_428_800)
    login_timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    idle_timeout_seconds: Mapped[int] = mapped_column(Integer, default=900)
    maximum_session_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)

    server: Mapped[Server] = relationship("Server")


class VncConnectionProfile(Base, TimestampMixin):
    __tablename__ = "vnc_connection_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=5900)
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    tls_required: Mapped[bool] = mapped_column(Boolean, default=True)


class SessionEvent(Base):
    __tablename__ = "session_events"
    __table_args__ = (UniqueConstraint("session_id", "sequence_number", name="uq_session_event_sequence"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    sequence_number: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), index=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionArtifact(Base):
    __tablename__ = "session_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(32), index=True)
    storage_path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    mime_type: Mapped[str] = mapped_column(String(128))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


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
    matched_policy_id: Mapped[int | None] = mapped_column(ForeignKey("pam_policies.id"), nullable=True, index=True)
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
    matched_policy_id: Mapped[int | None] = mapped_column(ForeignKey("pam_policies.id"), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User | None] = relationship("User")
    server: Mapped[Server | None] = relationship("Server")
    policy: Mapped["PamPolicy | None"] = relationship("PamPolicy")


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
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    allowed_access_types: Mapped[str] = mapped_column(String(128), default="ssh_only")
    max_grant_minutes: Mapped[int] = mapped_column(Integer, default=60)
    allowed_durations: Mapped[str] = mapped_column(String(128), default="30,60")
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    require_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    deny_direct_ssh: Mapped[bool] = mapped_column(Boolean, default=False)
    require_command_logging: Mapped[bool] = mapped_column(Boolean, default=True)
    require_session_recording: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_hours: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed_weekdays: Mapped[str] = mapped_column(String(32), default="0,1,2,3,4,5,6")
    max_concurrent_grants: Mapped[int] = mapped_column(Integer, default=1)
    max_active_sessions: Mapped[int] = mapped_column(Integer, default=1)
    allow_self_extension: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_auto_grant: Mapped[bool] = mapped_column(Boolean, default=False)
    require_reason: Mapped[bool] = mapped_column(Boolean, default=True)
    min_reason_length: Mapped[int] = mapped_column(Integer, default=10)
    revoke_on_membership_loss: Mapped[bool] = mapped_column(Boolean, default=True)
    terminate_sessions_on_membership_loss: Mapped[bool] = mapped_column(Boolean, default=True)


class ServerTemplate(Base, TimestampMixin):
    __tablename__ = "server_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    environment: Mapped[str] = mapped_column(String(64), default="dev", index=True)
    default_ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    criticality: Mapped[str] = mapped_column(String(32), default="low")
    gateway_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    direct_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    require_session_recording: Mapped[bool] = mapped_column(Boolean, default=False)
    command_logging_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_auth_types: Mapped[str] = mapped_column(String(128), default="password")
    connection_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    registration_requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    host_key_policy: Mapped[str] = mapped_column(String(32), default="strict")
    expected_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    allow_special_addresses: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_cidrs: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)


class ServerTemplateDefaultGroup(Base):
    __tablename__ = "server_template_default_groups"
    __table_args__ = (UniqueConstraint("template_id", "server_group_id", name="uq_server_template_default_group"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("server_templates.id"), index=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)


class ServerTemplateAllowedGroup(Base):
    __tablename__ = "server_template_allowed_groups"
    __table_args__ = (UniqueConstraint("template_id", "server_group_id", name="uq_server_template_allowed_group"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("server_templates.id"), index=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)


class ServerRegistrationIdentity(Base):
    __tablename__ = "server_registration_identities"
    __table_args__ = (
        UniqueConstraint("address", "ssh_port", name="uq_server_registration_address_port"),
        UniqueConstraint("hostname", name="uq_server_registration_hostname"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), unique=True, index=True)
    address: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer)
    hostname: Mapped[str] = mapped_column(String(255))


class ServerRegistrationIdempotency(Base):
    __tablename__ = "server_registration_idempotency"
    __table_args__ = (UniqueConstraint("user_id", "idempotency_key", name="uq_server_registration_idempotency"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    response_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ServerGroupMember(Base):
    __tablename__ = "server_group_members"
    __table_args__ = (UniqueConstraint("server_group_id", "server_id", name="uq_server_group_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    group: Mapped[ServerGroup] = relationship("ServerGroup")
    server: Mapped[Server] = relationship("Server")


class ServerGroupUserMembership(Base, TimestampMixin):
    __tablename__ = "server_group_user_memberships"
    __table_args__ = (UniqueConstraint("server_group_id", "user_id", name="uq_server_group_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    group_role: Mapped[str] = mapped_column(String(32), default="user", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    permission_template_id: Mapped[int | None] = mapped_column(ForeignKey("access_group_permission_templates.id"), nullable=True, index=True)

    group: Mapped[ServerGroup] = relationship("ServerGroup")
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    created_by: Mapped[User | None] = relationship("User", foreign_keys=[created_by_id])
    permission_template: Mapped["PermissionTemplate | None"] = relationship("PermissionTemplate")


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role", "permission_id", name="uq_role_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    permission: Mapped[Permission] = relationship("Permission")


class GroupPermission(Base, TimestampMixin):
    __tablename__ = "group_permissions"
    __table_args__ = (UniqueConstraint("server_group_id", "permission_id", name="uq_group_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    permission: Mapped[Permission] = relationship("Permission")


class UserGroupPermission(Base, TimestampMixin):
    __tablename__ = "user_group_permissions"
    __table_args__ = (UniqueConstraint("server_group_id", "user_id", "permission_id", name="uq_user_group_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_group_id: Mapped[int] = mapped_column(ForeignKey("server_groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    permission: Mapped[Permission] = relationship("Permission")


# Compatibility tables from the first RBAC iteration. Startup migration reads
# them into ServerGroup; authorization never queries them. PermissionTemplate
# remains active because it is a reusable UI preset, not an access scope.
class PermissionTemplate(Base, TimestampMixin):
    __tablename__ = "access_group_permission_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions_json: Mapped[str] = mapped_column(Text, default="{}")
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)


class AccessGroup(Base, TimestampMixin):
    __tablename__ = "access_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    allowed_access_types: Mapped[str] = mapped_column(String(128), default="ssh_only")
    max_grant_minutes: Mapped[int] = mapped_column(Integer, default=60)
    allowed_durations: Mapped[str] = mapped_column(String(128), default="30,60")
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    require_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    deny_direct_ssh: Mapped[bool] = mapped_column(Boolean, default=False)
    require_command_logging: Mapped[bool] = mapped_column(Boolean, default=True)
    require_session_recording: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_hours: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed_weekdays: Mapped[str] = mapped_column(String(32), default="0,1,2,3,4,5,6")
    max_concurrent_grants: Mapped[int] = mapped_column(Integer, default=1)
    max_active_sessions: Mapped[int] = mapped_column(Integer, default=1)
    allow_self_extension: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_auto_grant: Mapped[bool] = mapped_column(Boolean, default=False)
    require_reason: Mapped[bool] = mapped_column(Boolean, default=True)
    min_reason_length: Mapped[int] = mapped_column(Integer, default=10)
    revoke_on_membership_loss: Mapped[bool] = mapped_column(Boolean, default=True)
    terminate_sessions_on_membership_loss: Mapped[bool] = mapped_column(Boolean, default=True)


class AccessGroupUser(Base):
    __tablename__ = "access_group_users"
    __table_args__ = (UniqueConstraint("access_group_id", "user_id", name="uq_access_group_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    access_group_id: Mapped[int] = mapped_column(ForeignKey("access_groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    group_role: Mapped[str] = mapped_column(String(32), default="user", index=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    permission_template_id: Mapped[int | None] = mapped_column(ForeignKey("access_group_permission_templates.id"), nullable=True)

    group: Mapped[AccessGroup] = relationship("AccessGroup")
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    assigned_by: Mapped[User | None] = relationship("User", foreign_keys=[assigned_by_id])
    permission_template: Mapped[PermissionTemplate | None] = relationship("PermissionTemplate")


class AccessGroupServer(Base):
    __tablename__ = "access_group_servers"
    __table_args__ = (UniqueConstraint("access_group_id", "server_id", name="uq_access_group_server"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    access_group_id: Mapped[int] = mapped_column(ForeignKey("access_groups.id"), index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id"), index=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    group: Mapped[AccessGroup] = relationship("AccessGroup")
    server: Mapped[Server] = relationship("Server")


class AccessGroupPermission(Base):
    __tablename__ = "access_group_permissions"
    __table_args__ = (UniqueConstraint("access_group_id", "membership_id", "permission", name="uq_access_group_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    access_group_id: Mapped[int] = mapped_column(ForeignKey("access_groups.id"), index=True)
    membership_id: Mapped[int | None] = mapped_column(ForeignKey("access_group_users.id"), nullable=True, index=True)
    permission: Mapped[str] = mapped_column(String(128), index=True)
    effect: Mapped[str] = mapped_column(String(16), default="allow", index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    group: Mapped[AccessGroup] = relationship("AccessGroup")
    membership: Mapped[AccessGroupUser | None] = relationship("AccessGroupUser")

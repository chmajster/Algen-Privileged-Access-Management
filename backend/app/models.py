"""Database model for the protocol-independent PAM schema (version 2).

Protocol credentials and connection options deliberately live in the typed
connection-profile tables.  Grants and sessions only describe authorization
and lifecycle state.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


SCHEMA_VERSION = 3


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="user", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
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
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    last_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_password_change_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_identity_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)


class UserIdentity(Base, TimestampMixin):
    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("provider", "external_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    username: Mapped[str] = mapped_column(String(128))
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
    challenge_type: Mapped[str] = mapped_column(String(64))
    context: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
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
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user: Mapped[User | None] = relationship("User")


class ResourceGroup(Base, TimestampMixin):
    __tablename__ = "resource_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class Resource(Base, TimestampMixin):
    __tablename__ = "resources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    resource_type: Mapped[str] = mapped_column(String(16), index=True)
    environment: Mapped[str] = mapped_column(String(64), index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="low", index=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("resource_groups.id"), nullable=True, index=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_private_network: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
    group: Mapped[ResourceGroup | None] = relationship("ResourceGroup")


class ConnectionProfile(Base, TimestampMixin):
    __tablename__ = "connection_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    resource: Mapped[Resource] = relationship("Resource")


class SSHConnectionProfile(Base):
    __tablename__ = "ssh_connection_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_profile_id: Mapped[int] = mapped_column(ForeignKey("connection_profiles.id"), unique=True)
    hostname: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(64))
    administrative_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_mode: Mapped[str] = mapped_column(String(32), default="private_key")
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    host_key_policy: Mapped[str] = mapped_column(String(32), default="strict")
    expected_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sudo_policy: Mapped[str | None] = mapped_column(Text, nullable=True)
    connection_timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    gateway_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    direct_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sudo_mode: Mapped[str] = mapped_column(String(32), default="none")
    connection_profile: Mapped[ConnectionProfile] = relationship("ConnectionProfile")


class WebConnectionProfile(Base):
    __tablename__ = "web_connection_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_profile_id: Mapped[int] = mapped_column(ForeignKey("connection_profiles.id"), unique=True)
    initial_url: Mapped[str] = mapped_column(String(2048))
    blocked_domains: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    login_timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    idle_timeout_seconds: Mapped[int] = mapped_column(Integer, default=900)
    maximum_session_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    allow_downloads: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_uploads: Mapped[bool] = mapped_column(Boolean, default=False)
    clipboard_policy: Mapped[str] = mapped_column(String(32), default="deny")
    record_video: Mapped[bool] = mapped_column(Boolean, default=True)
    record_trace: Mapped[bool] = mapped_column(Boolean, default=True)
    record_events: Mapped[bool] = mapped_column(Boolean, default=True)
    connection_profile: Mapped[ConnectionProfile] = relationship("ConnectionProfile")


class AccessProfile(Base, TimestampMixin):
    __tablename__ = "access_profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    resource_type: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    access_option: Mapped[str] = mapped_column(String(32), default="standard")
    resource_group_id: Mapped[int | None] = mapped_column(ForeignKey("resource_groups.id"), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    user_group: Mapped[str | None] = mapped_column(String(255), nullable=True)
    max_session_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    recording_required: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_schedule_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    upload_policy: Mapped[str] = mapped_column(String(32), default="deny")
    download_policy: Mapped[str] = mapped_column(String(32), default="deny")
    clipboard_policy: Mapped[str] = mapped_column(String(32), default="deny")
    max_upload_bytes: Mapped[int] = mapped_column(Integer, default=10_485_760)
    max_download_bytes: Mapped[int] = mapped_column(Integer, default=10_485_760)


class AccessPolicy(Base, TimestampMixin):
    __tablename__ = "access_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    access_profile_id: Mapped[int] = mapped_column(ForeignKey("access_profiles.id"), unique=True, index=True)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_mode: Mapped[str] = mapped_column(String(32), default="any_approver")
    approval_group: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approval_stages_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_expiration_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    require_recording: Mapped[bool] = mapped_column(Boolean, default=True)
    record_events: Mapped[bool] = mapped_column(Boolean, default=True)
    capture_screenshots: Mapped[bool] = mapped_column(Boolean, default=False)
    idle_timeout_minutes: Mapped[int] = mapped_column(Integer, default=15)
    default_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    maximum_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    allow_downloads: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_uploads: Mapped[bool] = mapped_column(Boolean, default=False)
    clipboard_policy: Mapped[str] = mapped_column(String(32), default="deny")
    allowed_weekdays: Mapped[str] = mapped_column(String(32), default="0,1,2,3,4,5,6")
    allowed_time_ranges_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    scheduled_access: Mapped[bool] = mapped_column(Boolean, default=False)
    control_override_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_profile: Mapped[AccessProfile] = relationship("AccessProfile")


class AccessAssignment(Base, TimestampMixin):
    __tablename__ = "access_assignments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), index=True)
    access_profile_id: Mapped[int] = mapped_column(ForeignKey("access_profiles.id"), index=True)
    subject_type: Mapped[str] = mapped_column(String(32), index=True)
    subject_identifier: Mapped[str] = mapped_column(String(255), index=True)
    assignment_mode: Mapped[str] = mapped_column(String(32), default="request_required")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    resource: Mapped[Resource] = relationship("Resource")
    access_profile: Mapped[AccessProfile] = relationship("AccessProfile")


class AccessWizardDraft(Base, TimestampMixin):
    __tablename__ = "access_wizard_drafts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    mode: Mapped[str] = mapped_column(String(32))
    resource_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    completed_steps_json: Mapped[str] = mapped_column(Text, default="[]")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    user: Mapped[User] = relationship("User")


class AccessWizardSubmission(Base):
    __tablename__ = "access_wizard_submissions"
    __table_args__ = (UniqueConstraint("user_id", "submission_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    submission_key: Mapped[str] = mapped_column(String(64))
    result_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessRequest(Base, TimestampMixin):
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), index=True)
    access_profile_id: Mapped[int] = mapped_column(ForeignKey("access_profiles.id"))
    reason: Mapped[str] = mapped_column(Text)
    requested_duration_minutes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    approver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approver_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
    resource: Mapped[Resource] = relationship("Resource")
    access_profile: Mapped[AccessProfile] = relationship("AccessProfile")


class AccessGrant(Base, TimestampMixin):
    __tablename__ = "access_grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("access_requests.id"), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), index=True)
    access_profile_id: Mapped[int] = mapped_column(ForeignKey("access_profiles.id"))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[AccessRequest] = relationship("AccessRequest")
    user: Mapped[User] = relationship("User")
    resource: Mapped[Resource] = relationship("Resource")
    access_profile: Mapped[AccessProfile] = relationship("AccessProfile")


class PamSession(Base, TimestampMixin):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id"), index=True)
    grant_id: Mapped[int] = mapped_column(ForeignKey("access_grants.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), default="created", index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authentication_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    idle_timeout_seconds: Mapped[int] = mapped_column(Integer, default=900)
    absolute_timeout_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    termination_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    user: Mapped[User] = relationship("User")
    resource: Mapped[Resource] = relationship("Resource")
    grant: Mapped[AccessGrant] = relationship("AccessGrant")
    events: Mapped[list["SessionEvent"]] = relationship("SessionEvent", cascade="all, delete-orphan")
    artifacts: Mapped[list["SessionArtifact"]] = relationship("SessionArtifact", cascade="all, delete-orphan")


# Public domain name requested by the API contract without colliding with
# sqlalchemy.orm.Session imports in service code.
Session = PamSession


class SessionEvent(Base):
    __tablename__ = "session_events"
    __table_args__ = (UniqueConstraint("session_id", "sequence_number"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    sequence_number: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32))
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionArtifact(Base):
    __tablename__ = "session_artifacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(32), index=True)
    storage_path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role", "permission_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role: Mapped[str] = mapped_column(String(32), index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"))
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.id"), nullable=True, index=True)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("access_requests.id"), nullable=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    message: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    object_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[str] = mapped_column(String(32), default="success")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Secret(Base, TimestampMixin):
    __tablename__ = "secrets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    secret_type: Mapped[str] = mapped_column(String(64))
    backend_type: Mapped[str] = mapped_column(String(64), default="local_encrypted")
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(64), default="active")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_rotation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    status: Mapped[str] = mapped_column(String(64), default="active")
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
    secret_version_id: Mapped[int | None] = mapped_column(ForeignKey("secret_versions.id"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.id"), nullable=True)
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), nullable=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    access_context: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    secret: Mapped[Secret | None] = relationship("Secret")
    secret_version: Mapped[SecretVersion | None] = relationship("SecretVersion")
    user: Mapped[User | None] = relationship("User")


class SecretRotationJob(Base, TimestampMixin):
    __tablename__ = "secret_rotation_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("secrets.id"), nullable=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.id"), nullable=True)
    job_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(64), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    old_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    new_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

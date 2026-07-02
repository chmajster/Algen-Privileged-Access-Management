from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None
    challenge_id: int | None = None
    context: str | None = None
    provider: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str
    provider: str | None = None


class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "user"
    is_active: bool = True
    ssh_public_key: str | None = None
    auth_provider: str = "local"
    external_id: str | None = None
    display_name: str | None = None
    email_verified: bool = False
    mfa_enabled: bool = False
    mfa_required: bool = False
    risk_level: str = "low"
    last_risk_score: int = 0


class UserCreate(UserBase):
    password: str = Field(min_length=6)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=6)
    role: str | None = None
    is_active: bool | None = None
    ssh_public_key: str | None = None
    auth_provider: str | None = None
    external_id: str | None = None
    display_name: str | None = None
    email_verified: bool | None = None
    mfa_enabled: bool | None = None
    mfa_required: bool | None = None
    risk_level: str | None = None
    last_risk_score: int | None = None


class SshKeyUpdate(BaseModel):
    ssh_public_key: str


class UserOut(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None
    mfa_enrolled_at: datetime | None = None
    mfa_last_used_at: datetime | None = None
    last_identity_sync_at: datetime | None = None
    locked_until: datetime | None = None
    failed_login_count: int = 0


class ServerBase(BaseModel):
    hostname: str
    ip_address: str
    ssh_port: int = 22
    environment: str = "dev"
    owner: str | None = None
    description: str | None = None
    enabled: bool = True
    ssh_admin_user: str | None = None
    ssh_private_key_path: str | None = None
    session_recording_enabled: bool = False
    command_logging_enabled: bool = True
    gateway_enabled: bool = True
    gateway_target_user: str | None = None
    gateway_auth_type: str = "key"
    gateway_private_key_path: str | None = None
    direct_access_enabled: bool = True
    secret_ref_id: int | None = None
    gateway_secret_ref_id: int | None = None
    ssh_auth_secret_id: int | None = None
    rotation_enabled: bool = True
    last_secret_rotation_at: datetime | None = None
    next_secret_rotation_at: datetime | None = None
    risk_level: str = "low"
    server_group_id: int | None = None
    criticality: str = "low"
    require_session_recording: bool = False
    require_approval: bool = False
    require_mfa: bool = False


class ServerCreate(ServerBase):
    pass


class ServerUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    ssh_port: int | None = None
    environment: str | None = None
    owner: str | None = None
    description: str | None = None
    enabled: bool | None = None
    ssh_admin_user: str | None = None
    ssh_private_key_path: str | None = None
    session_recording_enabled: bool | None = None
    command_logging_enabled: bool | None = None
    gateway_enabled: bool | None = None
    gateway_target_user: str | None = None
    gateway_auth_type: str | None = None
    gateway_private_key_path: str | None = None
    direct_access_enabled: bool | None = None
    secret_ref_id: int | None = None
    gateway_secret_ref_id: int | None = None
    ssh_auth_secret_id: int | None = None
    rotation_enabled: bool | None = None
    last_secret_rotation_at: datetime | None = None
    next_secret_rotation_at: datetime | None = None
    risk_level: str | None = None
    server_group_id: int | None = None
    criticality: str | None = None
    require_session_recording: bool | None = None
    require_approval: bool | None = None
    require_mfa: bool | None = None


class ServerOut(ServerBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class AccessRequestCreate(BaseModel):
    server_id: int
    reason: str
    requested_duration_minutes: int
    requested_access_type: str


class DecisionIn(BaseModel):
    approver_comment: str | None = None


class AccessRequestOut(ORMModel):
    id: int
    user_id: int
    server_id: int
    reason: str
    requested_duration_minutes: int
    requested_access_type: str
    status: str
    approver_id: int | None = None
    approver_comment: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    calculated_risk_score: int = 0
    policy_decision_json: str | None = None
    mfa_required: bool = False
    approval_required: bool = False
    session_recording_required: bool = False
    denied_by_policy: bool = False
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class AccessGrantOut(ORMModel):
    id: int
    request_id: int
    user_id: int
    server_id: int
    linux_username: str
    access_type: str
    ssh_public_key: str
    sudo_policy: str | None = None
    valid_from: datetime
    valid_to: datetime
    revoked_at: datetime | None = None
    revoke_reason: str | None = None
    status: str
    access_mode: str = "direct"
    gateway_username: str | None = None
    gateway_connection_string: str | None = None
    gateway_session_required: bool = False
    direct_ssh_enabled: bool = True
    calculated_risk_score: int = 0
    policy_decision_json: str | None = None
    monitoring_level: str = "basic"
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class RevokeIn(BaseModel):
    reason: str = "manual revoke"


class PolicyBase(BaseModel):
    name: str
    role: str
    environment: str
    access_type: str
    max_duration_minutes: int
    requires_approval: bool = True
    command_logging_required: bool = True
    session_recording_required: bool = False
    enabled: bool = True


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    name: str | None = None
    role: str | None = None
    environment: str | None = None
    access_type: str | None = None
    max_duration_minutes: int | None = None
    requires_approval: bool | None = None
    command_logging_required: bool | None = None
    session_recording_required: bool | None = None
    enabled: bool | None = None


class PolicyOut(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class AuditLogOut(ORMModel):
    id: int
    user_id: int | None = None
    server_id: int | None = None
    request_id: int | None = None
    grant_id: int | None = None
    session_id: int | None = None
    action: str
    message: str
    source_ip: str | None = None
    metadata_json: str | None = None
    created_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class SessionOut(ORMModel):
    id: int
    user_id: int
    server_id: int
    grant_id: int
    linux_username: str
    source_ip: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    duration_seconds: int | None = None
    status: str
    session_record_path: str | None = None
    session_record_type: str
    access_mode: str = "direct"
    gateway_session_id: str | None = None
    target_host: str | None = None
    target_port: int | None = None
    target_user: str | None = None
    client_ip: str | None = None
    client_port: int | None = None
    recording_enabled: bool = False
    recording_path: str | None = None
    recording_size_bytes: int | None = None
    idle_timeout_seconds: int | None = None
    max_session_seconds: int | None = None
    termination_reason: str | None = None
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    server_hostname: str | None = None
    command_count: int | None = None
    access_type: str | None = None


class SessionCommandOut(ORMModel):
    id: int
    session_id: int
    user_id: int
    server_id: int
    grant_id: int
    linux_username: str
    command: str
    working_directory: str | None = None
    is_sudo: bool | None = None
    exit_code: int | None = None
    executed_at: datetime
    raw_log: str | None = None
    created_at: datetime
    source: str = "bash_hook"
    command_index: int | None = None
    stdin_fragment: str | None = None
    stdout_fragment: str | None = None
    stderr_fragment: str | None = None
    terminal_output_preview: str | None = None
    risk_score: int = 0
    risk_severity: str = "low"
    matched_policy_rule_id: int | None = None
    blocked_by_policy: bool = False
    username: str | None = None
    server_hostname: str | None = None


class GatewayConnectionOut(ORMModel):
    id: int
    session_id: int
    grant_id: int
    user_id: int
    server_id: int
    gateway_username: str
    target_host: str
    target_port: int
    target_user: str
    client_ip: str | None = None
    client_port: int | None = None
    started_at: datetime
    ended_at: datetime | None = None
    status: str
    termination_reason: str | None = None
    bytes_in: int
    bytes_out: int
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class GatewayRecordingOut(ORMModel):
    id: int
    session_id: int
    grant_id: int
    user_id: int
    server_id: int
    recording_path: str
    recording_type: str
    size_bytes: int
    checksum_sha256: str | None = None
    encryption_secret_id: int | None = None
    encrypted: bool = False
    started_at: datetime
    ended_at: datetime | None = None
    created_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class GatewayEventOut(ORMModel):
    id: int
    session_id: int | None = None
    grant_id: int | None = None
    user_id: int | None = None
    server_id: int | None = None
    event_type: str
    message: str
    metadata_json: str | None = None
    created_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class SecretCreate(BaseModel):
    name: str
    secret_type: str = "generic"
    backend_type: str = "local_encrypted"
    environment: str | None = None
    owner: str | None = None
    description: str | None = None
    value: str | None = None
    file_path: str | None = None
    external_ref: str | None = None
    public_key: str | None = None
    expires_at: datetime | None = None


class SecretUpdate(BaseModel):
    name: str | None = None
    environment: str | None = None
    owner: str | None = None
    description: str | None = None
    value: str | None = None
    file_path: str | None = None
    external_ref: str | None = None
    public_key: str | None = None
    status: str | None = None
    expires_at: datetime | None = None


class SecretOut(ORMModel):
    id: int
    name: str
    secret_type: str
    backend_type: str
    environment: str | None = None
    owner: str | None = None
    description: str | None = None
    fingerprint: str | None = None
    public_key: str | None = None
    version: int
    status: str
    expires_at: datetime | None = None
    last_rotated_at: datetime | None = None
    next_rotation_at: datetime | None = None
    created_by: int | None = None
    updated_by: int | None = None
    created_at: datetime
    updated_at: datetime


class SecretVersionOut(ORMModel):
    id: int
    secret_id: int
    version: int
    fingerprint: str | None = None
    public_key: str | None = None
    status: str
    created_by: int | None = None
    created_at: datetime
    activated_at: datetime | None = None
    revoked_at: datetime | None = None
    rotation_reason: str | None = None


class SecretAccessLogOut(ORMModel):
    id: int
    secret_id: int | None = None
    secret_version_id: int | None = None
    user_id: int | None = None
    server_id: int | None = None
    grant_id: int | None = None
    session_id: int | None = None
    action: str
    access_context: str | None = None
    source_ip: str | None = None
    success: bool
    message: str | None = None
    metadata_json: str | None = None
    created_at: datetime


class SecretRotationJobOut(ORMModel):
    id: int
    secret_id: int | None = None
    server_id: int | None = None
    job_type: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    old_fingerprint: str | None = None
    new_fingerprint: str | None = None
    metadata_json: str | None = None
    created_at: datetime
    updated_at: datetime
    secret_name: str | None = None
    server_hostname: str | None = None


class PolicyRuleBase(BaseModel):
    name: str
    description: str | None = None
    rule_type: str
    priority: int = 100
    enabled: bool = True
    environment: str | None = None
    user_role: str | None = None
    server_group: str | None = None
    access_type: str | None = None
    condition_json: str | None = None
    action_json: str | None = None
    risk_score_delta: int = 0


class PolicyRuleCreate(PolicyRuleBase):
    pass


class PolicyRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rule_type: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    environment: str | None = None
    user_role: str | None = None
    server_group: str | None = None
    access_type: str | None = None
    condition_json: str | None = None
    action_json: str | None = None
    risk_score_delta: int | None = None


class PolicyRuleOut(PolicyRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_by: int | None = None
    updated_by: int | None = None
    created_at: datetime
    updated_at: datetime


class PolicyDecisionOut(BaseModel):
    allowed: bool
    denied: bool
    requires_approval: bool
    requires_mfa: bool
    mfa_context: str | None = None
    mfa_reason: str | None = None
    step_up_valid_until: str | None = None
    requires_session_recording: bool
    requires_gateway: bool
    risk_score: int
    severity: str
    matched_rules: list[dict]
    actions: list[str]
    message: str


class PolicyEvaluateIn(BaseModel):
    user_id: int
    server_id: int
    access_type: str = "ssh_only"
    duration: int = 60
    reason: str | None = None
    command: str | None = None


class RiskEventOut(ORMModel):
    id: int
    user_id: int | None = None
    server_id: int | None = None
    grant_id: int | None = None
    session_id: int | None = None
    command_id: int | None = None
    event_type: str
    severity: str
    risk_score: int
    rule_id: int | None = None
    message: str
    metadata_json: str | None = None
    created_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class AlertOut(ORMModel):
    id: int
    risk_event_id: int | None = None
    user_id: int | None = None
    server_id: int | None = None
    grant_id: int | None = None
    session_id: int | None = None
    alert_type: str
    severity: str
    status: str
    title: str
    message: str
    assigned_to: int | None = None
    acknowledged_by: int | None = None
    acknowledged_at: datetime | None = None
    resolved_by: int | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    username: str | None = None
    server_hostname: str | None = None


class ServerGroupCreate(BaseModel):
    name: str
    description: str | None = None
    environment: str | None = None


class ServerGroupUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    environment: str | None = None


class ServerGroupOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    environment: str | None = None
    created_at: datetime
    updated_at: datetime


class MfaStatusOut(BaseModel):
    enabled: bool
    required: bool
    enrolled_at: datetime | None = None
    last_used_at: datetime | None = None
    recovery_codes_remaining: int = 0


class MfaEnrollStartOut(BaseModel):
    secret: str
    provisioning_uri: str
    challenge_id: int


class MfaVerifyIn(BaseModel):
    code: str
    challenge_id: int | None = None
    mfa_token: str | None = None
    context: str | None = None
    recovery_code: bool = False


class MfaDisableIn(BaseModel):
    code: str


class MfaChallengeOut(ORMModel):
    id: int
    user_id: int
    challenge_type: str
    context: str
    status: str
    expires_at: datetime
    verified_at: datetime | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    created_at: datetime


class StepUpIn(BaseModel):
    context: str
    reason: str | None = None


class StepUpStatusOut(BaseModel):
    context: str
    valid: bool
    valid_until: datetime | None = None


class RecoveryCodesOut(BaseModel):
    codes: list[str]


class ProviderOut(BaseModel):
    name: str
    enabled: bool
    default: bool = False


class IdentityUserOut(UserOut):
    disabled_reason: str | None = None


class UserIdentityOut(ORMModel):
    id: int
    user_id: int
    provider: str
    external_id: str
    username: str
    email: str | None = None
    display_name: str | None = None
    raw_claims_json: str | None = None
    last_login_at: datetime | None = None
    last_sync_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class UserGroupOut(ORMModel):
    id: int
    user_id: int
    provider: str
    group_name: str
    group_dn: str | None = None
    source: str | None = None
    created_at: datetime
    updated_at: datetime


class AuthEventOut(ORMModel):
    id: int
    user_id: int | None = None
    provider: str | None = None
    event_type: str
    success: bool
    source_ip: str | None = None
    user_agent: str | None = None
    message: str | None = None
    metadata_json: str | None = None
    created_at: datetime
    username: str | None = None


class SettingsOut(BaseModel):
    executor_mode: str
    session_log_import_enabled: bool
    session_log_dir: str
    scheduler_interval_seconds: int
    access_mode: str
    gateway_enabled: bool
    gateway_host: str
    gateway_port: int
    gateway_session_recording: bool
    gateway_command_logging: bool
    gateway_idle_timeout_seconds: int
    gateway_max_session_seconds: int
    vault_mode: str
    secret_rotation_enabled: bool
    secret_rotation_interval_hours: int
    ssh_key_rotation_enabled: bool
    policy_engine_enabled: bool
    risk_engine_enabled: bool
    alerts_enabled: bool
    auto_revoke_on_critical_risk: bool
    critical_risk_score: int
    high_risk_score: int
    medium_risk_score: int
    auth_providers: str
    default_auth_provider: str
    mfa_enabled: bool
    mfa_issuer: str
    mfa_required_for_admin: bool
    mfa_required_for_prod: bool
    mfa_required_for_full_sudo: bool
    mfa_required_for_gateway: bool
    mfa_required_for_secret_rotation: bool
    mfa_token_ttl_seconds: int
    step_up_ttl_seconds: int
    ldap_enabled: bool
    oidc_enabled: bool


class Message(BaseModel):
    message: str
    detail: Any | None = None

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ResourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    resource_type: Literal["ssh", "web"]
    environment: str = Field(min_length=1, max_length=64)
    criticality: Literal["low", "medium", "high", "critical"] = "low"
    group_id: int | None = None
    owner: str | None = None
    description: str | None = None
    enabled: bool = True
    allow_private_network: bool = False
    allowed_domains: list[str] = []


class ResourceGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None


class ConnectionProfileIn(BaseModel):
    resource_id: int
    name: str = "default"
    hostname: str | None = None
    port: int = 22
    username: str | None = None
    auth_mode: Literal["password", "private_key", "agent"] | None = None
    secret_id: int | None = None
    host_key_policy: Literal["strict", "trust_on_first_use"] = "strict"
    expected_host_key_fingerprint: str | None = None
    sudo_policy: str | None = None
    initial_url: HttpUrl | None = None
    authentication_mode: Literal["none", "basic_auth", "form", "http_header", "cookie", "manual"] | None = None
    username_secret_id: int | None = None
    password_secret_id: int | None = None
    auth_secret_id: int | None = None
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    success_url_pattern: str | None = None
    success_dom_selector: str | None = None
    header_name: str | None = None
    cookie_name: str | None = None


class AccessProfileIn(BaseModel):
    name: str
    resource_type: Literal["ssh", "web"] | None = None
    resource_group_id: int | None = None
    environment: str | None = None
    criticality: str | None = None
    user_id: int | None = None
    user_group: str | None = None
    max_session_duration_minutes: int = Field(default=60, ge=1, le=1440)
    approval_required: bool = True
    mfa_required: bool = False
    recording_required: bool = True
    allowed_schedule: dict[str, Any] | None = None
    upload_policy: Literal["deny", "allow"] = "deny"
    download_policy: Literal["deny", "allow"] = "deny"
    clipboard_policy: Literal["deny", "read", "write", "read_write"] = "deny"
    max_upload_bytes: int = Field(default=10_485_760, ge=0)
    max_download_bytes: int = Field(default=10_485_760, ge=0)


class AccessRequestIn(BaseModel):
    resource_id: int
    access_profile_id: int
    reason: str = Field(min_length=3, max_length=4000)
    requested_duration_minutes: int = Field(ge=1, le=1440)


class ApprovalIn(BaseModel):
    approver_comment: str | None = None


class RevokeIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class SessionCreate(BaseModel):
    grant_id: int
    idle_timeout_seconds: int | None = Field(default=None, ge=30, le=86400)


class SessionInput(BaseModel):
    token: str
    event: dict[str, Any]

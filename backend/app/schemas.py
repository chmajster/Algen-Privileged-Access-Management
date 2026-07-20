"""Schemas for retained identity, MFA and secret-store infrastructure APIs."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr


class ORMModel(BaseModel):
    model_config=ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token:str|None=None; token_type:str="bearer"; mfa_required:bool=False
    mfa_token:str|None=None; challenge_id:int|None=None; context:str|None=None; provider:str|None=None


class LoginRequest(BaseModel):
    username:str; password:str; provider:str|None=None


class UserOut(ORMModel):
    id:int; username:str; email:EmailStr; role:str; is_active:bool; auth_provider:str
    external_id:str|None=None; display_name:str|None=None; email_verified:bool=False
    mfa_enabled:bool=False; mfa_required:bool=False; risk_level:str="low"; last_risk_score:int=0
    created_at:datetime; updated_at:datetime; last_login_at:datetime|None=None
    mfa_enrolled_at:datetime|None=None; mfa_last_used_at:datetime|None=None
    last_identity_sync_at:datetime|None=None; locked_until:datetime|None=None; failed_login_count:int=0


class SecretCreate(BaseModel):
    name:str; secret_type:str="generic"; backend_type:str="local_encrypted"; environment:str|None=None
    owner:str|None=None; description:str|None=None; value:str|None=None; file_path:str|None=None
    external_ref:str|None=None; public_key:str|None=None; expires_at:datetime|None=None


class SecretUpdate(BaseModel):
    name:str|None=None; environment:str|None=None; owner:str|None=None; description:str|None=None
    value:str|None=None; file_path:str|None=None; external_ref:str|None=None; public_key:str|None=None
    status:str|None=None; expires_at:datetime|None=None


class SecretOut(ORMModel):
    id:int; name:str; secret_type:str; backend_type:str; environment:str|None=None; owner:str|None=None
    description:str|None=None; fingerprint:str|None=None; public_key:str|None=None; version:int; status:str
    expires_at:datetime|None=None; last_rotated_at:datetime|None=None; next_rotation_at:datetime|None=None
    created_by:int|None=None; updated_by:int|None=None; created_at:datetime; updated_at:datetime


class SecretVersionOut(ORMModel):
    id:int; secret_id:int; version:int; fingerprint:str|None=None; public_key:str|None=None; status:str
    created_by:int|None=None; created_at:datetime; activated_at:datetime|None=None; revoked_at:datetime|None=None
    rotation_reason:str|None=None


class SecretAccessLogOut(ORMModel):
    id:int; secret_id:int|None=None; secret_version_id:int|None=None; user_id:int|None=None
    resource_id:int|None=None; grant_id:int|None=None; session_id:int|None=None; action:str
    access_context:str|None=None; source_ip:str|None=None; success:bool; message:str|None=None
    metadata_json:str|None=None; created_at:datetime


class MfaStatusOut(BaseModel):
    enabled:bool; required:bool; enrolled_at:datetime|None=None; last_used_at:datetime|None=None; recovery_codes_remaining:int=0


class MfaEnrollStartOut(BaseModel):
    secret:str; provisioning_uri:str; challenge_id:int


class MfaVerifyIn(BaseModel):
    code:str; challenge_id:int|None=None; mfa_token:str|None=None; context:str|None=None; recovery_code:bool=False


class MfaDisableIn(BaseModel): code:str


class MfaChallengeOut(ORMModel):
    id:int; user_id:int; challenge_type:str; context:str; status:str; expires_at:datetime
    verified_at:datetime|None=None; source_ip:str|None=None; user_agent:str|None=None; created_at:datetime


class StepUpIn(BaseModel): context:str; reason:str|None=None
class StepUpStatusOut(BaseModel): context:str; valid:bool; valid_until:datetime|None=None
class RecoveryCodesOut(BaseModel): codes:list[str]
class ProviderOut(BaseModel): name:str; enabled:bool; default:bool=False


class IdentityUserOut(UserOut): disabled_reason:str|None=None


class UserIdentityOut(ORMModel):
    id:int; user_id:int; provider:str; external_id:str; username:str; email:str|None=None
    display_name:str|None=None; raw_claims_json:str|None=None; last_login_at:datetime|None=None
    last_sync_at:datetime|None=None; created_at:datetime; updated_at:datetime


class UserGroupOut(ORMModel):
    id:int; user_id:int; provider:str; group_name:str; group_dn:str|None=None; source:str|None=None
    created_at:datetime; updated_at:datetime


class AuthEventOut(ORMModel):
    id:int; user_id:int|None=None; provider:str|None=None; event_type:str; success:bool
    source_ip:str|None=None; user_agent:str|None=None; message:str|None=None; metadata_json:str|None=None
    created_at:datetime; username:str|None=None


class Message(BaseModel): message:str; detail:Any|None=None

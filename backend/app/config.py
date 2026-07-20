from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def readable_env_file(path: Path) -> Path | None:
    try:
        with path.open("rb"): pass
    except OSError: return None
    return path


DEFAULT_ENV_FILE=Path(__file__).parents[2]/".env"


class Settings(BaseSettings):
    database_url:str="sqlite:///./pam.db"
    secret_key:str="change-me"
    jwt_algorithm:str="HS256"
    jwt_expire_minutes:int=480
    pam_default_admin_user:str="administrator"
    pam_default_admin_email:str="administrator@localhost.localdomain"
    pam_default_admin_password:str="admin123"
    pam_auth_providers:str="local_os,local_db,ldap,oidc"
    pam_default_auth_provider:str="local_db"
    pam_local_auth_mode:str="database"
    pam_os_pam_service:str="login"
    pam_os_admin_users:str="root"
    pam_os_auto_provision:bool=True
    pam_mfa_enabled:bool=True
    pam_mfa_issuer:str="Algen PAM"
    pam_mfa_required_for_admin:bool=True
    pam_mfa_token_ttl_seconds:int=300
    pam_step_up_ttl_seconds:int=900
    pam_ldap_enabled:bool=False
    pam_ldap_url:str="ldap://ldap.example.local:389"
    pam_ldap_base_dn:str="dc=example,dc=local"
    pam_ldap_user_filter:str="(sAMAccountName={username})"
    pam_ldap_use_tls:bool=False
    pam_ldap_role_admin_group:str="PAM-Admins"
    pam_ldap_role_approver_group:str="PAM-Operators"
    pam_ldap_role_user_group:str="PAM-Users"
    pam_oidc_enabled:bool=False
    pam_oidc_issuer_url:str=""
    pam_oidc_client_id:str=""
    pam_oidc_redirect_uri:str="http://localhost:8080/api/auth/oidc/callback"
    pam_oidc_role_claim:str="roles"
    pam_oidc_username_claim:str="preferred_username"
    pam_oidc_email_claim:str="email"
    pam_oidc_admin_role:str="pam_admin"
    pam_oidc_approver_role:str="pam_operator"
    pam_oidc_user_role:str="pam_user"
    pam_vault_mode:str="local_encrypted"
    pam_vault_master_key:str="change-this-long-master-key"
    pam_secret_access_audit_enabled:bool=True
    pam_secret_rotation_interval_hours:int=24
    pam_artifact_dir:str="/data/artifacts"
    pam_browser_profile_dir:str="/data/browser-profiles"
    pam_browser_headless:bool=True
    pam_browser_concurrency:int=4
    pam_web_idle_timeout_seconds:int=900
    pam_web_absolute_timeout_seconds:int=3600
    pam_web_stream_token_ttl_seconds:int=60
    pam_web_viewport_width:int=1440
    pam_web_viewport_height:int=900
    pam_web_record_screenshots:bool=False
    pam_web_max_upload_bytes:int=10_485_760
    pam_web_max_download_bytes:int=10_485_760

    model_config=SettingsConfigDict(env_file=readable_env_file(DEFAULT_ENV_FILE),extra="ignore")


@lru_cache
def get_settings()->Settings: return Settings()


settings=get_settings()

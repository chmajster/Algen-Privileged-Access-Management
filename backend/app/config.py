from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def readable_env_file(path: Path) -> Path | None:
    """Use dotenv for manual launches, but trust systemd's EnvironmentFile when sandboxed."""
    try:
        with path.open("rb"):
            pass
    except OSError:
        return None
    return path


DEFAULT_ENV_FILE = Path(__file__).parents[2] / ".env"


class Settings(BaseSettings):
    database_url: str = "sqlite:///./pam_lite.db"
    secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    pam_executor_mode: str = "mock"
    pam_executor_ssh_key_path: str = "/run/secrets/pam_ssh_key"
    scheduler_interval_seconds: int = 60
    pam_session_log_import_enabled: bool = True
    pam_session_log_dir: str = "/var/log/pam-lite"
    pam_default_admin_user: str = "administrator"
    pam_default_admin_email: str = "administrator@localhost.localdomain"
    pam_default_admin_password: str = "admin123"
    pam_gateway_host: str = "0.0.0.0"
    pam_gateway_port: int = 2222
    pam_gateway_host_key_path: str = "/data/gateway_host_key"
    pam_vault_master_key: str = "change-this-32-byte-key"
    pam_vault_external_url: str = ""
    pam_vault_external_token: str = ""
    pam_ssh_key_type: str = "ed25519"
    pam_ssh_key_bits: int = 4096
    pam_secret_access_audit_enabled: bool = True
    pam_max_risk_score: int = 100
    pam_auth_providers: str = "local_os,local_db,ldap,oidc"
    pam_default_auth_provider: str = "local_db"
    pam_os_pam_service: str = "login"
    pam_os_admin_users: str = "root"
    pam_mfa_enabled: bool = False
    pam_mfa_issuer: str = "Linux PAM Lite"
    pam_ldap_enabled: bool = False
    pam_ldap_url: str = "ldap://ldap.example.local:389"
    pam_ldap_bind_dn: str = ""
    pam_ldap_bind_password: str = ""
    pam_ldap_base_dn: str = "dc=example,dc=local"
    pam_ldap_user_filter: str = "(sAMAccountName={username})"
    pam_ldap_group_filter: str = "(member={user_dn})"
    pam_ldap_use_tls: bool = False
    pam_ldap_role_admin_group: str = "Linux-PAM-Admins"
    pam_ldap_role_approver_group: str = "Linux-PAM-Approvers"
    pam_ldap_role_user_group: str = "Linux-PAM-Users"
    pam_oidc_enabled: bool = False
    pam_oidc_issuer_url: str = ""
    pam_oidc_client_id: str = ""
    pam_oidc_client_secret: str = ""
    pam_oidc_redirect_uri: str = "http://localhost:8080/auth/oidc/callback"
    pam_oidc_role_claim: str = "roles"
    pam_oidc_username_claim: str = "preferred_username"
    pam_oidc_email_claim: str = "email"
    pam_oidc_admin_role: str = "pam_admin"
    pam_oidc_approver_role: str = "pam_approver"
    pam_oidc_user_role: str = "pam_user"
    pam_registration_require_https: bool = True
    pam_registration_rate_limit_count: int = 10
    pam_registration_rate_limit_window_minutes: int = 60
    pam_registration_known_hosts_path: str = "/data/registration_known_hosts"
    pam_artifact_dir: str = "/app/data/pam-artifacts"
    pam_browser_profile_dir: str = "/tmp/algen-pam-browser-profiles"
    pam_browser_headless: bool = True
    pam_browser_concurrency: int = 8
    pam_web_viewport_width: int = 1440
    pam_web_viewport_height: int = 900
    pam_web_record_screenshots: bool = False
    pam_web_idle_timeout_seconds: int = 900
    pam_web_absolute_timeout_seconds: int = 28800
    pam_websocket_token_ttl_seconds: int = 60
    pam_vnc_enabled: bool = False
    pam_cors_origins: str = ""


    @property
    def pam_gateway_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("gateway.enabled", False)

    @property
    def pam_gateway_session_recording(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.recording", False)

    @property
    def pam_gateway_command_logging(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.command_logging", False)

    @property
    def pam_gateway_idle_timeout_seconds(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.idle_timeout", 900)

    @property
    def pam_gateway_max_session_seconds(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("gateway.max_session", 28800)

    @property
    def pam_vault_mode(self) -> str:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.vault_mode", "local_encrypted")

    @property
    def pam_secret_rotation_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.rotation_enabled", False)

    @property
    def pam_secret_rotation_interval_hours(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.rotation_interval", 24)

    @property
    def pam_ssh_key_rotation_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.ssh_key_rotation_enabled", False)

    @property
    def pam_risk_engine_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.engine_enabled", False)

    @property
    def pam_alerts_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.alerts_enabled", False)

    @property
    def pam_auto_revoke_on_critical_risk(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.auto_revoke", False)

    @property
    def pam_require_reason_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.require_reason", False)

    @property
    def pam_require_approval_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.require_approval", False)

    @property
    def pam_require_session_recording_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.recording", False)

    @property
    def pam_require_mfa_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", False)

    @property
    def pam_critical_risk_score(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.critical_threshold", 80)

    @property
    def pam_high_risk_score(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.high_threshold", 60)

    @property
    def pam_medium_risk_score(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.medium_threshold", 30)

    @property
    def pam_local_auth_mode(self) -> str:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.local_auth_mode", "database")

    @property
    def pam_os_auto_provision(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.os_auto_provision", False)

    @property
    def pam_mfa_required_for_admin(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", False)

    @property
    def pam_mfa_required_for_full_sudo(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", False)

    @property
    def pam_mfa_required_for_gateway(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", False)

    @property
    def pam_mfa_required_for_secret_rotation(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", False)

    @property
    def pam_mfa_token_ttl_seconds(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_token_ttl", 300)

    @property
    def pam_step_up_ttl_seconds(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.step_up_ttl", 900)

    @property
    def pam_access_mode(self) -> str:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.access_mode", "direct")

    @property
    def pam_group_scoped_access(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.group_scoped_access", False)

    @property
    def pam_policy_engine_enabled(self) -> bool:
        return False

    model_config = SettingsConfigDict(env_file=readable_env_file(DEFAULT_ENV_FILE), extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

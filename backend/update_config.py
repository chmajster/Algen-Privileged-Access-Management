import re

with open("app/config.py", "r") as f:
    content = f.read()

# Fields to remove from config.py and replace with properties
fields_to_remove = [
    "pam_gateway_enabled", "pam_gateway_session_recording", "pam_gateway_command_logging",
    "pam_gateway_idle_timeout_seconds", "pam_gateway_max_session_seconds", "pam_vault_mode",
    "pam_secret_rotation_enabled", "pam_secret_rotation_interval_hours", "pam_ssh_key_rotation_enabled",
    "pam_risk_engine_enabled", "pam_alerts_enabled", "pam_auto_revoke_on_critical_risk",
    "pam_require_reason_for_prod", "pam_require_approval_for_prod", "pam_require_session_recording_for_prod",
    "pam_require_mfa_for_prod", "pam_critical_risk_score", "pam_high_risk_score", "pam_medium_risk_score",
    "pam_local_auth_mode", "pam_os_auto_provision", "pam_mfa_required_for_admin",
    "pam_mfa_required_for_full_sudo", "pam_mfa_required_for_gateway", "pam_mfa_required_for_secret_rotation",
    "pam_mfa_token_ttl_seconds", "pam_step_up_ttl_seconds", "pam_access_mode", "pam_group_scoped_access",
    "pam_policy_engine_enabled", "pam_mfa_required_for_prod"
]

for field in fields_to_remove:
    content = re.sub(rf"^\s+{field}\s*:.*?\n", "", content, flags=re.MULTILINE)

properties_str = """
    @property
    def pam_gateway_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("gateway.enabled", True)

    @property
    def pam_gateway_session_recording(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.recording", True)

    @property
    def pam_gateway_command_logging(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.command_logging", True)

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
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.rotation_enabled", True)

    @property
    def pam_secret_rotation_interval_hours(self) -> int:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.rotation_interval", 24)

    @property
    def pam_ssh_key_rotation_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("secret.ssh_key_rotation_enabled", True)

    @property
    def pam_risk_engine_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.engine_enabled", True)

    @property
    def pam_alerts_enabled(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.alerts_enabled", True)

    @property
    def pam_auto_revoke_on_critical_risk(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("risk.auto_revoke", False)

    @property
    def pam_require_reason_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.require_reason", True)

    @property
    def pam_require_approval_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.require_approval", True)

    @property
    def pam_require_session_recording_for_prod(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("session.recording", True)

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
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.os_auto_provision", True)

    @property
    def pam_mfa_required_for_admin(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", True)

    @property
    def pam_mfa_required_for_full_sudo(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", True)

    @property
    def pam_mfa_required_for_gateway(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", True)

    @property
    def pam_mfa_required_for_secret_rotation(self) -> bool:
        from app.policy.resolver import get_policy_value; return get_policy_value("auth.mfa_required", True)

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
        from app.policy.resolver import get_policy_value; return get_policy_value("session.group_scoped_access", True)

    @property
    def pam_policy_engine_enabled(self) -> bool:
        return True
"""

content = content.replace("    model_config = SettingsConfigDict", properties_str + "\n    model_config = SettingsConfigDict")

with open("app/config.py", "w") as f:
    f.write(content)

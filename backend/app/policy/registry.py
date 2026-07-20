# Policy definitions for PAM
from typing import List, Dict, Any

class PolicyDefinition:
    def __init__(
        self,
        policy_id: str,
        name: str,
        description: str,
        category: str,
        value_type: str = "boolean",
        default_value: Any = None,
        allowed_scopes: List[str] = None
    ):
        self.policy_id = policy_id
        self.name = name
        self.description = description
        self.category = category
        self.value_type = value_type # boolean, integer, string, enum
        self.default_value = default_value
        self.allowed_scopes = allowed_scopes or ["global", "użytkownik", "grupa", "zasób", "typ zasobu", "protokół", "brama"]

POLICY_CATEGORIES = [
    "Authentication & Access",
    "Session Control",
    "Gateway Configuration",
    "Secret Management",
    "Risk & Alerts"
]

POLICY_REGISTRY: Dict[str, PolicyDefinition] = {}

def register_policy(policy: PolicyDefinition):
    POLICY_REGISTRY[policy.policy_id] = policy

# 1. Authentication & Access
register_policy(PolicyDefinition(
    policy_id="auth.mfa_required",
    name="MFA required",
    description="Wymagaj uwierzytelniania wieloskładnikowego (MFA).",
    category="Authentication & Access",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="auth.mfa_token_ttl",
    name="MFA tokens TTL",
    description="Czas życia tokenu MFA (w sekundach).",
    category="Authentication & Access",
    value_type="integer",
    default_value=3600
))

register_policy(PolicyDefinition(
    policy_id="auth.step_up_ttl",
    name="Step-up authentication TTL",
    description="Czas życia sesji po step-up authentication (w sekundach).",
    category="Authentication & Access",
    value_type="integer",
    default_value=900
))

register_policy(PolicyDefinition(
    policy_id="auth.local_auth_mode",
    name="Local Auth Mode",
    description="Tryb uwierzytelniania lokalnego (np. db, os, disabled).",
    category="Authentication & Access",
    value_type="string",
    default_value="db"
))

register_policy(PolicyDefinition(
    policy_id="auth.os_auto_provision",
    name="OS auto-provisioning",
    description="Automatyczne tworzenie kont w systemie operacyjnym.",
    category="Authentication & Access",
    value_type="boolean",
    default_value=False
))

# 2. Session Control
register_policy(PolicyDefinition(
    policy_id="session.recording",
    name="Session recording",
    description="Nagrywanie przebiegu sesji.",
    category="Session Control",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="session.command_logging",
    name="Command logging",
    description="Rejestrowanie poleceń wykonywanych w trakcie sesji.",
    category="Session Control",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="session.max_duration",
    name="Max session duration",
    description="Maksymalny czas trwania sesji (w minutach).",
    category="Session Control",
    value_type="integer",
    default_value=60
))

register_policy(PolicyDefinition(
    policy_id="session.idle_timeout",
    name="Idle timeout",
    description="Czas bezczynności przed zakończeniem sesji (w sekundach).",
    category="Session Control",
    value_type="integer",
    default_value=900
))

register_policy(PolicyDefinition(
    policy_id="session.group_scoped_access",
    name="Group-scoped access",
    description="Ograniczenie dostępu w oparciu o grupy.",
    category="Session Control",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="session.access_mode",
    name="Access mode",
    description="Tryb dostępu: exclusive lub shared.",
    category="Session Control",
    value_type="string",
    default_value="exclusive"
))

# 3. Gateway Configuration
register_policy(PolicyDefinition(
    policy_id="gateway.enabled",
    name="Gateway enabled",
    description="Włącz użycie bramy pośredniczącej.",
    category="Gateway Configuration",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="gateway.max_session",
    name="Max Gateway session duration",
    description="Maksymalny czas trwania sesji przez bramę (w sekundach).",
    category="Gateway Configuration",
    value_type="integer",
    default_value=3600
))

# 4. Secret Management
register_policy(PolicyDefinition(
    policy_id="secret.vault_mode",
    name="Vault mode",
    description="Tryb działania vaulta (np. local).",
    category="Secret Management",
    value_type="string",
    default_value="local"
))

register_policy(PolicyDefinition(
    policy_id="secret.rotation_enabled",
    name="Secret rotation enabled",
    description="Włącz rotację haseł/sekretów.",
    category="Secret Management",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="secret.ssh_key_rotation_enabled",
    name="SSH key rotation enabled",
    description="Włącz rotację kluczy SSH.",
    category="Secret Management",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="secret.rotation_interval",
    name="Secret rotation interval",
    description="Częstotliwość rotacji (w godzinach).",
    category="Secret Management",
    value_type="integer",
    default_value=24
))

# 5. Risk & Alerts
register_policy(PolicyDefinition(
    policy_id="risk.engine_enabled",
    name="Risk engine enabled",
    description="Włącz analizę ryzyka w czasie rzeczywistym.",
    category="Risk & Alerts",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="risk.auto_revoke",
    name="Auto-revoke on critical risk",
    description="Automatycznie wycofuj sesję przy krytycznym poziomie ryzyka.",
    category="Risk & Alerts",
    value_type="boolean",
    default_value=False
))

register_policy(PolicyDefinition(
    policy_id="risk.critical_threshold",
    name="Critical risk score threshold",
    description="Próg punktacji dla krytycznego ryzyka.",
    category="Risk & Alerts",
    value_type="integer",
    default_value=90
))

register_policy(PolicyDefinition(
    policy_id="risk.high_threshold",
    name="High risk score threshold",
    description="Próg punktacji dla wysokiego ryzyka.",
    category="Risk & Alerts",
    value_type="integer",
    default_value=70
))

register_policy(PolicyDefinition(
    policy_id="risk.medium_threshold",
    name="Medium risk score threshold",
    description="Próg punktacji dla średniego ryzyka.",
    category="Risk & Alerts",
    value_type="integer",
    default_value=40
))

register_policy(PolicyDefinition(
    policy_id="risk.alerts_enabled",
    name="Alerts enabled",
    description="Włącz powiadomienia o alarmach i ryzyku.",
    category="Risk & Alerts",
    value_type="boolean",
    default_value=False
))

def get_all_policies() -> List[PolicyDefinition]:
    return list(POLICY_REGISTRY.values())

def get_policy(policy_id: str) -> PolicyDefinition:
    return POLICY_REGISTRY.get(policy_id)

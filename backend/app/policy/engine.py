import json
from dataclasses import asdict, dataclass, field

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import AccessGrant, PolicyRule, RiskEvent, ServerGroup, ServerGroupMember, SessionCommand
from app.rbac import active_memberships, effective_permissions
from app.session_monitor import detect_sudo_command

from .actions import action_names, load_actions
from .alerts import create_alert_for_risk_event
from .conditions import load_json, matches_condition
from .risk import clamp_score, is_critical_command, is_dangerous_command, outside_business_hours, severity_for_score


@dataclass
class PolicyDecision:
    allowed: bool = True
    denied: bool = False
    requires_approval: bool = False
    requires_mfa: bool = False
    mfa_context: str | None = None
    mfa_reason: str | None = None
    step_up_valid_until: str | None = None
    requires_session_recording: bool = False
    requires_gateway: bool = False
    denies_direct_ssh: bool = False
    max_grant_minutes: int | None = None
    allowed_access_types: list[str] | None = None
    risk_score: int = 0
    severity: str = "info"
    matched_rules: list[dict] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    message: str = "Allowed by policy"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class PolicyEngine:
    def __init__(self, db: DBSession):
        self.db = db

    def _rbac_context(self, user, server) -> dict:
        memberships = active_memberships(self.db, user, server_id=server.id)
        group_rows = self.db.query(ServerGroup.id, ServerGroup.name).join(ServerGroupMember).filter(
            ServerGroupMember.server_id == server.id, ServerGroup.enabled.is_(True)
        ).all()
        group_ids = [row.id for row in group_rows]
        names = [row.name for row in group_rows]
        valid_until = [membership.valid_to.isoformat() for membership in memberships if membership.valid_to]
        permissions = [
            item["permission"] for item in effective_permissions(self.db, user, server_id=server.id)
            if item["effect"] == "allow"
        ]
        return {
            "user_role": "operator" if user.role == "approver" else user.role,
            "group_role": [membership.group_role for membership in memberships],
            "server_group_ids": group_ids,
            "server_group_names": names,
            "server_group": names[0] if len(names) == 1 else None,
            "effective_permissions": permissions,
            "membership_valid_until": min(valid_until) if valid_until else None,
            "server_environment": server.environment,
            "server_criticality": server.criticality,
        }

    def _rules(self, rule_type: str, context: dict) -> list[tuple[PolicyRule, dict]]:
        if not settings.pam_policy_engine_enabled:
            return []
        matched = []
        for rule in self.db.query(PolicyRule).filter(PolicyRule.enabled.is_(True), PolicyRule.rule_type == rule_type).order_by(PolicyRule.priority.asc()).all():
            if rule.environment and rule.environment not in {"*", context.get("environment")}:
                continue
            if rule.user_role and rule.user_role not in {"*", context.get("user_role")}:
                continue
            if rule.access_type and rule.access_type not in {"*", context.get("access_type")}:
                continue
            if rule.server_group and rule.server_group != "*" and rule.server_group not in context.get("server_group_names", [context.get("server_group")]):
                continue
            condition = load_json(rule.condition_json)
            if matches_condition(condition, context):
                matched.append((rule, load_actions(rule.action_json)))
        return matched

    def _base_decision(self, score: int, rules: list[tuple[PolicyRule, dict]], message: str) -> PolicyDecision:
        decision = PolicyDecision(risk_score=clamp_score(score), severity=severity_for_score(score), message=message)
        for rule, actions in rules:
            decision.risk_score = clamp_score(decision.risk_score + rule.risk_score_delta)
            decision.matched_rules.append({"id": rule.id, "name": rule.name, "risk_score_delta": rule.risk_score_delta})
            decision.actions.extend(action_names(actions))
            if actions.get("deny"):
                decision.denied = True
            if actions.get("require_approval"):
                decision.requires_approval = True
            if actions.get("require_mfa"):
                decision.requires_mfa = True
            if actions.get("require_session_recording"):
                decision.requires_session_recording = True
            if actions.get("requires_gateway"):
                decision.requires_gateway = True
            if actions.get("deny_direct_ssh"):
                decision.denies_direct_ssh = True
                decision.requires_gateway = True
            if actions.get("max_grant_minutes") is not None:
                value = int(actions["max_grant_minutes"])
                decision.max_grant_minutes = min(decision.max_grant_minutes or value, value)
            if isinstance(actions.get("allowed_access_types"), list):
                allowed = set(actions["allowed_access_types"])
                decision.allowed_access_types = sorted(allowed if decision.allowed_access_types is None else allowed & set(decision.allowed_access_types))
        decision.denied = bool(decision.denied)
        decision.allowed = not decision.denied
        decision.severity = severity_for_score(decision.risk_score)
        if decision.denied:
            decision.message = "Denied by policy"
        return decision

    def evaluate_access_request(self, user, server, access_type: str, duration: int, reason: str | None) -> PolicyDecision:
        score = 0
        if server.environment == "prod":
            score += 30
        if access_type == "full_sudo":
            score += 30
        if outside_business_hours():
            score += 20
        if not (reason or "").strip():
            score += 20
        if server.criticality == "critical":
            score += 30
        context = {"environment": server.environment, "access_type": access_type, "reason": reason, "criticality": server.criticality, **self._rbac_context(user, server)}
        decision = self._base_decision(score, self._rules("access_request", context), "Access request evaluated")
        if decision.max_grant_minutes is not None and duration > decision.max_grant_minutes:
            decision.denied = True
            decision.allowed = False
            decision.message = "Requested duration exceeds policy limit"
        if decision.allowed_access_types is not None and access_type not in decision.allowed_access_types:
            decision.denied = True
            decision.allowed = False
            decision.message = "Requested access type is restricted by policy"
        if settings.pam_require_approval_for_prod and server.environment == "prod":
            decision.requires_approval = True
        if settings.pam_require_session_recording_for_prod and server.environment == "prod":
            decision.requires_session_recording = True
        if settings.pam_require_mfa_for_prod and server.environment == "prod":
            decision.requires_mfa = True
        if settings.pam_mfa_required_for_prod and server.environment == "prod":
            decision.requires_mfa = True
            decision.mfa_context = "prod_full_sudo_request" if access_type == "full_sudo" else "prod_access_request"
            decision.mfa_reason = "Production access requires MFA"
        if settings.pam_mfa_required_for_full_sudo and access_type == "full_sudo":
            decision.requires_mfa = True
            decision.mfa_context = "prod_full_sudo_request" if server.environment == "prod" else "full_sudo_request"
            decision.mfa_reason = "Full sudo access requires MFA"
        if settings.pam_require_reason_for_prod and server.environment == "prod" and not (reason or "").strip():
            decision.denied = True
            decision.allowed = False
            decision.message = "Production access requires a reason"
        if decision.requires_mfa and not getattr(user, "mfa_enabled", False):
            decision.denied = True
            decision.allowed = False
            decision.message = "MFA is required by policy"
        return decision

    def evaluate_approval(self, request, approver) -> PolicyDecision:
        decision = self._base_decision(request.calculated_risk_score or 0, self._rules("approval", {"user_role": approver.role}), "Approval evaluated")
        if request.calculated_risk_score >= settings.pam_high_risk_score:
            decision.requires_mfa = True
            decision.mfa_context = "approve_high_risk_request"
            decision.mfa_reason = "High risk approval requires MFA"
        if request.user_id == approver.id:
            decision.denied = True
            decision.allowed = False
            decision.message = "Users cannot approve their own requests"
        return decision

    def evaluate_grant(self, grant: AccessGrant) -> PolicyDecision:
        return self._base_decision(grant.calculated_risk_score or 0, self._rules("grant", {"access_type": grant.access_type, "environment": grant.server.environment}), "Grant evaluated")

    def evaluate_session_start(self, session) -> PolicyDecision:
        return self._base_decision(session.grant.calculated_risk_score if session.grant else 0, self._rules("session_start", {"environment": session.server.environment}), "Session start evaluated")

    def evaluate_command(self, command: SessionCommand) -> PolicyDecision:
        score = 0
        if command.is_sudo or detect_sudo_command(command.command):
            score += 15
        if is_dangerous_command(command.command):
            score += 40
        if is_critical_command(command.command):
            score += 80
        context = {"command": command.command, "environment": command.server.environment if command.server else None}
        return self._base_decision(score, self._rules("command", context), "Command evaluated")

    def evaluate_gateway_login(self, user, server, grant) -> PolicyDecision:
        score = 0 if grant else 30
        context = {"environment": server.environment if server else None, "user_role": user.role if user else None, "has_grant": bool(grant)}
        if user and server:
            context.update(self._rbac_context(user, server))
        decision = self._base_decision(score, self._rules("gateway_login", context), "Gateway login evaluated")
        if not grant:
            decision.denied = True
            decision.allowed = False
            decision.message = "No active gateway grant"
        if settings.pam_mfa_required_for_gateway:
            decision.requires_mfa = True
            decision.mfa_context = "gateway_login"
            decision.mfa_reason = "Gateway access requires MFA step-up"
        return decision

    def evaluate_secret_use(self, secret, context: dict) -> PolicyDecision:
        decision = self._base_decision(10, self._rules("secret_use", {"environment": getattr(secret, "environment", None)}), "Secret use evaluated")
        if context.get("operation") == "rotation" and settings.pam_mfa_required_for_secret_rotation:
            decision.requires_mfa = True
            decision.mfa_context = "rotate_secret"
            decision.mfa_reason = "Secret rotation requires MFA"
        return decision

    def evaluate_revoke(self, grant, reason: str | None) -> PolicyDecision:
        return self._base_decision(0, self._rules("revoke", {"access_type": grant.access_type, "environment": grant.server.environment}), "Revoke evaluated")

    def record_risk_event(self, decision: PolicyDecision, event_type: str, message: str, *, user_id=None, server_id=None, grant_id=None, session_id=None, command_id=None, alert_type: str = "security") -> RiskEvent | None:
        if not settings.pam_risk_engine_enabled:
            return None
        if decision.risk_score < settings.pam_medium_risk_score and event_type not in {"secret_used", "gateway_login_denied"} and "denied" not in event_type:
            return None
        rule_id = decision.matched_rules[0]["id"] if decision.matched_rules else None
        event = RiskEvent(user_id=user_id, server_id=server_id, grant_id=grant_id, session_id=session_id, command_id=command_id, event_type=event_type, severity=decision.severity, risk_score=decision.risk_score, rule_id=rule_id, message=message, metadata_json=decision.to_json())
        self.db.add(event)
        self.db.flush()
        create_alert_for_risk_event(self.db, event, alert_type=alert_type)
        return event

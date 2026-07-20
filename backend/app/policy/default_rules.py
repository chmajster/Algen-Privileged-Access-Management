import json


DEFAULT_POLICY_RULES = [
    ("Prod requires approval", "access_request", 10, "prod", None, None, {"environment": "prod"}, {"require_approval": True}, 30),
    ("Prod requires session recording", "access_request", 20, "prod", None, None, {"environment": "prod"}, {"require_session_recording": True}, 15),
    ("Prod full sudo high risk", "access_request", 30, "prod", None, "full_sudo", {"environment": "prod", "access_type": "full_sudo"}, {"mark_high_risk": True, "alert": True}, 60),
    ("Outside business hours medium risk", "access_request", 40, None, None, None, {"time_range": "outside_business_hours"}, {"alert": True}, 30),
    ("Dangerous commands high risk", "command", 10, None, None, None, {"command_regex": r"rm\s+-rf|chmod\s+777|chown\s+-R|useradd|userdel|passwd|visudo|iptables|nft|systemctl\s+(stop|disable)|mkfs|dd\s+if=|curl.*\|\s*sh|wget.*\|\s*sh|kill\s+-9|reboot|shutdown"}, {"alert": True, "mark_high_risk": True}, 60),
    ("Shell history cleanup critical", "command", 5, None, None, None, {"command_regex": r"history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=/dev/null"}, {"alert": True, "mark_high_risk": True}, 90),
    ("Gateway login requires active grant", "gateway_login", 5, None, None, None, {"grant_missing": True}, {"deny_without_grant": True, "alert": True}, 30),
    ("Secret use info risk", "secret_use", 100, None, None, None, {}, {"alert": False}, 10),
    ("Critical full sudo requires recording", "access_request", 5, None, None, "full_sudo", {"criticality": "critical", "access_type": "full_sudo"}, {"require_approval": True, "require_session_recording": True, "alert": True}, 80),
    ("No self approval", "approval", 1, None, None, None, {}, {"deny_self_approval": True}, 100),
]


def seed_default_policy_rules(db, PolicyRule):
    for name, rule_type, priority, environment, user_role, access_type, condition, action, delta in DEFAULT_POLICY_RULES:
        if not db.query(PolicyRule).filter(PolicyRule.name == name).first():
            db.add(
                PolicyRule(
                    name=name,
                    description=f"Default rule: {name}",
                    rule_type=rule_type,
                    priority=priority,
                    enabled=True,
                    environment=environment,
                    user_role=user_role,
                    access_type=access_type,
                    condition_json=json.dumps(condition),
                    action_json=json.dumps(action),
                    risk_score_delta=delta,
                )
            )

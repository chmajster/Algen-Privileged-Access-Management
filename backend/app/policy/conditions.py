import json
import re

from .risk import outside_business_hours


def load_json(value: str | None) -> dict:
    if not value:
        return {}
    return json.loads(value)


def matches_condition(condition: dict, context: dict) -> bool:
    if not condition:
        return True
    for key in ("environment", "access_type", "user_role"):
        expected = condition.get(key)
        if expected and expected not in {"*", context.get(key)}:
            return False
    if condition.get("requires_reason") and (context.get("reason") or "").strip():
        return False
    if condition.get("time_range") == "outside_business_hours" and not outside_business_hours():
        return False
    regex = condition.get("command_regex")
    if regex and not re.search(regex, context.get("command") or "", re.IGNORECASE):
        return False
    criticality = condition.get("criticality")
    if criticality and criticality != context.get("criticality"):
        return False
    server_group = condition.get("server_group")
    if server_group and server_group not in context.get("server_group_names", [context.get("server_group")]):
        return False
    required_permission = condition.get("effective_permission")
    if required_permission and required_permission not in context.get("effective_permissions", []):
        return False
    group_role = condition.get("group_role")
    if group_role and group_role not in context.get("group_role", []):
        return False
    if condition.get("grant_missing") and context.get("has_grant"):
        return False
    return True

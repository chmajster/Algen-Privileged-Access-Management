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
    if server_group and server_group != context.get("server_group"):
        return False
    if condition.get("grant_missing") and context.get("has_grant"):
        return False
    return True

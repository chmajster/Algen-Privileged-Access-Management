import json


def validate_rule_json(condition_json: str | None, action_json: str | None) -> None:
    for value in (condition_json, action_json):
        if value:
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ValueError("Rule JSON must be an object")

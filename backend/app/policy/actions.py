import json


def load_actions(value: str | None) -> dict:
    if not value:
        return {}
    return json.loads(value)


def action_names(actions: dict) -> list[str]:
    return [key for key, value in actions.items() if value]

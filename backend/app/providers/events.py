import json
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.models import PamSession, SessionEvent


FORBIDDEN_KEYS = {"password", "authorization", "cookie", "token", "secret", "value", "headers"}


def sanitize_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower() in FORBIDDEN_KEYS else sanitize_metadata(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    return value


def add_event(db: DBSession, session: PamSession, event_type: str, source: str,
              metadata: dict[str, Any] | None = None, sensitive: bool = False) -> SessionEvent:
    current = db.query(func.max(SessionEvent.sequence_number)).filter(SessionEvent.session_id == session.id).scalar() or 0
    event = SessionEvent(session_id=session.id, event_type=event_type, sequence_number=current + 1,
                         source=source, metadata_json=json.dumps(sanitize_metadata(metadata or {}), default=str),
                         sensitive=sensitive)
    db.add(event); db.flush()
    return event

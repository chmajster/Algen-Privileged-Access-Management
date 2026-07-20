import json
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.models import Session, SessionEvent

SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "cookie", "cookies", "authorization", "authentication", "header_value", "value", "text"}


def sanitize_metadata(value: Any) -> Any:
    """Fail closed when event metadata resembles credential material."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            lowered = str(key).lower()
            clean[key] = "[REDACTED]" if any(part in lowered for part in SENSITIVE_KEYS) else sanitize_metadata(item)
        return clean
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    return value


def add_event(db: DBSession, session: Session, event_type: str, source: str, metadata: dict[str, Any] | None = None, *, sensitive: bool = False) -> SessionEvent:
    sequence = (db.query(func.max(SessionEvent.sequence_number)).filter(SessionEvent.session_id == session.id).scalar() or 0) + 1
    event = SessionEvent(
        session_id=session.id,
        event_type=event_type,
        sequence_number=sequence,
        source=source,
        metadata_json=json.dumps(sanitize_metadata(metadata or {}), separators=(",", ":"), sort_keys=True),
        sensitive=sensitive,
    )
    db.add(event)
    db.flush()
    return event

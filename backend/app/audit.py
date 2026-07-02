import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


def write_audit(
    db: Session,
    action: str,
    message: str,
    *,
    user_id: int | None = None,
    server_id: int | None = None,
    request_id: int | None = None,
    grant_id: int | None = None,
    session_id: int | None = None,
    source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    log = AuditLog(
        action=action,
        message=message,
        user_id=user_id,
        server_id=server_id,
        request_id=request_id,
        grant_id=grant_id,
        session_id=session_id,
        source_ip=source_ip,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(log)
    db.flush()
    return log

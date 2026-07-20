import json
from contextvars import ContextVar, Token
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog

_request_user_agent: ContextVar[str | None] = ContextVar("audit_user_agent", default=None)


def set_audit_user_agent(value: str | None) -> Token:
    return _request_user_agent.set(value)


def reset_audit_user_agent(token: Token) -> None:
    _request_user_agent.reset(token)


def write_audit(db: Session, action: str, message: str, *, user_id: int | None = None,
                resource_id: int | None = None, request_id: int | None = None,
                grant_id: int | None = None, session_id: int | None = None,
                source_ip: str | None = None, user_agent: str | None = None,
                object_type: str | None = None, object_id: int | str | None = None,
                result: str = "success", metadata: dict[str, Any] | None = None) -> AuditLog:
    values = metadata or {}
    if object_type is None:
        for kind, value in (("resource", resource_id), ("access_request", request_id),
                            ("access_grant", grant_id), ("session", session_id)):
            if value is not None:
                object_type, object_id = kind, value
                break
    log = AuditLog(user_id=user_id, resource_id=resource_id, request_id=request_id,
                   grant_id=grant_id, session_id=session_id, action=action, message=message,
                   source_ip=source_ip, user_agent=(user_agent or _request_user_agent.get()),
                   object_type=object_type, object_id=str(object_id) if object_id is not None else None,
                   result=result, metadata_json=json.dumps(values, default=str))
    db.add(log)
    db.flush()
    return log

import json

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import SecretAccessLog


def write_secret_access_log(
    db: DBSession,
    *,
    action: str,
    secret_id: int | None = None,
    secret_version_id: int | None = None,
    user_id: int | None = None,
    server_id: int | None = None,
    grant_id: int | None = None,
    session_id: int | None = None,
    access_context: str | None = None,
    source_ip: str | None = None,
    success: bool = True,
    message: str | None = None,
    metadata: dict | None = None,
) -> SecretAccessLog:
    if not settings.pam_secret_access_audit_enabled:
        return None
    item = SecretAccessLog(
        secret_id=secret_id,
        secret_version_id=secret_version_id,
        user_id=user_id,
        server_id=server_id,
        grant_id=grant_id,
        session_id=session_id,
        action=action,
        access_context=access_context,
        source_ip=source_ip,
        success=success,
        message=message,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(item)
    db.flush()
    if action in {"secret_used", "secret_rotation_failed"}:
        from app.models import Secret
        from app.policy.engine import PolicyEngine

        secret = db.get(Secret, secret_id) if secret_id else None
        engine = PolicyEngine(db)
        decision = engine.evaluate_secret_use(secret, metadata or {})
        if not success:
            decision.risk_score = max(decision.risk_score, settings.pam_high_risk_score)
            decision.severity = "high"
            decision.message = message or action
        engine.record_risk_event(
            decision,
            action,
            message or f"Secret event: {action}",
            user_id=user_id,
            server_id=server_id,
            grant_id=grant_id,
            session_id=session_id,
            alert_type="secret",
        )
    return item

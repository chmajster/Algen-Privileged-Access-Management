from datetime import timedelta

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import Alert, RiskEvent, utcnow


def create_alert_for_risk_event(db: DBSession, event: RiskEvent, alert_type: str = "security") -> Alert | None:
    if not settings.pam_alerts_enabled:
        return None
    if event.severity not in {"high", "critical"} and event.risk_score < settings.pam_high_risk_score:
        return None
    cutoff = utcnow() - timedelta(minutes=10)
    duplicate = (
        db.query(Alert)
        .join(RiskEvent, Alert.risk_event_id == RiskEvent.id)
        .filter(
            Alert.user_id == event.user_id,
            Alert.server_id == event.server_id,
            Alert.status.in_(["open", "acknowledged"]),
            RiskEvent.event_type == event.event_type,
            RiskEvent.created_at >= cutoff,
        )
        .first()
    )
    if duplicate:
        duplicate.message = event.message
        duplicate.updated_at = utcnow()
        return duplicate
    alert = Alert(
        risk_event_id=event.id,
        user_id=event.user_id,
        server_id=event.server_id,
        grant_id=event.grant_id,
        session_id=event.session_id,
        alert_type=alert_type,
        severity=event.severity,
        status="open",
        title=f"{event.severity.upper()} {event.event_type}",
        message=event.message,
    )
    db.add(alert)
    db.flush()
    return alert

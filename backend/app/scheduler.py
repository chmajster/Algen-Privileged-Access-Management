from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.gateway.service import finish_gateway_connection
from app.models import AccessGrant, GatewayConnection, SecretRotationJob, utcnow
from app.services import revoke_grant
from app.session_monitor import import_session_logs_for_grant
from app.vault.rotation import rotate_secret_value, run_due_rotations


scheduler = BackgroundScheduler(timezone="UTC")


def _same_timezone(value, reference):
    if value.tzinfo is None and reference.tzinfo is not None:
        return value.replace(tzinfo=reference.tzinfo)
    if value.tzinfo is not None and reference.tzinfo is None:
        return value.replace(tzinfo=None)
    return value


def expire_due_grants(db: Session | None = None) -> int:
    owns_session = db is None
    db = db or SessionLocal()
    count = 0
    try:
        grants = db.query(AccessGrant).filter(AccessGrant.status == "active", AccessGrant.valid_to < utcnow()).all()
        for grant in grants:
            revoke_grant(db, grant, actor=None, reason="expired by scheduler", expired=True)
            count += 1
        db.commit()
        return count
    finally:
        if owns_session:
            db.close()


def import_active_grant_logs(db: Session | None = None) -> int:
    owns_session = db is None
    db = db or SessionLocal()
    try:
        imported = 0
        if settings.pam_session_log_import_enabled:
            grants = db.query(AccessGrant).filter(AccessGrant.status == "active").all()
            for grant in grants:
                if grant.direct_ssh_enabled:
                    imported += import_session_logs_for_grant(db, grant)
            db.commit()
        return imported
    finally:
        if owns_session:
            db.close()


def enforce_gateway_sessions(db: Session | None = None) -> int:
    owns_session = db is None
    db = db or SessionLocal()
    closed = 0
    now = utcnow()
    try:
        connections = db.query(GatewayConnection).filter(GatewayConnection.status == "active").all()
        for connection in connections:
            session = connection.session
            grant = connection.grant
            session.duration_seconds = max(0, int((now - _same_timezone(session.started_at, now)).total_seconds()))
            if grant.status != "active" or _same_timezone(grant.valid_to, now) <= now:
                finish_gateway_connection(db, connection, "grant_expired")
                closed += 1
                continue
            idle_seconds = session.idle_timeout_seconds or settings.pam_gateway_idle_timeout_seconds
            max_seconds = session.max_session_seconds or settings.pam_gateway_max_session_seconds
            idle_for = (now - _same_timezone(connection.updated_at, now)).total_seconds()
            running_for = (now - _same_timezone(connection.started_at, now)).total_seconds()
            if idle_seconds and idle_for > idle_seconds:
                finish_gateway_connection(db, connection, "idle_timeout")
                closed += 1
            elif max_seconds and running_for > max_seconds:
                finish_gateway_connection(db, connection, "max_session_time")
                closed += 1
        db.commit()
        return closed
    finally:
        if owns_session:
            db.close()


def process_secret_rotations(db: Session | None = None) -> int:
    owns_session = db is None
    db = db or SessionLocal()
    count = 0
    try:
        count += run_due_rotations(db)
        pending = db.query(SecretRotationJob).filter(SecretRotationJob.status == "pending", SecretRotationJob.secret_id.isnot(None)).all()
        for job in pending:
            if job.secret:
                rotate_secret_value(db, job.secret, reason=job.job_type)
                job.status = "completed"
                count += 1
        db.commit()
        return count
    finally:
        if owns_session:
            db.close()


def tick() -> None:
    import_active_grant_logs()
    enforce_gateway_sessions()
    process_secret_rotations()
    expire_due_grants()


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.add_job(tick, "interval", seconds=settings.scheduler_interval_seconds, id="pam-lite-tick", replace_existing=True)
        scheduler.start()


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)

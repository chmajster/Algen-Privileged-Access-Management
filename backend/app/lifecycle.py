import asyncio
from datetime import timezone

from app.database import SessionLocal
from app.models import AccessGrant, AccessWizardDraft, PamSession, utcnow
from app.routes.domain import terminate


_task: asyncio.Task | None = None


def aware(value):
    return value.replace(tzinfo=value.tzinfo or timezone.utc) if value else None


async def enforce_lifecycle_once() -> None:
    db=SessionLocal(); now=utcnow()
    try:
        db.query(AccessWizardDraft).filter(AccessWizardDraft.expires_at <= now).delete(synchronize_session=False)
        for session in db.query(PamSession).filter_by(status="active").all():
            grant=db.get(AccessGrant,session.grant_id); reason=None
            if not grant or grant.status!="active": reason="grant_revoked"
            elif aware(grant.valid_to)<=now: reason="grant_expired"
            elif session.authentication_expires_at and aware(session.authentication_expires_at)<=now: reason="jwt_expired"
            elif session.started_at and (now-aware(session.started_at)).total_seconds()>=session.absolute_timeout_seconds: reason="absolute_timeout"
            elif session.last_heartbeat_at and (now-aware(session.last_heartbeat_at)).total_seconds()>=session.idle_timeout_seconds: reason="idle_timeout"
            elif session.protocol=="web":
                from app.providers.web import web_provider
                if session.id not in web_provider.runtimes or not web_provider.healthy(): reason="worker_failure"
            elif session.protocol=="ssh":
                from app.providers.ssh import ssh_provider
                if session.id not in ssh_provider.clients: reason="worker_failure"
            if reason: await terminate(db,session,reason)
        db.commit()
    finally: db.close()


async def monitor() -> None:
    while True:
        try: await enforce_lifecycle_once()
        except Exception: pass
        await asyncio.sleep(5)


def start_lifecycle_monitor() -> None:
    global _task
    _task=asyncio.create_task(monitor())


async def stop_lifecycle_monitor() -> None:
    global _task
    if _task:
        _task.cancel()
        try: await _task
        except asyncio.CancelledError: pass
    _task=None

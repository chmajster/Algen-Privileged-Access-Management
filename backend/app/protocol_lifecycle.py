import asyncio
from datetime import timezone

from app.database import SessionLocal
from app.models import AccessGrant, Session, utcnow
from app.providers.base import ProviderContext
from app.providers.registry import provider_for

_task: asyncio.Task | None = None


def aware(value):
    return value.replace(tzinfo=value.tzinfo or timezone.utc) if value else None


async def terminate_protocol_session(db, session: Session, reason: str) -> None:
    """Idempotently stop provider resources before sealing database state."""
    if session.status not in {"active", "termination_pending"}:
        return
    provider = provider_for(session.protocol)
    try:
        await provider.terminate_session(ProviderContext(db, session.server, session.grant, session), reason)
    finally:
        now = utcnow()
        session.status = "terminated"
        session.ended_at = now
        session.termination_reason = reason
        session.duration_seconds = max(0, int((now - aware(session.started_at)).total_seconds()))
        db.flush()


async def enforce_lifecycle_once() -> None:
    db = SessionLocal()
    now = utcnow()
    try:
        for session in db.query(Session).filter(Session.protocol.in_(("web", "vnc")), Session.status.in_(("active", "termination_pending"))).all():
            grant = db.get(AccessGrant, session.grant_id)
            reason = "logout" if session.status == "termination_pending" else None
            if not reason and (not grant or grant.status != "active"): reason = "grant_revoked"
            elif not reason and aware(grant.valid_to) <= now: reason = "grant_expired"
            elif not reason and session.authentication_expires_at and aware(session.authentication_expires_at) <= now: reason = "jwt_expired"
            elif not reason and session.absolute_timeout_seconds and (now - aware(session.started_at)).total_seconds() >= session.absolute_timeout_seconds: reason = "absolute_timeout"
            elif not reason and session.idle_timeout_seconds and session.last_heartbeat_at and (now - aware(session.last_heartbeat_at)).total_seconds() >= session.idle_timeout_seconds: reason = "idle_timeout"
            if not reason and session.protocol == "web":
                from app.providers.web import web_provider
                if session.id not in web_provider.runtimes or not web_provider.healthy(): reason = "worker_failure"
            if not reason and session.protocol == "vnc":
                from app.providers.vnc import vnc_provider
                if session.id not in vnc_provider.runtimes: reason = "worker_failure"
            if reason:
                await terminate_protocol_session(db, session, reason)
        db.commit()
    finally:
        db.close()


async def _monitor() -> None:
    while True:
        try:
            await enforce_lifecycle_once()
        except Exception:
            pass
        await asyncio.sleep(5)


def start_protocol_lifecycle() -> None:
    global _task
    if not _task:
        _task = asyncio.create_task(_monitor())


async def stop_protocol_lifecycle() -> None:
    global _task
    if _task:
        _task.cancel()
        try: await _task
        except asyncio.CancelledError: pass
    _task = None
    from app.providers.web import web_provider
    await web_provider.shutdown()

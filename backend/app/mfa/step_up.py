from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import StepUpSession, User, utcnow
from app.mfa.challenge import create_challenge, write_auth_event


def step_up_context(name: str) -> str:
    return name


def has_valid_step_up(db: DBSession, user: User, context: str) -> bool:
    if not settings.pam_mfa_enabled:
        return True
    user_requires_mfa = user.mfa_required or (settings.pam_mfa_required_for_admin and user.role == "admin")
    if not user.mfa_enabled and not user_requires_mfa:
        return True
    if not user.mfa_enabled and user_requires_mfa:
        return False
    return has_step_up_session(db, user, context)


def has_step_up_session(db: DBSession, user: User, context: str) -> bool:
    return (
        db.query(StepUpSession)
        .filter(StepUpSession.user_id == user.id, StepUpSession.context == context, StepUpSession.valid_until >= utcnow())
        .count()
        > 0
    )


def require_step_up(db: DBSession, user: User, context: str, request: Request | None, *, reason: str | None = None, force: bool = False) -> None:
    if not settings.pam_mfa_enabled:
        return
    if not force and has_valid_step_up(db, user, context):
        return
    if force and user.mfa_enabled and has_step_up_session(db, user, context):
        return
    user_requires_mfa = user.mfa_required or (settings.pam_mfa_required_for_admin and user.role == "admin")
    if (force or user_requires_mfa) and not user.mfa_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {"code": "mfa_enrollment_required", "context": context, "message": "MFA enrollment is required before this action"},
        )
    source_ip = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    challenge = create_challenge(db, user, "step_up", context, source_ip=source_ip, user_agent=user_agent, metadata={"reason": reason or context})
    write_auth_event(db, "step_up_required", user=user, success=False, source_ip=challenge.source_ip, user_agent=challenge.user_agent, message=reason or f"Step-up required for {context}", metadata={"challenge_id": challenge.id, "context": context})
    db.commit()
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        {"code": "step_up_required", "challenge_id": challenge.id, "context": context, "message": reason or "MFA step-up required"},
    )

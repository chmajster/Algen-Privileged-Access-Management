import json
from datetime import timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import AuthEvent, MfaChallenge, StepUpSession, User, utcnow
from app.mfa.recovery_codes import verify_recovery_code
from app.mfa.totp import decrypt_mfa_secret, verify_totp


def write_auth_event(db: DBSession, event_type: str, *, user: User | None = None, provider: str | None = None, success: bool = True, source_ip: str | None = None, user_agent: str | None = None, message: str | None = None, metadata: dict | None = None) -> AuthEvent:
    item = AuthEvent(
        user_id=user.id if user else None,
        provider=provider or (user.auth_provider if user else None),
        event_type=event_type,
        success=success,
        source_ip=source_ip,
        user_agent=(user_agent or "")[:255] or None,
        message=message,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(item)
    db.flush()
    return item


def create_challenge(db: DBSession, user: User, challenge_type: str, context: str, *, source_ip: str | None = None, user_agent: str | None = None, metadata: dict | None = None) -> MfaChallenge:
    item = MfaChallenge(
        user_id=user.id,
        challenge_type=challenge_type,
        context=context,
        status="pending",
        expires_at=utcnow() + timedelta(seconds=settings.pam_mfa_token_ttl_seconds),
        source_ip=source_ip,
        user_agent=(user_agent or "")[:255] or None,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(item)
    db.flush()
    write_auth_event(db, "mfa_required" if challenge_type == "login" else "step_up_required", user=user, success=True, source_ip=source_ip, user_agent=user_agent, message=f"MFA required for {context}", metadata={"challenge_id": item.id, "context": context})
    return item


def verify_challenge(db: DBSession, challenge: MfaChallenge, code: str, *, recovery_code: bool = False) -> bool:
    expires_at = challenge.expires_at if challenge.expires_at.tzinfo else challenge.expires_at.replace(tzinfo=timezone.utc)
    if challenge.status != "pending" or expires_at < utcnow():
        challenge.status = "expired"
        return False
    user = db.get(User, challenge.user_id)
    if not user:
        challenge.status = "failed"
        return False
    ok = False
    if recovery_code:
        ok = verify_recovery_code(db, user, code)
    elif user.mfa_secret_encrypted:
        ok = verify_totp(decrypt_mfa_secret(user.mfa_secret_encrypted), code)
    if not ok:
        challenge.status = "failed"
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= 5:
            user.locked_until = utcnow() + timedelta(minutes=15)
            write_auth_event(db, "account_locked", user=user, success=False, source_ip=challenge.source_ip, user_agent=challenge.user_agent, message="Account locked after MFA failures")
        write_auth_event(db, "mfa_failed", user=user, success=False, source_ip=challenge.source_ip, user_agent=challenge.user_agent, message="Invalid MFA code", metadata={"challenge_id": challenge.id, "context": challenge.context})
        return False
    now = utcnow()
    challenge.status = "verified"
    challenge.verified_at = now
    user.mfa_last_used_at = now
    user.failed_login_count = 0
    user.locked_until = None
    if challenge.challenge_type == "step_up":
        db.add(
            StepUpSession(
                user_id=user.id,
                context=challenge.context,
                valid_until=now + timedelta(seconds=settings.pam_step_up_ttl_seconds),
                source_ip=challenge.source_ip,
                user_agent=challenge.user_agent,
            )
        )
    write_auth_event(db, "mfa_success" if challenge.challenge_type == "login" else "step_up_success", user=user, success=True, source_ip=challenge.source_ip, user_agent=challenge.user_agent, message=f"MFA verified for {challenge.context}", metadata={"challenge_id": challenge.id, "context": challenge.context})
    return True

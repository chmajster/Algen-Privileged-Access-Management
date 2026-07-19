import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from datetime import timezone
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.config import settings
from app.database import get_db
from app.identity.oidc_provider import authenticate_oidc_callback, oidc_login_url
from app.identity.local_provider import LocalAuthenticationBackendError
from app.identity.providers import authenticate_with_provider
from app.mfa.challenge import create_challenge, write_auth_event
from app.models import User, utcnow
from app.security import create_access_token


router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)


@router.post("/login", response_model=schemas.Token)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    provider = payload.provider or settings.pam_default_auth_provider
    ip = source_ip(request)
    user_agent = request.headers.get("user-agent")
    try:
        user, _ = authenticate_with_provider(db, provider, payload.username, payload.password)
    except LocalAuthenticationBackendError as exc:
        logger.exception("Linux PAM login backend failed for provider=%s: %s", provider, exc)
        db.rollback()
        write_auth_event(db, "login_backend_error", provider=provider, success=False, source_ip=ip, user_agent=user_agent, message="Linux PAM authentication backend unavailable")
        db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Linux PAM authentication is unavailable; check the service journal")
    locked_until = user.locked_until if user and user.locked_until and user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc) if user and user.locked_until else None
    if user and locked_until and locked_until > utcnow():
        write_auth_event(db, "account_locked", user=user, provider=provider, success=False, source_ip=ip, user_agent=user_agent, message="Account locked")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if not user or not user.is_active:
        target = db.query(User).filter(User.username == payload.username).first()
        if target:
            target.failed_login_count = (target.failed_login_count or 0) + 1
            if target.failed_login_count >= 5:
                from datetime import timedelta

                target.locked_until = utcnow() + timedelta(minutes=15)
                write_auth_event(db, "account_locked", user=target, provider=provider, success=False, source_ip=ip, user_agent=user_agent, message="Account locked after failed logins")
        write_auth_event(db, "login_failed", user=target, provider=provider, success=False, source_ip=ip, user_agent=user_agent, message="Login failed")
        write_audit(db, "auth.login_failed", f"Failed login for {payload.username}", source_ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    user.failed_login_count = 0
    user.locked_until = None
    write_auth_event(db, "login_attempt", user=user, provider=provider, success=True, source_ip=ip, user_agent=user_agent, message="Login credentials accepted")
    mfa_required = settings.pam_mfa_enabled and user.mfa_enabled and (user.mfa_required or (settings.pam_mfa_required_for_admin and user.role == "admin"))
    if mfa_required:
        challenge = create_challenge(db, user, "login", "login", source_ip=ip, user_agent=user_agent)
        db.commit()
        return schemas.Token(
            access_token=None,
            mfa_required=True,
            mfa_token=create_access_token(user.username, expires_minutes=max(1, settings.pam_mfa_token_ttl_seconds // 60), token_type="mfa", extra={"challenge_id": challenge.id, "provider": provider}),
            challenge_id=challenge.id,
            context="login",
            provider=provider,
        )
    user.last_login_at = utcnow()
    write_auth_event(db, "login_success", user=user, provider=provider, success=True, source_ip=ip, user_agent=user_agent, message="Login successful")
    write_audit(db, "auth.login", f"{user.username} logged in", user_id=user.id, source_ip=source_ip(request))
    db.commit()
    return schemas.Token(access_token=create_access_token(user.username), provider=provider)


@router.post("/logout", response_model=schemas.Message)
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    write_auth_event(db, "logout", user=current_user, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="Logout")
    write_audit(db, "auth.logout", f"{current_user.username} logged out", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    return {"message": "Logged out"}


@router.get("/me", response_model=schemas.UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/oidc/login", response_model=schemas.Message)
def oidc_login():
    return {"message": "oidc login", "detail": {"url": oidc_login_url()}}


@router.get("/oidc/callback", response_model=schemas.Token)
def oidc_callback(request: Request, db: Session = Depends(get_db)):
    claims = {
        "sub": request.query_params.get("sub") or "mock-oidc-user",
        settings.pam_oidc_username_claim: request.query_params.get("username") or "oidc_user",
        settings.pam_oidc_email_claim: request.query_params.get("email") or "oidc_user@example.local",
        settings.pam_oidc_role_claim: [request.query_params.get("role") or settings.pam_oidc_user_role],
        "name": request.query_params.get("name") or "Mock OIDC User",
    }
    user = authenticate_oidc_callback(db, claims)
    write_auth_event(db, "oidc_login", user=user, provider="oidc", success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="OIDC callback accepted")
    db.commit()
    return schemas.Token(access_token=create_access_token(user.username), provider="oidc")


@router.post("/oidc/logout", response_model=schemas.Message)
def oidc_logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    write_auth_event(db, "logout", user=current_user, provider="oidc", success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="OIDC logout")
    db.commit()
    return {"message": "OIDC logout completed"}

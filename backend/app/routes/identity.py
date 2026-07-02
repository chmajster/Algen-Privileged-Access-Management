from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.identity.ldap_provider import authenticate_ldap
from app.identity.providers import provider_status
from app.mfa.challenge import write_auth_event
from app.models import AuthEvent, User, UserGroup, UserIdentity, utcnow


router = APIRouter(prefix="/api/identity", tags=["identity"])


def _user_out(user: User) -> dict:
    return schemas.IdentityUserOut.model_validate(user).model_dump()


@router.get("/providers", response_model=list[schemas.ProviderOut])
def providers(_: User = Depends(get_current_user)):
    return provider_status()


@router.get("/me", response_model=schemas.IdentityUserOut)
def identity_me(current_user: User = Depends(get_current_user)):
    return _user_out(current_user)


@router.post("/sync/ldap", response_model=schemas.Message)
def sync_ldap(request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user, groups = authenticate_ldap(db, "ldap_user", "mock-sync")
    write_auth_event(db, "ldap_sync", user=current_user, provider="ldap", success=bool(user), source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message="LDAP sync completed", metadata={"synced_user": user.username if user else None, "groups": groups})
    db.commit()
    return {"message": "ldap sync completed", "detail": {"user": user.username if user else None, "groups": groups}}


@router.get("/users", response_model=list[schemas.IdentityUserOut])
def identity_users(_: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    return [_user_out(user) for user in db.query(User).order_by(User.username).all()]


@router.get("/users/{user_id}", response_model=schemas.IdentityUserOut)
def identity_user(user_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return _user_out(user)


@router.get("/users/{user_id}/groups", response_model=list[schemas.UserGroupOut])
def identity_user_groups(user_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    if not db.get(User, user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return [schemas.UserGroupOut.model_validate(item).model_dump() for item in db.query(UserGroup).filter(UserGroup.user_id == user_id).order_by(UserGroup.group_name).all()]


@router.get("/users/{user_id}/identities", response_model=list[schemas.UserIdentityOut])
def identity_user_identities(user_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    if not db.get(User, user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return [schemas.UserIdentityOut.model_validate(item).model_dump() for item in db.query(UserIdentity).filter(UserIdentity.user_id == user_id).order_by(UserIdentity.provider).all()]


@router.post("/users/{user_id}/resync", response_model=schemas.IdentityUserOut)
def identity_resync(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.last_identity_sync_at = utcnow()
    write_auth_event(db, "ldap_sync" if user.auth_provider == "ldap" else "oidc_login" if user.auth_provider == "oidc" else "identity_sync", user=current_user, provider=user.auth_provider, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message=f"Identity resync for {user.username}")
    db.commit()
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/lock", response_model=schemas.IdentityUserOut)
def identity_lock(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    from datetime import timedelta

    user.locked_until = utcnow() + timedelta(days=365)
    user.disabled_reason = "Locked by admin"
    write_auth_event(db, "account_locked", user=user, provider=user.auth_provider, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message=f"Locked by {current_user.username}")
    db.commit()
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/unlock", response_model=schemas.IdentityUserOut)
def identity_unlock(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.locked_until = None
    user.failed_login_count = 0
    user.disabled_reason = None
    write_auth_event(db, "account_unlocked", user=user, provider=user.auth_provider, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message=f"Unlocked by {current_user.username}")
    db.commit()
    db.refresh(user)
    return _user_out(user)


@router.post("/users/{user_id}/reset-mfa", response_model=schemas.IdentityUserOut)
def identity_reset_mfa(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_enrolled_at = None
    user.mfa_last_used_at = None
    write_auth_event(db, "mfa_disabled", user=user, provider=user.auth_provider, success=True, source_ip=source_ip(request), user_agent=request.headers.get("user-agent"), message=f"MFA reset by {current_user.username}")
    db.commit()
    db.refresh(user)
    return _user_out(user)


@router.get("/auth-events", response_model=list[schemas.AuthEventOut])
def auth_events(
    user_id: int | None = None,
    provider: str | None = None,
    event_type: str | None = None,
    success: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    _: User = Depends(require_roles("admin")),
    db: DBSession = Depends(get_db),
):
    query = db.query(AuthEvent)
    if user_id:
        query = query.filter(AuthEvent.user_id == user_id)
    if provider:
        query = query.filter(AuthEvent.provider == provider)
    if event_type:
        query = query.filter(AuthEvent.event_type == event_type)
    if success is not None:
        query = query.filter(AuthEvent.success.is_(success))
    if date_from:
        query = query.filter(AuthEvent.created_at >= datetime.fromisoformat(date_from.replace("Z", "+00:00")))
    if date_to:
        query = query.filter(AuthEvent.created_at <= datetime.fromisoformat(date_to.replace("Z", "+00:00")))
    result = []
    for item in query.order_by(AuthEvent.created_at.desc()).limit(1000).all():
        data = schemas.AuthEventOut.model_validate(item).model_dump()
        data["username"] = item.user.username if item.user else None
        result.append(data)
    return result

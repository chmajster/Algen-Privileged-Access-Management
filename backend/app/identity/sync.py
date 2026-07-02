import json

from sqlalchemy.orm import Session as DBSession

from app.models import User, UserGroup, UserIdentity, utcnow
from app.security import hash_password


def upsert_external_user(db: DBSession, *, provider: str, external_id: str, username: str, email: str | None, display_name: str | None, role: str, groups: list[dict] | None = None, claims: dict | None = None) -> User:
    identity = db.query(UserIdentity).filter(UserIdentity.provider == provider, UserIdentity.external_id == external_id).first()
    user = identity.user if identity else db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            email=email or f"{username}@example.local",
            password_hash=hash_password(f"external-{provider}-disabled"),
            role=role,
            is_active=True,
            auth_provider=provider,
            external_id=external_id,
            display_name=display_name,
            email_verified=bool(email),
        )
        db.add(user)
        db.flush()
    user.role = role
    user.email = email or user.email
    user.display_name = display_name or user.display_name
    user.auth_provider = provider
    user.external_id = external_id
    user.email_verified = bool(email)
    user.last_identity_sync_at = utcnow()
    if not identity:
        identity = UserIdentity(user_id=user.id, provider=provider, external_id=external_id, username=username)
        db.add(identity)
    identity.username = username
    identity.email = email
    identity.display_name = display_name
    identity.raw_claims_json = json.dumps(claims or {}, ensure_ascii=False)
    identity.last_login_at = utcnow()
    identity.last_sync_at = utcnow()
    db.query(UserGroup).filter(UserGroup.user_id == user.id, UserGroup.provider == provider).delete()
    for group in groups or []:
        db.add(UserGroup(user_id=user.id, provider=provider, group_name=group.get("name", ""), group_dn=group.get("dn"), source=group.get("source", provider)))
    db.flush()
    return user

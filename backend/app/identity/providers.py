from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.identity.ldap_provider import authenticate_ldap
from app.identity.local_provider import authenticate_local


def enabled_providers() -> list[str]:
    return [item.strip() for item in settings.pam_auth_providers.split(",") if item.strip()]


def provider_status() -> list[dict]:
    return [
        {"name": "local", "enabled": "local" in enabled_providers(), "default": settings.pam_default_auth_provider == "local"},
        {"name": "ldap", "enabled": settings.pam_ldap_enabled or "ldap" in enabled_providers(), "default": settings.pam_default_auth_provider == "ldap"},
        {"name": "oidc", "enabled": settings.pam_oidc_enabled or "oidc" in enabled_providers(), "default": settings.pam_default_auth_provider == "oidc"},
    ]


def authenticate_with_provider(db: DBSession, provider: str, username: str, password: str):
    provider = provider or settings.pam_default_auth_provider
    if provider == "ldap":
        return authenticate_ldap(db, username, password)
    if provider == "local":
        return authenticate_local(db, username, password)
    return None, []

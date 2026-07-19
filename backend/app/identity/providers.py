from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.identity.ldap_provider import authenticate_ldap
from app.identity.local_provider import authenticate_local, authenticate_local_database, authenticate_local_os


def enabled_providers() -> list[str]:
    providers = [item.strip() for item in settings.pam_auth_providers.split(",") if item.strip()]
    if "local" in providers:
        providers.extend(["local_os", "local_db"])
    return list(dict.fromkeys(providers))


def default_provider() -> str:
    if settings.pam_default_auth_provider != "local":
        return settings.pam_default_auth_provider
    return "local_db" if settings.pam_local_auth_mode == "database" else "local_os"


def provider_status() -> list[dict]:
    return [
        {"name": "local_os", "enabled": "local_os" in enabled_providers(), "default": default_provider() == "local_os"},
        {"name": "local_db", "enabled": "local_db" in enabled_providers(), "default": default_provider() == "local_db"},
        {"name": "ldap", "enabled": settings.pam_ldap_enabled or "ldap" in enabled_providers(), "default": settings.pam_default_auth_provider == "ldap"},
        {"name": "oidc", "enabled": settings.pam_oidc_enabled or "oidc" in enabled_providers(), "default": settings.pam_default_auth_provider == "oidc"},
    ]


def authenticate_with_provider(db: DBSession, provider: str, username: str, password: str):
    provider = provider or settings.pam_default_auth_provider
    if provider in {"local_os", "passwd"}:
        return authenticate_local_os(db, username, password)
    if provider in {"local_db", "database"}:
        return authenticate_local_database(db, username, password)
    if provider == "ldap":
        return authenticate_ldap(db, username, password)
    if provider == "local":
        return authenticate_local(db, username, password)
    return None, []

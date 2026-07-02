from app.config import settings
from app.identity.role_mapper import role_from_oidc_claims
from app.identity.sync import upsert_external_user


def oidc_login_url() -> str:
    if settings.pam_oidc_enabled and settings.pam_oidc_issuer_url:
        return f"{settings.pam_oidc_issuer_url.rstrip('/')}/protocol/openid-connect/auth?client_id={settings.pam_oidc_client_id}&response_type=code&redirect_uri={settings.pam_oidc_redirect_uri}"
    return "/api/auth/oidc/callback?mock=1"


def authenticate_oidc_callback(db, claims: dict):
    username = claims.get(settings.pam_oidc_username_claim) or claims.get("sub") or "oidc_user"
    email = claims.get(settings.pam_oidc_email_claim) or f"{username}@example.local"
    role = role_from_oidc_claims(claims)
    roles = claims.get(settings.pam_oidc_role_claim, [])
    if isinstance(roles, str):
        roles = [roles]
    return upsert_external_user(
        db,
        provider="oidc",
        external_id=str(claims.get("sub") or username),
        username=username,
        email=email,
        display_name=claims.get("name") or username,
        role=role,
        groups=[{"name": role_name, "source": "oidc"} for role_name in roles],
        claims=claims,
    )

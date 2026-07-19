from app.config import settings


def role_from_ldap_groups(groups: list[str]) -> str:
    names = set(groups or [])
    if settings.pam_ldap_role_admin_group in names:
        return "admin"
    if settings.pam_ldap_role_approver_group in names:
        return "operator"
    if settings.pam_ldap_role_user_group in names:
        return "user"
    return "user"


def role_from_oidc_claims(claims: dict) -> str:
    roles = claims.get(settings.pam_oidc_role_claim) or []
    if isinstance(roles, str):
        roles = [roles]
    names = set(roles)
    if settings.pam_oidc_admin_role in names:
        return "admin"
    if settings.pam_oidc_approver_role in names:
        return "operator"
    if settings.pam_oidc_user_role in names:
        return "user"
    return "user"

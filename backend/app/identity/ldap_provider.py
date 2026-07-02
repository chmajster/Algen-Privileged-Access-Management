from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.identity.role_mapper import role_from_ldap_groups
from app.identity.sync import upsert_external_user


def authenticate_ldap(db: DBSession, username: str, password: str):
    if settings.pam_ldap_enabled:
        try:
            from ldap3 import ALL, Connection, Server

            server = Server(settings.pam_ldap_url, get_info=ALL, use_ssl=settings.pam_ldap_use_tls)
            user_dn = settings.pam_ldap_user_filter.format(username=username).strip("()")
            conn = Connection(server, user=f"{username}", password=password, auto_bind=True)
            conn.search(settings.pam_ldap_base_dn, settings.pam_ldap_user_filter.format(username=username), attributes=["cn", "mail", "memberOf", "distinguishedName"])
            if not conn.entries:
                return None, []
            entry = conn.entries[0]
            groups = [str(item).split(",")[0].replace("CN=", "") for item in getattr(entry, "memberOf", [])]
            role = role_from_ldap_groups(groups)
            return upsert_external_user(
                db,
                provider="ldap",
                external_id=str(getattr(entry, "distinguishedName", user_dn)),
                username=username,
                email=str(getattr(entry, "mail", "")) or None,
                display_name=str(getattr(entry, "cn", username)),
                role=role,
                groups=[{"name": group, "source": "ldap"} for group in groups],
                claims={"groups": groups},
            ), groups
        except Exception:
            return None, []
    if username == "ldap_user" and password:
        groups = [settings.pam_ldap_role_user_group]
        return upsert_external_user(
            db,
            provider="ldap",
            external_id="mock-ldap-user",
            username="ldap_user",
            email="ldap_user@example.local",
            display_name="Mock LDAP User",
            role=role_from_ldap_groups(groups),
            groups=[{"name": group, "source": "mock"} for group in groups],
            claims={"mock": True, "groups": groups},
        ), groups
    return None, []

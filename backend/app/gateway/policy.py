import re
from dataclasses import dataclass

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import AccessGrant, Server, Session as PamSession, User, utcnow
from app.rbac import constraints_for_request, has_permission


GATEWAY_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,63}(?:\+[0-9]+)?$")


@dataclass
class GatewayLogin:
    gateway_username: str
    requested_server_id: int | None = None


def parse_gateway_username(value: str) -> GatewayLogin:
    if not GATEWAY_USERNAME_RE.match(value or ""):
        raise ValueError("Invalid gateway username")
    if "+" not in value:
        return GatewayLogin(gateway_username=value)
    username, server_id = value.rsplit("+", 1)
    return GatewayLogin(gateway_username=username, requested_server_id=int(server_id))


def gateway_enabled_for(server: Server) -> bool:
    return bool(settings.pam_gateway_enabled and server.enabled and server.gateway_enabled)


def active_gateway_grants(db: DBSession, user: User, requested_server_id: int | None = None) -> list[AccessGrant]:
    query = (
        db.query(AccessGrant)
        .join(Server, AccessGrant.server_id == Server.id)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.status == "active",
            AccessGrant.valid_to > utcnow(),
            AccessGrant.gateway_session_required.is_(True),
            Server.enabled.is_(True),
            Server.gateway_enabled.is_(True),
        )
    )
    if requested_server_id:
        query = query.filter(AccessGrant.server_id == requested_server_id)
    output = []
    for grant in query.order_by(AccessGrant.valid_to.asc()).all():
        if not has_permission(db, user, "access.connect", server_id=grant.server_id) or not has_permission(db, user, "access.connect_gateway", server_id=grant.server_id):
            continue
        constraints = constraints_for_request(db, user, grant.server_id)
        active_sessions = db.query(PamSession).filter(PamSession.user_id == user.id, PamSession.server_id == grant.server_id, PamSession.status == "active").count()
        if active_sessions >= constraints["max_active_sessions"]:
            continue
        output.append(grant)
    return output


def choose_gateway_grant(db: DBSession, user: User, requested_server_id: int | None = None) -> AccessGrant | None:
    grants = active_gateway_grants(db, user, requested_server_id)
    if requested_server_id:
        return grants[0] if grants else None
    return grants[0] if len(grants) == 1 else None

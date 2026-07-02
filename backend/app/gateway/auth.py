from sqlalchemy.orm import Session as DBSession

from app.models import Server, User
from app.policy.engine import PolicyEngine
from app.mfa.step_up import has_valid_step_up
from app.security import sanitize_linux_username

from .policy import GatewayLogin, choose_gateway_grant, parse_gateway_username
from .service import write_gateway_event


def normalize_public_key(public_key: str | None) -> str:
    if not public_key:
        return ""
    parts = public_key.strip().split()
    return " ".join(parts[:2]) if len(parts) >= 2 else public_key.strip()


def find_user_for_gateway_login(db: DBSession, raw_username: str, public_key: str | None = None, client_ip: str | None = None) -> tuple[User | None, GatewayLogin | None]:
    try:
        login = parse_gateway_username(raw_username)
    except ValueError:
        write_gateway_event(db, "gateway_login_denied", "Gateway login denied: invalid username", metadata={"client_ip": client_ip})
        return None, None

    key = normalize_public_key(public_key)
    users = db.query(User).filter(User.is_active.is_(True)).all()
    for user in users:
        names = {user.username, sanitize_linux_username(user.username)}
        if login.gateway_username not in names:
            continue
        if key and normalize_public_key(user.ssh_public_key) != key:
            continue
        write_gateway_event(db, "gateway_login_attempt", f"Gateway login attempt for {user.username}", metadata={"user_id": user.id, "client_ip": client_ip})
        return user, login
    write_gateway_event(db, "gateway_login_denied", "Gateway login denied: unknown user or key", metadata={"client_ip": client_ip})
    return None, login


def authorize_gateway_login(db: DBSession, raw_username: str, public_key: str | None = None, client_ip: str | None = None):
    user, login = find_user_for_gateway_login(db, raw_username, public_key, client_ip)
    if not user or not login:
        return None
    grant = choose_gateway_grant(db, user, login.requested_server_id)
    server = grant.server if grant else db.get(Server, login.requested_server_id) if login.requested_server_id else None
    decision = PolicyEngine(db).evaluate_gateway_login(user, server, grant)
    if not grant:
        write_gateway_event(db, "gateway_policy_denied", "Gateway denied: no active gateway grant", metadata={"user_id": user.id, "client_ip": client_ip})
        PolicyEngine(db).record_risk_event(decision, "gateway_login_denied", decision.message, user_id=user.id, server_id=server.id if server else None, alert_type="gateway")
        return None
    if decision.denied:
        write_gateway_event(db, "gateway_policy_denied", decision.message, grant=grant, metadata={"user_id": user.id, "client_ip": client_ip})
        PolicyEngine(db).record_risk_event(decision, "gateway_login_denied", decision.message, user_id=user.id, server_id=grant.server_id, grant_id=grant.id, alert_type="gateway")
        return None
    if decision.requires_mfa and (not user.mfa_enabled or not has_valid_step_up(db, user, decision.mfa_context or "gateway_login")):
        message = "MFA step-up required. Open PAM Lite panel and verify MFA for gateway access."
        write_gateway_event(db, "gateway_mfa_required", message, grant=grant, metadata={"user_id": user.id, "client_ip": client_ip})
        PolicyEngine(db).record_risk_event(decision, "gateway_login_denied", message, user_id=user.id, server_id=grant.server_id, grant_id=grant.id, alert_type="gateway")
        return None
    write_gateway_event(db, "gateway_login_success", f"Gateway login authorized for {user.username}", grant=grant, metadata={"client_ip": client_ip})
    PolicyEngine(db).record_risk_event(decision, "gateway_login_success", f"Gateway login authorized for {user.username}", user_id=user.id, server_id=grant.server_id, grant_id=grant.id, alert_type="gateway")
    return grant

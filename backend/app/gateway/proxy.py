from app.models import AccessGrant, Server
from app.database import SessionLocal
from app.models import Secret
from app.vault import get_vault_backend_for_secret
from sqlalchemy.orm import object_session
from .service import write_gateway_event


def target_connection_settings(grant: AccessGrant) -> dict:
    server: Server = grant.server
    if getattr(server, "registration_status", "approved") != "approved" or not server.enabled:
        raise RuntimeError("Server is not approved for gateway access")
    key_path = server.gateway_private_key_path or server.ssh_private_key_path
    secret_id = server.gateway_secret_ref_id or server.ssh_auth_secret_id
    if secret_id:
        db = object_session(grant) or object_session(server) or SessionLocal()
        owns_session = object_session(grant) is None and object_session(server) is None
        try:
            secret = db.get(Secret, secret_id)
            if not secret:
                raise RuntimeError("Configured gateway secret not found")
            get_vault_backend_for_secret(db, secret).get_secret_value(secret_id, {"server_id": server.id, "grant_id": grant.id, "access_context": "gateway_target_key"})
            if owns_session:
                db.commit()
        finally:
            if owns_session:
                db.close()
        key_path = f"vault://secret/{secret_id}"
    return {
        "host": server.ip_address,
        "port": server.ssh_port,
        "username": server.gateway_target_user or server.ssh_admin_user or "root",
        "key_path": key_path,
    }


async def proxy_terminal(*_args, **_kwargs) -> None:
    raise NotImplementedError("Live SSH proxy requires asyncssh runtime integration")


def record_target_connect_failed(db, grant: AccessGrant, error: str):
    return write_gateway_event(
        db,
        "gateway_target_connect_failed",
        "Gateway target SSH connection failed",
        grant=grant,
        metadata={"error": error[:500]},
    )

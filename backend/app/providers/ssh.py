import asyncio
import base64
import hashlib
from io import StringIO
from typing import Any

import paramiko

from app.models import SSHConnectionProfile, Secret
from app.vault import get_vault_backend_for_secret

from .base import ProviderContext
from .events import add_event


class SSHAccessProvider:
    def __init__(self):
        self.clients: dict[int, paramiko.SSHClient] = {}

    def _profile(self, context: ProviderContext) -> SSHConnectionProfile:
        value = context.db.query(SSHConnectionProfile).filter_by(connection_profile_id=context.connection_profile.id).first()
        if not value: raise ValueError("SSH connection profile is missing")
        return value

    async def validate_configuration(self, context: ProviderContext) -> None:
        profile = self._profile(context)
        if not profile.hostname or not 1 <= profile.port <= 65535: raise ValueError("Invalid SSH target")
        if profile.auth_mode not in {"password", "private_key", "agent"}: raise ValueError("Unsupported SSH authentication mode")
        if profile.auth_mode != "agent" and not profile.secret_id: raise ValueError("SSH secret is required")

    def _connect(self, context: ProviderContext) -> paramiko.SSHClient:
        profile = self._profile(context)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if profile.host_key_policy == "trust_on_first_use": client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else: client.set_missing_host_key_policy(paramiko.RejectPolicy())
        kwargs: dict[str, Any] = {"hostname": profile.hostname, "port": profile.port, "username": profile.username, "timeout": 10}
        if profile.secret_id:
            secret = context.db.get(Secret, profile.secret_id)
            if not secret:
                raise ValueError("SSH secret does not exist")
            value = get_vault_backend_for_secret(context.db, secret).get_secret_value(secret.id, {"resource_id": context.resource.id, "grant_id": context.grant.id if context.grant else None, "session_id": context.session.id if context.session else None, "access_context": "ssh_provider"})
            if profile.auth_mode == "password": kwargs["password"] = value
            else:
                for key_type in (paramiko.Ed25519Key,paramiko.RSAKey,paramiko.ECDSAKey):
                    try: kwargs["pkey"] = key_type.from_private_key(StringIO(value)); break
                    except (paramiko.SSHException,ValueError): continue
                if "pkey" not in kwargs: raise ValueError("Unsupported or invalid SSH private key")
        client.connect(**kwargs)
        remote=client.get_transport().get_remote_server_key()
        fingerprint="SHA256:"+base64.b64encode(hashlib.sha256(remote.asbytes()).digest()).decode().rstrip("=")
        if profile.expected_host_key_fingerprint and profile.expected_host_key_fingerprint.lower()!=fingerprint.lower():
            client.close(); raise ValueError("SSH host key fingerprint mismatch")
        return client

    async def test_connection(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        client = await asyncio.to_thread(self._connect, context); client.close()
        return {"ok": True, "protocol": "ssh"}

    async def launch_session(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        if not context.session:
            raise ValueError("Session context is required")
        client = await asyncio.to_thread(self._connect, context)
        self.clients[context.session.id] = client
        add_event(context.db, context.session, "session_started", "ssh", {"hostname": self._profile(context).hostname})
        return {"protocol": "ssh", "stream_url": f"/api/ssh-sessions/{context.session.id}/stream"}

    async def terminate_session(self, context: ProviderContext, reason: str) -> None:
        if not context.session:
            return
        client = self.clients.pop(context.session.id, None)
        if client: await asyncio.to_thread(client.close)
        add_event(context.db, context.session, "session_finished", "ssh", {"reason": reason})

    async def collect_events(self, context: ProviderContext) -> list[dict[str, Any]]: return []
    async def cleanup_session(self, context: ProviderContext) -> None: await self.terminate_session(context, "cleanup")


ssh_provider = SSHAccessProvider()

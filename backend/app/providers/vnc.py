import asyncio
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.models import Secret, VncConnectionProfile
from app.vault import get_vault_backend_for_secret

from .base import ProviderContext
from .events import add_event


def _reverse_bits(byte: int) -> int:
    return int(f"{byte:08b}"[::-1], 2)


def _vnc_response(password: str, challenge: bytes) -> bytes:
    raw = password.encode("latin-1", "ignore")[:8].ljust(8, b"\0")
    key = bytes(_reverse_bits(item) for item in raw)
    encryptor = Cipher(algorithms.TripleDES(key * 3), modes.ECB()).encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


@dataclass
class VncRuntime:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    version: bytes


class VNCProvider:
    """Server-side RFB 3.8 authenticator and WebSocket relay; target ports stay private."""

    def __init__(self):
        self.runtimes: dict[int, VncRuntime] = {}

    def profile(self, context: ProviderContext) -> VncConnectionProfile:
        value = context.db.query(VncConnectionProfile).filter_by(server_id=context.resource.id).first()
        if not value:
            raise ValueError("VNC connection profile is missing")
        return value

    async def validate_configuration(self, context: ProviderContext) -> None:
        profile = self.profile(context)
        if not profile.hostname or not 1 <= profile.port <= 65535:
            raise ValueError("Invalid VNC target")

    async def _connect(self, context: ProviderContext) -> VncRuntime:
        profile = self.profile(context)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(profile.hostname, profile.port), 10)
        version = await asyncio.wait_for(reader.readexactly(12), 5)
        if not version.startswith(b"RFB 003.008"):
            writer.close()
            raise ValueError("Only RFB 3.8 is supported")
        writer.write(version)
        await writer.drain()
        count = (await reader.readexactly(1))[0]
        security_types = await reader.readexactly(count)
        selected = 2 if 2 in security_types else 1 if 1 in security_types else 0
        if not selected:
            writer.close()
            raise ValueError("VNC server offers no supported security type")
        if selected == 1 and profile.secret_id:
            writer.close()
            raise ValueError("VNC target unexpectedly permits unauthenticated access")
        writer.write(bytes([selected]))
        await writer.drain()
        if selected == 2:
            if not profile.secret_id:
                writer.close()
                raise ValueError("VNC password secret is required")
            secret = context.db.get(Secret, profile.secret_id)
            if not secret:
                writer.close()
                raise ValueError("VNC secret does not exist")
            password = get_vault_backend_for_secret(context.db, secret).get_secret_value(secret.id, {"session_id": context.session.id if context.session else None, "access_context": "vnc_worker"})
            challenge = await reader.readexactly(16)
            writer.write(_vnc_response(password, challenge))
            await writer.drain()
        result = int.from_bytes(await reader.readexactly(4), "big")
        if result:
            writer.close()
            raise ValueError("VNC authentication failed")
        return VncRuntime(reader, writer, version)

    async def test_connection(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        runtime = await self._connect(context)
        runtime.writer.close()
        await runtime.writer.wait_closed()
        return {"ok": True, "protocol": "vnc"}

    async def launch_session(self, context: ProviderContext) -> dict[str, Any]:
        if not context.session:
            raise ValueError("Session context is required")
        await self.validate_configuration(context)
        self.runtimes[context.session.id] = await self._connect(context)
        add_event(context.db, context.session, "session_started", "vnc", {})
        return {"protocol": "vnc", "stream_url": f"/api/vnc-sessions/{context.session.id}/stream"}

    async def handle_input(self, context: ProviderContext, event: dict[str, Any]) -> dict[str, Any]:
        raise ValueError("VNC uses its binary WebSocket stream")

    async def terminate_session(self, context: ProviderContext, reason: str) -> None:
        if not context.session:
            return
        runtime = self.runtimes.pop(context.session.id, None)
        if runtime:
            runtime.writer.close()
            await runtime.writer.wait_closed()
        add_event(context.db, context.session, "session_finished", "vnc", {"reason": reason})

    async def cleanup_session(self, context: ProviderContext) -> None:
        await self.terminate_session(context, "cleanup")


vnc_provider = VNCProvider()

import asyncio
import socket
from typing import Any

from .base import ProviderContext
from .events import add_event


class SSHAccessProvider:
    """Adapter around the existing SSH gateway/session implementation."""

    async def validate_configuration(self, context: ProviderContext) -> None:
        if not context.resource.hostname or not 1 <= context.resource.ssh_port <= 65535:
            raise ValueError("Invalid SSH target")

    async def test_connection(self, context: ProviderContext) -> dict[str, Any]:
        await self.validate_configuration(context)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(context.resource.ip_address, context.resource.ssh_port), 10)
        banner = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
        await writer.wait_closed()
        return {"ok": banner.startswith(b"SSH-"), "protocol": "ssh"}

    async def launch_session(self, context: ProviderContext) -> dict[str, Any]:
        if not context.session:
            raise ValueError("Session context is required")
        add_event(context.db, context.session, "session_started", "ssh", {"host": context.resource.hostname})
        return {"protocol": "ssh", "transport": "existing_gateway"}

    async def handle_input(self, context: ProviderContext, event: dict[str, Any]) -> dict[str, Any]:
        raise ValueError("SSH input is handled by the existing gateway")

    async def terminate_session(self, context: ProviderContext, reason: str) -> None:
        if context.session:
            add_event(context.db, context.session, "session_finished", "ssh", {"reason": reason})

    async def cleanup_session(self, context: ProviderContext) -> None:
        await self.terminate_session(context, "cleanup")


ssh_provider = SSHAccessProvider()

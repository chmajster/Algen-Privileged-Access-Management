from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.orm import Session as DBSession

from app.models import AccessGrant, Server, Session


@dataclass
class ProviderContext:
    db: DBSession
    resource: Server
    grant: AccessGrant | None = None
    session: Session | None = None


class AccessProvider(Protocol):
    async def validate_configuration(self, context: ProviderContext) -> None: ...
    async def test_connection(self, context: ProviderContext) -> dict[str, Any]: ...
    async def launch_session(self, context: ProviderContext) -> dict[str, Any]: ...
    async def handle_input(self, context: ProviderContext, event: dict[str, Any]) -> dict[str, Any]: ...
    async def terminate_session(self, context: ProviderContext, reason: str) -> None: ...
    async def cleanup_session(self, context: ProviderContext) -> None: ...

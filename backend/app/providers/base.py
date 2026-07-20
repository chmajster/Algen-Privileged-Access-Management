from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.orm import Session as DBSession

from app.models import AccessGrant, ConnectionProfile, PamSession, Resource


@dataclass
class ProviderContext:
    db: DBSession
    resource: Resource
    connection_profile: ConnectionProfile
    grant: AccessGrant | None = None
    session: PamSession | None = None


class AccessProvider(Protocol):
    async def validate_configuration(self, context: ProviderContext) -> None: ...
    async def test_connection(self, context: ProviderContext) -> dict[str, Any]: ...
    async def launch_session(self, context: ProviderContext) -> dict[str, Any]: ...
    async def terminate_session(self, context: ProviderContext, reason: str) -> None: ...
    async def collect_events(self, context: ProviderContext) -> list[dict[str, Any]]: ...
    async def cleanup_session(self, context: ProviderContext) -> None: ...

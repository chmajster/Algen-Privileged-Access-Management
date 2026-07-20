from .base import AccessProvider
from .ssh import ssh_provider
from .web import web_provider


def provider_for(resource_type: str) -> AccessProvider:
    providers: dict[str, AccessProvider] = {"ssh": ssh_provider, "web": web_provider}
    try: return providers[resource_type]
    except KeyError as exc: raise ValueError(f"No access provider for resource type: {resource_type}") from exc

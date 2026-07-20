from .base import AccessProvider
from .ssh import ssh_provider
from .vnc import vnc_provider
from .web import web_provider


PROVIDERS: dict[str, AccessProvider] = {"ssh": ssh_provider, "web": web_provider, "vnc": vnc_provider}


def provider_for(protocol: str) -> AccessProvider:
    try:
        return PROVIDERS[protocol.lower()]
    except KeyError as exc:
        raise ValueError(f"No access provider for protocol: {protocol}") from exc

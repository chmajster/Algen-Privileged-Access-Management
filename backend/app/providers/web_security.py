import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class UnsafeNavigation(ValueError):
    pass


BLOCKED_SCHEMES = {"file", "data", "javascript", "chrome", "chrome-extension", "about", "ftp"}
METADATA_ADDRESSES = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}


def normalize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme in BLOCKED_SCHEMES or scheme not in {"http", "https"}:
        raise UnsafeNavigation(f"URL scheme is not allowed: {scheme or 'missing'}")
    if parsed.username or parsed.password:
        raise UnsafeNavigation("Credentials in URLs are not allowed")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeNavigation("Destination hostname is required")
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise UnsafeNavigation("Invalid destination hostname") from exc
    port = parsed.port
    netloc = f"[{host}]" if ":" in host else host
    if port and port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


class NavigationGuard:
    def __init__(self, allowed_domains: list[str], allow_private_network: bool = False, blocked_domains: list[str] | None = None):
        self.allowed_domains = tuple(item.strip().lower().rstrip(".") for item in allowed_domains if item.strip())
        self.blocked_domains = tuple(item.strip().lower().rstrip(".") for item in (blocked_domains or []) if item.strip())
        self.allow_private_network = allow_private_network
        self.resolutions: dict[str, frozenset[str]] = {}

    def _domain_allowed(self, host: str) -> bool:
        if any(host == item or host.endswith("." + item) for item in self.blocked_domains):
            return False
        return not self.allowed_domains or any(host == item or host.endswith("." + item) for item in self.allowed_domains)

    async def resolve(self, host: str, port: int) -> set[str]:
        try:
            return {str(ipaddress.ip_address(host))}
        except ValueError:
            loop = asyncio.get_running_loop()
            rows = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            return {str(row[4][0]).split("%")[0] for row in rows}

    async def validate(self, url: str) -> tuple[str, set[str]]:
        normalized = normalize_url(url)
        parsed = urlsplit(normalized)
        host = parsed.hostname or ""
        if not self._domain_allowed(host):
            raise UnsafeNavigation("Destination domain is not allowed")
        addresses = await self.resolve(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        if not addresses:
            raise UnsafeNavigation("Destination did not resolve")
        canonical = set()
        for raw in addresses:
            address = ipaddress.ip_address(raw)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            canonical.add(str(address))
            if address in METADATA_ADDRESSES or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise UnsafeNavigation("Destination address is blocked")
            if address.is_private and not self.allow_private_network:
                raise UnsafeNavigation("Private network destinations are disabled")
        pinned = frozenset(canonical)
        previous = self.resolutions.get(host)
        if previous is not None and previous != pinned:
            raise UnsafeNavigation("DNS rebinding detected")
        self.resolutions[host] = pinned
        return normalized, canonical

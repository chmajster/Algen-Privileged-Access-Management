import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


BLOCKED_SCHEMES = {"file", "data", "javascript", "chrome", "about", "ftp"}
METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("192.0.0.192"), ipaddress.ip_address("fd00:ec2::254"),
}


class UnsafeNavigation(ValueError):
    pass


class NavigationGuard:
    def __init__(self, allowed_domains: list[str], allow_private_network: bool = False, blocked_domains: list[str] | None = None):
        self.allowed_domains = [item.lower().lstrip(".") for item in allowed_domains if item]
        self.blocked_domains = [item.lower().lstrip(".") for item in (blocked_domains or []) if item]
        self.allow_private_network = allow_private_network
        self.resolutions: dict[str, frozenset[str]] = {}

    def _domain_allowed(self, host: str) -> bool:
        if any(host == domain or host.endswith("." + domain) for domain in self.blocked_domains): return False
        return not self.allowed_domains or any(host == domain or host.endswith("." + domain) for domain in self.allowed_domains)

    async def validate(self, url: str) -> set[str]:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme in BLOCKED_SCHEMES or scheme not in {"http", "https"}:
            raise UnsafeNavigation(f"URL scheme is not allowed: {scheme or 'missing'}")
        if parsed.username or parsed.password:
            raise UnsafeNavigation("Credentials in URLs are not allowed")
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host or not self._domain_allowed(host):
            raise UnsafeNavigation("Destination domain is not allowed")
        try:
            literal = ipaddress.ip_address(host)
            addresses = {str(literal)}
        except ValueError:
            loop = asyncio.get_running_loop()
            info = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM))
            addresses = {str(item[4][0]).split("%")[0] for item in info}
        if not addresses:
            raise UnsafeNavigation("Destination did not resolve")
        for raw in addresses:
            address = ipaddress.ip_address(raw)
            if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:
                address=address.ipv4_mapped
            if address in METADATA_ADDRESSES or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise UnsafeNavigation("Destination address is blocked")
            if address.is_private and not self.allow_private_network:
                raise UnsafeNavigation("Private network destinations are disabled")
        resolved = frozenset(addresses)
        previous = self.resolutions.get(host)
        if previous is not None and previous != resolved:
            raise UnsafeNavigation("DNS rebinding detected")
        self.resolutions[host] = resolved
        return addresses

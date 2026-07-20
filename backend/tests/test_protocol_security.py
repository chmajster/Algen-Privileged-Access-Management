import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from app.providers.events import sanitize_metadata
from app.providers.registry import provider_for
from app.providers.web_security import NavigationGuard, UnsafeNavigation, normalize_url


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "data:text/html,x", "javascript:alert(1)",
    "chrome://settings", "about:blank", "ftp://example.com/a",
    "https://user:pass@example.com/",
])
def test_forbidden_url_schemes_and_credentials(url):
    with pytest.raises(UnsafeNavigation):
        normalize_url(url)


def test_loopback_and_private_network_are_blocked():
    async def scenario():
        guard = NavigationGuard([])
        with pytest.raises(UnsafeNavigation): await guard.validate("http://127.0.0.1/")
        with pytest.raises(UnsafeNavigation): await guard.validate("http://10.0.0.2/")
        allowed = NavigationGuard([], allow_private_network=True)
        _, addresses = await allowed.validate("http://10.0.0.2/")
        assert addresses == {"10.0.0.2"}
    asyncio.run(scenario())


def test_domain_rules_are_label_aware():
    async def scenario():
        guard = NavigationGuard(["example.com"])
        guard.resolve = AsyncMock(return_value={"93.184.216.34"})
        await guard.validate("https://app.example.com/path")
        with pytest.raises(UnsafeNavigation): await guard.validate("https://example.com.attacker.test/")
    asyncio.run(scenario())


def test_dns_rebinding_is_rejected():
    async def scenario():
        guard = NavigationGuard(["example.com"])
        guard.resolve = AsyncMock(side_effect=[{"93.184.216.34"}, {"93.184.216.35"}])
        await guard.validate("https://example.com/")
        with pytest.raises(UnsafeNavigation): await guard.validate("https://example.com/next")
    asyncio.run(scenario())


def test_event_metadata_never_discloses_credentials():
    original = {"password": "p", "nested": {"Authorization": "Bearer x", "cookie": "sid=x", "selector": "#password", "value_changed": True}}
    serialized = json.dumps(sanitize_metadata(original))
    assert "Bearer x" not in serialized and "sid=x" not in serialized and '"p"' not in serialized
    assert "#password" in serialized and "value_changed" in serialized


def test_provider_registry_is_extensible_and_supports_required_protocols():
    assert provider_for("ssh")
    assert provider_for("web")
    assert provider_for("vnc")
    with pytest.raises(ValueError): provider_for("rdp")

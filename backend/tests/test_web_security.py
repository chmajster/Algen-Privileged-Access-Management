import asyncio
import json
import socket

import pytest

from app.database import SessionLocal
from app.models import PamSession, User
from app.providers.events import add_event
from app.providers.web_security import NavigationGuard, UnsafeNavigation


@pytest.mark.parametrize("url",["file:///etc/passwd","data:text/plain,x","javascript:alert(1)","chrome://settings","about:blank","ftp://example.com/x"])
def test_blocked_schemes(url):
    with pytest.raises(UnsafeNavigation): asyncio.run(NavigationGuard(["example.com"]).validate(url))


def test_ssrf_blocks_loopback_and_metadata():
    with pytest.raises(UnsafeNavigation): asyncio.run(NavigationGuard([],allow_private_network=True).validate("http://127.0.0.1"))
    with pytest.raises(UnsafeNavigation): asyncio.run(NavigationGuard([],allow_private_network=True).validate("http://169.254.169.254"))


def test_allowed_domain_enforcement():
    with pytest.raises(UnsafeNavigation): asyncio.run(NavigationGuard(["example.com"]).validate("https://example.net"))


def test_dns_rebinding_is_rejected(monkeypatch):
    answers=iter([[(socket.AF_INET,socket.SOCK_STREAM,6,"",("93.184.216.34",443))],[(socket.AF_INET,socket.SOCK_STREAM,6,"",("93.184.216.35",443))]])
    monkeypatch.setattr(socket,"getaddrinfo",lambda *a,**k:next(answers))
    guard=NavigationGuard(["example.com"]); asyncio.run(guard.validate("https://example.com"))
    with pytest.raises(UnsafeNavigation,match="rebinding"): asyncio.run(guard.validate("https://example.com/path"))


def test_sensitive_form_values_are_redacted(client):
    with SessionLocal() as db:
        user=db.query(User).first(); session=PamSession(user_id=user.id,resource_id=1,grant_id=1,protocol="web",status="active"); db.add(session)
        # Use a transient object to test the normalizer without committing invalid FKs.
        db.flush(); event=add_event(db,session,"form_submit","web",{"password":"never-store","value":"secret","selector":"#password"},True)
        data=json.loads(event.metadata_json); assert data["password"]=="[REDACTED]" and data["value"]=="[REDACTED]" and data["selector"]=="#password"

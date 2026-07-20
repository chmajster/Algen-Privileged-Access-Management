from datetime import timedelta
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

from app.database import SessionLocal
from app.models import AccessGrant, PamSession, SessionArtifact, StepUpSession, User, utcnow
from app.providers.registry import provider_for
from app.providers.ssh import SSHAccessProvider, ssh_provider
from app.providers.web import WebAccessProvider, web_provider
from app.lifecycle import enforce_lifecycle_once
from tests.conftest import auth_headers


def create_grant(client,headers,resource_name="Demo Web"):
    resource=next(x for x in client.get("/api/resources",headers=headers).json() if x["name"]==resource_name)
    profile=next(x for x in client.get("/api/access-profiles",headers=headers).json() if x["resource_type"]==resource["resource_type"])
    request=client.post("/api/access-requests",headers=headers,json={"resource_id":resource["id"],"access_profile_id":profile["id"],"reason":"automated lifecycle test","requested_duration_minutes":30})
    assert request.status_code==201,request.text
    grant=next(x for x in client.get("/api/access-grants",headers=headers).json() if x["resource_id"]==resource["id"])
    return resource,grant


def test_provider_dispatch():
    assert isinstance(provider_for("ssh"),SSHAccessProvider)
    assert isinstance(provider_for("web"),WebAccessProvider)


def test_resource_api_has_no_servers_compatibility(client):
    headers=auth_headers(client)
    assert client.get("/api/resources",headers=headers).status_code==200
    assert client.get("/api/servers",headers=headers).status_code==404


def test_request_grant_and_session_lifecycle(client,monkeypatch):
    headers=auth_headers(client); _,grant=create_grant(client,headers)
    created=client.post("/api/sessions",headers=headers,json={"grant_id":grant["id"]})
    assert created.status_code==201
    launch=AsyncMock(return_value={"protocol":"web","stream_url":"/api/web-sessions/1/stream"})
    stop=AsyncMock()
    monkeypatch.setattr(web_provider,"launch_session",launch); monkeypatch.setattr(web_provider,"terminate_session",stop)
    result=client.post(f"/api/sessions/{created.json()['id']}/launch",headers=headers)
    assert result.status_code==200,result.text
    ended=client.post(f"/api/sessions/{created.json()['id']}/terminate",headers=headers,json={"reason":"test complete"})
    assert ended.json()["status"]=="terminated"; stop.assert_awaited_once()


def test_ssh_access_lifecycle(client,monkeypatch):
    headers=auth_headers(client); _,grant=create_grant(client,headers,"Demo SSH")
    launch=AsyncMock(return_value={"protocol":"ssh","stream_url":"/api/ssh-sessions/1/stream"}); stop=AsyncMock()
    monkeypatch.setattr(ssh_provider,"launch_session",launch); monkeypatch.setattr(ssh_provider,"terminate_session",stop)
    created=client.post("/api/sessions",headers=headers,json={"grant_id":grant["id"]}).json()
    assert client.post(f"/api/sessions/{created['id']}/launch",headers=headers).status_code==200
    assert client.post(f"/api/sessions/{created['id']}/terminate",headers=headers,json={"reason":"done"}).status_code==200
    launch.assert_awaited_once(); stop.assert_awaited_once()


def test_grant_revocation_terminates_session(client,monkeypatch):
    headers=auth_headers(client); _,grant=create_grant(client,headers); stop=AsyncMock(); monkeypatch.setattr(web_provider,"terminate_session",stop)
    with SessionLocal() as db:
        session=PamSession(user_id=grant["user_id"],resource_id=grant["resource_id"],grant_id=grant["id"],protocol="web",status="active",started_at=utcnow(),last_heartbeat_at=utcnow()); db.add(session); db.commit(); sid=session.id
    response=client.post(f"/api/access-grants/{grant['id']}/revoke",headers=headers,json={"reason":"security incident"})
    assert response.status_code==200
    with SessionLocal() as db: assert db.get(PamSession,sid).termination_reason=="security incident"


def test_grant_expiry_terminates_session(client,monkeypatch):
    headers=auth_headers(client); _,grant=create_grant(client,headers); stop=AsyncMock(); monkeypatch.setattr(web_provider,"terminate_session",stop)
    with SessionLocal() as db:
        row=db.get(AccessGrant,grant["id"]); row.valid_to=utcnow()-timedelta(seconds=1)
        session=PamSession(user_id=row.user_id,resource_id=row.resource_id,grant_id=row.id,protocol="web",status="active",started_at=utcnow(),last_heartbeat_at=utcnow()); db.add(session); db.commit(); sid=session.id
    asyncio.run(enforce_lifecycle_once())
    with SessionLocal() as db: assert db.get(PamSession,sid).termination_reason=="grant_expired"


def test_rbac_denies_user_recordings(client):
    admin=auth_headers(client); _,grant=create_grant(client,admin)
    with SessionLocal() as db:
        user=db.query(User).filter_by(username="user").one(); grant_row=db.get(AccessGrant,grant["id"]); grant_row.user_id=user.id
        session=PamSession(user_id=user.id,resource_id=grant_row.resource_id,grant_id=grant_row.id,protocol="web",status="terminated"); db.add(session); db.flush()
        db.add(SessionArtifact(session_id=session.id,artifact_type="video",storage_path="outside-public.webm",sha256="0"*64,size_bytes=0,mime_type="video/webm")); db.commit(); sid=session.id
    response=client.get(f"/api/sessions/{sid}/artifacts",headers=auth_headers(client,"user","user123"))
    assert response.status_code==403


def test_recording_requires_mfa_step_up_for_privileged_user(client):
    headers=auth_headers(client); _,grant=create_grant(client,headers)
    with SessionLocal() as db:
        admin=db.query(User).filter_by(username="admin").one(); admin.mfa_enabled=True
        session=PamSession(user_id=admin.id,resource_id=grant["resource_id"],grant_id=grant["id"],protocol="web",status="terminated"); db.add(session); db.flush()
        path=Path("test-artifacts")/"test-recording.webm"; path.parent.mkdir(exist_ok=True); path.write_bytes(b"video")
        artifact=SessionArtifact(session_id=session.id,artifact_type="video",storage_path=str(path),sha256="0"*64,size_bytes=5,mime_type="video/webm"); db.add(artifact); db.commit(); sid=session.id; aid=artifact.id
    denied=client.get(f"/api/sessions/{sid}/artifacts/{aid}/play",headers=headers)
    assert denied.status_code==403 and denied.json()["detail"]["code"]=="step_up_required"
    with SessionLocal() as db:
        admin=db.query(User).filter_by(username="admin").one(); db.add(StepUpSession(user_id=admin.id,context="recording_access",valid_until=utcnow()+timedelta(minutes=5))); db.commit()
    assert client.get(f"/api/sessions/{sid}/artifacts/{aid}/play",headers=headers).status_code==200

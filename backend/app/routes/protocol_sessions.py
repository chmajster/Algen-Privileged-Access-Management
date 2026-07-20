import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.auth import get_current_user, oauth2_scheme, source_ip
from app.config import settings
from app.database import SessionLocal, get_db
from app.mfa.step_up import require_step_up
from app.models import AccessGrant, Server, Session, SessionArtifact, SessionEvent, User, VncConnectionProfile, WebConnectionProfile, utcnow
from app.protocol_lifecycle import terminate_protocol_session
from app.providers.base import ProviderContext
from app.providers.registry import provider_for
from app.providers.web import web_provider
from app.providers.vnc import vnc_provider
from app.rbac import has_permission, is_global_admin, normalized_role, require_permission

router = APIRouter(prefix="/api", tags=["multi-protocol-sessions"])


class InputEvent(BaseModel):
    type: Literal["mouse", "key", "text", "wheel"]
    action: str | None = Field(default=None, max_length=16)
    key: str | None = Field(default=None, max_length=64)
    text: str | None = Field(default=None, max_length=4096)
    selector: str | None = Field(default=None, max_length=512)
    field_type: str | None = Field(default=None, max_length=32)
    x: float | None = None
    y: float | None = None
    delta_x: float | None = None
    delta_y: float | None = None
    button: str | None = Field(default=None, max_length=16)


class WebProfileIn(BaseModel):
    initial_url: str
    authentication_mode: Literal["none", "basic_auth", "form", "http_header", "cookie", "manual"] = "none"
    username_secret_id: int | None = None
    password_secret_id: int | None = None
    auth_secret_id: int | None = None
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    success_url_pattern: str | None = None
    success_dom_selector: str | None = None
    header_name: str | None = None
    cookie_name: str | None = None
    blocked_domains: str | None = None
    upload_policy: Literal["deny", "allow"] = "deny"
    download_policy: Literal["deny", "allow"] = "deny"
    clipboard_policy: Literal["deny", "read", "write", "read_write"] = "deny"
    popup_policy: Literal["deny", "same_origin", "allow"] = "same_origin"
    allow_subdomains: bool = True
    login_timeout_seconds: int = Field(default=30, ge=1, le=300)
    idle_timeout_seconds: int = Field(default=900, ge=30, le=86400)
    maximum_session_duration_minutes: int = Field(default=60, ge=1, le=1440)
    max_upload_bytes: int = Field(default=10_485_760, ge=0, le=1_073_741_824)
    max_download_bytes: int = Field(default=52_428_800, ge=0, le=1_073_741_824)


class VncProfileIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(default=5900, ge=1, le=65535)
    secret_id: int | None = None
    tls_required: bool = True


def _profile_out(profile) -> dict[str, Any]:
    # Secret references are metadata, never secret values.
    return {column.name: getattr(profile, column.name) for column in profile.__table__.columns if column.name not in {"created_at", "updated_at"}}


@router.put("/servers/{server_id}/web-profile")
async def put_web_profile(server_id: int, payload: WebProfileIn, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server: raise HTTPException(404, "Server not found")
    require_permission(db, user, "servers.edit", server_id=server_id, conceal=True)
    profile = db.query(WebConnectionProfile).filter_by(server_id=server_id).first() or WebConnectionProfile(server_id=server_id)
    values = payload.model_dump(); server.allow_subdomains = values.pop("allow_subdomains")
    for key, value in values.items(): setattr(profile, key, value)
    server.protocol = "web"
    db.add(profile)
    await web_provider.validate_configuration(ProviderContext(db, server))
    db.commit(); db.refresh(profile)
    return _profile_out(profile)


@router.put("/servers/{server_id}/vnc-profile")
async def put_vnc_profile(server_id: int, payload: VncProfileIn, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server: raise HTTPException(404, "Server not found")
    require_permission(db, user, "servers.edit", server_id=server_id, conceal=True)
    profile = db.query(VncConnectionProfile).filter_by(server_id=server_id).first() or VncConnectionProfile(server_id=server_id)
    for key, value in payload.model_dump().items(): setattr(profile, key, value)
    server.protocol = "vnc"; db.add(profile); db.commit(); db.refresh(profile)
    return _profile_out(profile)


def _authorize_session(db: DBSession, user: User, session_id: int, permission: str | None = None) -> Session:
    session = db.get(Session, session_id)
    if not session: raise HTTPException(404, "Session not found")
    code = permission or ("sessions.view_own" if session.user_id == user.id else "sessions.view_group")
    if not is_global_admin(user) and not has_permission(db, user, code, server_id=session.server_id):
        raise HTTPException(404, "Session not found")
    return session


def _stream_token(user: User, session: Session) -> str:
    expire = utcnow() + timedelta(seconds=settings.pam_websocket_token_ttl_seconds)
    return jwt.encode({"sub": user.username, "uid": user.id, "sid": session.id, "typ": "pam_stream", "exp": expire}, settings.secret_key, algorithm=settings.jwt_algorithm)


def _verify_stream_token(token: str, session_id: int) -> dict[str, Any]:
    try:
        claims = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        if claims.get("typ") != "pam_stream" or int(claims.get("sid", -1)) != session_id:
            raise JWTError("wrong binding")
        return claims
    except (JWTError, ValueError, TypeError) as exc:
        raise HTTPException(401, "Invalid stream token") from exc


@router.post("/access-grants/{grant_id}/launch-session", status_code=201)
async def launch(grant_id: int, request: Request, token: str = Depends(oauth2_scheme), user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    grant = db.get(AccessGrant, grant_id)
    if not grant or grant.status != "active" or grant.valid_to.replace(tzinfo=grant.valid_to.tzinfo or timezone.utc) <= utcnow():
        raise HTTPException(404, "Active grant not found")
    if grant.user_id != user.id and not is_global_admin(user): raise HTTPException(404, "Active grant not found")
    require_permission(db, user, "access.connect", server_id=grant.server_id, conceal=True)
    server = grant.server
    protocol = server.protocol or "ssh"
    if protocol == "ssh": raise HTTPException(409, "Use the existing SSH gateway for SSH grants")
    claims = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    auth_expiry = datetime.fromtimestamp(claims["exp"], timezone.utc)
    now = utcnow()
    web_profile = db.query(WebConnectionProfile).filter_by(server_id=server.id).first() if protocol == "web" else None
    idle_timeout = web_profile.idle_timeout_seconds if web_profile else settings.pam_web_idle_timeout_seconds
    absolute_timeout = web_profile.maximum_session_duration_minutes * 60 if web_profile else settings.pam_web_absolute_timeout_seconds
    session = Session(user_id=user.id, server_id=server.id, grant_id=grant.id, linux_username=grant.linux_username, source_ip=source_ip(request), started_at=now, status="active", protocol=protocol, target_host=server.hostname, recording_enabled=True, last_heartbeat_at=now, authentication_expires_at=auth_expiry, idle_timeout_seconds=idle_timeout, absolute_timeout_seconds=absolute_timeout, max_session_seconds=absolute_timeout)
    db.add(session); db.flush()
    try:
        result = await provider_for(protocol).launch_session(ProviderContext(db, server, grant, session))
    except Exception:
        session.status = "failed"; session.ended_at = utcnow(); session.termination_reason = "worker_failure"; db.commit()
        raise
    write_audit(db, "session.started", f"Started {protocol} session {session.id}", user_id=user.id, server_id=server.id, grant_id=grant.id, session_id=session.id, source_ip=source_ip(request))
    db.commit()
    return {"session_id": session.id, "protocol": protocol, "stream_token": _stream_token(user, session), **result}


@router.post("/sessions/{session_id}/heartbeat")
def heartbeat(session_id: int, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = _authorize_session(db, user, session_id)
    if session.status != "active": raise HTTPException(409, "Session is not active")
    session.last_heartbeat_at = utcnow(); db.commit()
    return {"message": "ok"}


@router.post("/sessions/{session_id}/stream-token")
def renew_token(session_id: int, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = _authorize_session(db, user, session_id)
    if session.status != "active": raise HTTPException(409, "Session is not active")
    return {"token": _stream_token(user, session), "expires_in": settings.pam_websocket_token_ttl_seconds}


@router.post("/web-sessions/{session_id}/input")
async def browser_input(session_id: int, payload: InputEvent, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = _authorize_session(db, user, session_id)
    if session.protocol != "web" or session.status != "active": raise HTTPException(409, "Active web session required")
    result = await web_provider.handle_input(ProviderContext(db, session.server, session.grant, session), payload.model_dump(exclude_none=True))
    session.last_heartbeat_at = utcnow(); db.commit()
    return result


@router.post("/web-sessions/{session_id}/upload")
async def browser_upload(session_id: int, selector: str = Form(...), file: UploadFile = File(...), user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = _authorize_session(db, user, session_id)
    data = await file.read(web_provider.profile(ProviderContext(db, session.server, session.grant, session)).max_upload_bytes + 1)
    await web_provider.handle_upload(ProviderContext(db, session.server, session.grant, session), selector, file.filename or "upload", data)
    session.last_heartbeat_at = utcnow(); db.commit()
    return {"message": "uploaded"}


@router.get("/sessions/{session_id}/events")
def events(session_id: int, event_type: str | None = None, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    _authorize_session(db, user, session_id)
    query = db.query(SessionEvent).filter_by(session_id=session_id)
    if event_type: query = query.filter_by(event_type=event_type)
    return [{"id": row.id, "session_id": row.session_id, "event_type": row.event_type, "timestamp": row.timestamp, "sequence_number": row.sequence_number, "source": row.source, "metadata": json.loads(row.metadata_json or "{}"), "sensitive": row.sensitive} for row in query.order_by(SessionEvent.sequence_number).all()]


def _recording_session(db: DBSession, user: User, session_id: int, request: Request) -> Session:
    session = _authorize_session(db, user, session_id)
    permission = "recordings.view_own" if session.user_id == user.id else "recordings.view_group"
    if not is_global_admin(user) and not has_permission(db, user, permission, server_id=session.server_id): raise HTTPException(404, "Session not found")
    if normalized_role(user.role) in {"admin", "operator"}:
        require_step_up(db, user, "view_recording", request, reason="Privileged recording access requires MFA step-up", force=True)
    write_audit(db, "recording.accessed", f"Accessed recordings for session {session.id}", user_id=user.id, server_id=session.server_id, session_id=session.id, source_ip=source_ip(request))
    return session


@router.get("/sessions/{session_id}/artifacts")
def artifacts(session_id: int, request: Request, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    _recording_session(db, user, session_id, request)
    result = [{"id": row.id, "artifact_type": row.artifact_type, "sha256": row.sha256, "mime_type": row.mime_type, "size_bytes": row.size_bytes, "created_at": row.created_at} for row in db.query(SessionArtifact).filter_by(session_id=session_id).all()]
    db.commit()
    return result


def _safe_artifact(db: DBSession, session_id: int, artifact_id: int) -> SessionArtifact:
    artifact = db.query(SessionArtifact).filter_by(id=artifact_id, session_id=session_id).first()
    if not artifact: raise HTTPException(404, "Artifact not found")
    root = Path(settings.pam_artifact_dir).resolve()
    path = Path(artifact.storage_path).resolve()
    if root not in path.parents or not path.is_file(): raise HTTPException(404, "Artifact not found")
    return artifact


def _artifact_response(session_id: int, artifact_id: int, request: Request, user: User, db: DBSession, download: bool):
    session = _recording_session(db, user, session_id, request)
    artifact = _safe_artifact(db, session_id, artifact_id)
    action = "recording.downloaded" if download else "recording.played"
    write_audit(db, action, f"Accessed artifact {artifact.id}", user_id=user.id, server_id=session.server_id, session_id=session.id, source_ip=source_ip(request), metadata={"artifact_id": artifact.id, "sha256": artifact.sha256})
    db.commit()
    headers = {"Content-Disposition": f'{"attachment" if download else "inline"}; filename="{Path(artifact.storage_path).name}"'}
    return FileResponse(artifact.storage_path, media_type=artifact.mime_type, headers=headers)


@router.get("/sessions/{session_id}/artifacts/{artifact_id}/play")
def play(session_id: int, artifact_id: int, request: Request, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    return _artifact_response(session_id, artifact_id, request, user, db, False)


@router.get("/sessions/{session_id}/artifacts/{artifact_id}/download")
def download(session_id: int, artifact_id: int, request: Request, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    return _artifact_response(session_id, artifact_id, request, user, db, True)


@router.get("/sessions/{session_id}/replay")
def replay(session_id: int, request: Request, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = _recording_session(db, user, session_id, request)
    events_data = events(session_id, None, user, db)
    artifact_data = artifacts(session_id, request, user, db)
    return {"session": {"id": session.id, "protocol": session.protocol, "status": session.status, "started_at": session.started_at, "ended_at": session.ended_at, "termination_reason": session.termination_reason}, "user": {"id": session.user.id, "username": session.user.username}, "resource": {"id": session.server.id, "hostname": session.server.hostname, "protocol": session.protocol}, "request": {"id": session.grant.request_id}, "grant": {"id": session.grant.id, "valid_from": session.grant.valid_from, "valid_to": session.grant.valid_to, "status": session.grant.status}, "events": events_data, "artifacts": artifact_data}


async def _ws_session(websocket: WebSocket, session_id: int, token: str, protocol: str):
    try: claims = _verify_stream_token(token, session_id)
    except HTTPException:
        await websocket.close(code=4401); return None, None
    db = SessionLocal()
    session = db.get(Session, session_id)
    if not session or session.protocol != protocol or session.status != "active" or session.user_id != int(claims["uid"]):
        db.close(); await websocket.close(code=4403); return None, None
    await websocket.accept()
    return db, session


@router.websocket("/web-sessions/{session_id}/stream")
async def browser_stream(websocket: WebSocket, session_id: int, token: str = Query(...)):
    db, session = await _ws_session(websocket, session_id, token, "web")
    if not session: return
    try:
        runtime = web_provider.runtimes.get(session_id)
        if not runtime: await websocket.close(code=1011); return
        while True:
            frame_task = asyncio.create_task(runtime.frames.get())
            input_task = asyncio.create_task(websocket.receive_json())
            done, pending = await asyncio.wait((frame_task, input_task), return_when=asyncio.FIRST_COMPLETED)
            for task in pending: task.cancel()
            if frame_task in done:
                await websocket.send_json({"type": "frame", **frame_task.result()})
            if input_task in done:
                payload = InputEvent.model_validate(input_task.result())
                await web_provider.handle_input(ProviderContext(db, session.server, session.grant, session), payload.model_dump(exclude_none=True))
                session.last_heartbeat_at = utcnow(); db.commit()
    except (WebSocketDisconnect, asyncio.CancelledError): pass
    finally: db.close()


@router.websocket("/vnc-sessions/{session_id}/stream")
async def vnc_stream(websocket: WebSocket, session_id: int, token: str = Query(...)):
    db, session = await _ws_session(websocket, session_id, token, "vnc")
    if not session: return
    runtime = vnc_provider.runtimes.get(session_id)
    if not runtime: db.close(); await websocket.close(code=1011); return
    try:
        await websocket.send_bytes(runtime.version)
        await websocket.receive_bytes()
        await websocket.send_bytes(b"\x01\x01")
        await websocket.receive_bytes()
        await websocket.send_bytes(b"\x00\x00\x00\x00")
        runtime.writer.write(await websocket.receive_bytes()); await runtime.writer.drain()

        async def target_to_client():
            while data := await runtime.reader.read(65536): await websocket.send_bytes(data)
        async def client_to_target():
            while True:
                data = await websocket.receive_bytes(); runtime.writer.write(data); await runtime.writer.drain()
        tasks = [asyncio.create_task(target_to_client()), asyncio.create_task(client_to_target())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending: task.cancel()
    except (WebSocketDisconnect, asyncio.CancelledError): pass
    finally: db.close()

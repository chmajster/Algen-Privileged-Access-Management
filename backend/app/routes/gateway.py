from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user
from app.config import settings
from app.database import get_db
from app.gateway.server import state as gateway_state
from app.gateway.service import finish_gateway_connection
from app.models import AccessGrant, AccessRequest, GatewayConnection, GatewayEvent, GatewayRecording, User
from app.mfa.step_up import require_step_up
from app.rbac import has_permission, is_global_admin, normalized_role, permitted_server_ids


router = APIRouter(prefix="/api/gateway", tags=["gateway"])


def _can_view_grant(db: DBSession, user: User, grant_id: int) -> bool:
    if is_global_admin(user):
        return True
    grant = db.get(AccessGrant, grant_id)
    if not grant:
        return False
    permission = "sessions.view_own" if grant.user_id == user.id else "sessions.view_group"
    return has_permission(db, user, permission, server_id=grant.server_id)


def _can_view_recording(db: DBSession, user: User, recording: GatewayRecording) -> bool:
    if is_global_admin(user):
        return True
    permission = "recordings.view_own" if recording.user_id == user.id else "recordings.view_group"
    return has_permission(db, user, permission, server_id=recording.server_id)


def _visible_connections(db: DBSession, user: User):
    query = db.query(GatewayConnection)
    if not is_global_admin(user):
        own_ids = permitted_server_ids(db, user, "sessions.view_own") or set()
        group_ids = permitted_server_ids(db, user, "sessions.view_group") or set()
        query = query.filter(((GatewayConnection.user_id == user.id) & GatewayConnection.server_id.in_(own_ids)) | GatewayConnection.server_id.in_(group_ids))
    return query


def _connection_out(item: GatewayConnection) -> dict:
    data = schemas.GatewayConnectionOut.model_validate(item).model_dump()
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


def _recording_out(item: GatewayRecording) -> dict:
    data = schemas.GatewayRecordingOut.model_validate(item).model_dump()
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


def _event_out(item: GatewayEvent) -> dict:
    data = schemas.GatewayEventOut.model_validate(item).model_dump()
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


@router.get("/status", response_model=schemas.Message)
def status_view(_: User = Depends(get_current_user)):
    return {
        "message": "gateway status",
        "detail": {
            "enabled": settings.pam_gateway_enabled,
            "host": settings.pam_gateway_host,
            "port": settings.pam_gateway_port,
            "access_mode": settings.pam_access_mode,
            "running": gateway_state.running,
            "runtime": gateway_state.message,
        },
    }


@router.get("/connections", response_model=list[schemas.GatewayConnectionOut])
def list_connections(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    return [_connection_out(item) for item in _visible_connections(db, current_user).order_by(GatewayConnection.started_at.desc()).limit(1000).all()]


@router.get("/connections/active", response_model=list[schemas.GatewayConnectionOut])
def active_connections(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = _visible_connections(db, current_user).filter(GatewayConnection.status == "active")
    return [_connection_out(item) for item in query.order_by(GatewayConnection.started_at.desc()).all()]


@router.post("/connections/{connection_id}/terminate", response_model=schemas.GatewayConnectionOut)
def terminate_connection(connection_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    connection = db.get(GatewayConnection, connection_id)
    if not connection:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway connection not found")
    if not _can_view_grant(db, current_user, connection.grant_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway connection not found")
    if not has_permission(db, current_user, "sessions.terminate", server_id=connection.server_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing sessions.terminate permission")
    finish_gateway_connection(db, connection, "manual_terminate")
    db.commit()
    db.refresh(connection)
    return _connection_out(connection)


@router.get("/events", response_model=list[schemas.GatewayEventOut])
def list_events(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = db.query(GatewayEvent)
    if not is_global_admin(current_user):
        own_ids = permitted_server_ids(db, current_user, "sessions.view_own") or set(); group_ids = permitted_server_ids(db, current_user, "sessions.view_group") or set()
        query = query.filter(((GatewayEvent.user_id == current_user.id) & GatewayEvent.server_id.in_(own_ids)) | GatewayEvent.server_id.in_(group_ids))
    return [_event_out(item) for item in query.order_by(GatewayEvent.created_at.desc()).limit(1000).all()]


@router.get("/recordings", response_model=list[schemas.GatewayRecordingOut])
def list_recordings(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query = db.query(GatewayRecording)
    if not is_global_admin(current_user):
        own_ids = permitted_server_ids(db, current_user, "recordings.view_own") or set(); group_ids = permitted_server_ids(db, current_user, "recordings.view_group") or set()
        query = query.filter(((GatewayRecording.user_id == current_user.id) & GatewayRecording.server_id.in_(own_ids)) | GatewayRecording.server_id.in_(group_ids))
    return [_recording_out(item) for item in query.order_by(GatewayRecording.created_at.desc()).limit(1000).all()]


@router.get("/recordings/{recording_id}", response_model=schemas.GatewayRecordingOut)
def get_recording(recording_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    recording = db.get(GatewayRecording, recording_id)
    if not recording:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recording not found")
    if not _can_view_recording(db, current_user, recording):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recording not found")
    return _recording_out(recording)


@router.get("/recordings/{recording_id}/download")
def download_recording(recording_id: int, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    recording = db.get(GatewayRecording, recording_id)
    if not recording:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recording not found")
    if not _can_view_recording(db, current_user, recording):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Recording not found")
    if normalized_role(current_user.role) in {"admin", "operator"}:
        require_step_up(db, current_user, "view_recording", request, reason="Recording download requires MFA step-up", force=True)
    path = Path(recording.recording_path)
    if not path.exists():
        return Response("", media_type="text/plain")
    return FileResponse(path, media_type="application/jsonl", filename=path.name)

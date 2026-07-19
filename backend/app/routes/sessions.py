import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.database import get_db
from app.models import AccessGrant, AccessRequest, GatewayConnection, Session, SessionCommand, User
from app.mfa.step_up import require_step_up
from app.rbac import has_permission, is_global_admin, normalized_role, permitted_server_ids
from app.gateway.service import finish_gateway_connection


router = APIRouter(prefix="/api", tags=["sessions"])


def _can_view(db: DBSession, user: User, item: Session) -> bool:
    if is_global_admin(user):
        return True
    permission = "sessions.view_own" if user.id == item.user_id else "sessions.view_group"
    return has_permission(db, user, permission, server_id=item.server_id)


def _session_out(item: Session) -> dict:
    return {
        **schemas.SessionOut.model_validate(item).model_dump(),
        "username": item.user.username if item.user else None,
        "server_hostname": item.server.hostname if item.server else None,
        "command_count": len(item_commands(item)),
        "access_type": item.grant.access_type if item.grant else None,
    }


def _command_out(item: SessionCommand) -> dict:
    data = schemas.SessionCommandOut.model_validate(item).model_dump()
    data["is_sudo"] = item.is_sudo
    data["username"] = item.user.username if item.user else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


def item_commands(item: Session) -> list[SessionCommand]:
    return list(getattr(item, "commands", []) or [])


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _visible_sessions_query(db: DBSession, current_user: User):
    query = db.query(Session)
    if not is_global_admin(current_user):
        own_ids = permitted_server_ids(db, current_user, "sessions.view_own") or set()
        group_ids = permitted_server_ids(db, current_user, "sessions.view_group") or set()
        query = query.filter(((Session.user_id == current_user.id) & Session.server_id.in_(own_ids)) | Session.server_id.in_(group_ids))
    return query


def _apply_session_filters(query, user_id: int | None, server_id: int | None, status_value: str | None, active: bool | None, date_from: str | None, date_to: str | None):
    if user_id:
        query = query.filter(Session.user_id == user_id)
    if server_id:
        query = query.filter(Session.server_id == server_id)
    if status_value:
        query = query.filter(Session.status == status_value)
    if active is not None:
        query = query.filter(Session.status == "active" if active else Session.status != "active")
    parsed_from = _parse_dt(date_from)
    parsed_to = _parse_dt(date_to)
    if parsed_from:
        query = query.filter(Session.started_at >= parsed_from)
    if parsed_to:
        query = query.filter(Session.started_at <= parsed_to)
    return query


def _visible_commands_query(db: DBSession, current_user: User):
    query = db.query(SessionCommand)
    if not is_global_admin(current_user):
        own_ids = permitted_server_ids(db, current_user, "commands.view_own") or set()
        group_ids = permitted_server_ids(db, current_user, "commands.view_group") or set()
        query = query.filter(((SessionCommand.user_id == current_user.id) & SessionCommand.server_id.in_(own_ids)) | SessionCommand.server_id.in_(group_ids))
    return query


def _apply_command_filters(query, user_id: int | None, server_id: int | None, q: str | None, sudo: bool | None, date_from: str | None, date_to: str | None):
    if user_id:
        query = query.filter(SessionCommand.user_id == user_id)
    if server_id:
        query = query.filter(SessionCommand.server_id == server_id)
    if q:
        query = query.filter(SessionCommand.command.contains(q))
    if sudo is not None:
        query = query.filter(SessionCommand.is_sudo.is_(sudo))
    parsed_from = _parse_dt(date_from)
    parsed_to = _parse_dt(date_to)
    if parsed_from:
        query = query.filter(SessionCommand.executed_at >= parsed_from)
    if parsed_to:
        query = query.filter(SessionCommand.executed_at <= parsed_to)
    return query


@router.get("/sessions", response_model=list[schemas.SessionOut])
def list_sessions(
    user_id: int | None = None,
    server_id: int | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    active: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    query = _apply_session_filters(_visible_sessions_query(db, current_user), user_id, server_id, status_value, active, date_from, date_to)
    return [_session_out(item) for item in query.order_by(Session.started_at.desc()).all()]


@router.get("/sessions/{session_id:int}", response_model=schemas.SessionOut)
def get_session(session_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(Session, session_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not _can_view(db, current_user, item):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return _session_out(item)


@router.get("/sessions/{session_id:int}/commands", response_model=list[schemas.SessionCommandOut])
def session_commands(
    session_id: int,
    q: str | None = None,
    sudo: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    session = db.get(Session, session_id)
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not _can_view(db, current_user, session):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    query = _apply_command_filters(db.query(SessionCommand).filter(SessionCommand.session_id == session_id), None, None, q, sudo, date_from, date_to)
    return [_command_out(item) for item in query.order_by(SessionCommand.executed_at.desc()).all()]


@router.post("/sessions/{session_id:int}/terminate", response_model=schemas.SessionOut)
def terminate_session(session_id: int, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(Session, session_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not has_permission(db, current_user, "sessions.terminate", server_id=item.server_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if item.status == "active":
        connection = db.query(GatewayConnection).filter(GatewayConnection.session_id == item.id, GatewayConnection.status == "active").first()
        if connection:
            finish_gateway_connection(db, connection, "manual_terminate")
        else:
            item.status = "terminated"; item.ended_at = datetime.now(item.started_at.tzinfo); item.termination_reason = "manual_terminate"
        write_audit(db, "session.terminated", f"Terminated session {item.id}", user_id=current_user.id, server_id=item.server_id, session_id=item.id, source_ip=source_ip(request))
        db.commit(); db.refresh(item)
    return _session_out(item)


@router.get("/sessions/{session_id:int}/recording", response_model=schemas.Message)
def session_recording(session_id: int, request: Request, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    session = db.get(Session, session_id)
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not _can_view(db, current_user, session):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if normalized_role(current_user.role) in {"admin", "operator"}:
        require_step_up(db, current_user, "view_recording", request, reason="Recording access requires MFA step-up", force=True)
    if not session.session_record_path or session.session_record_path.startswith("session_id="):
        return {"message": "No recording for this session"}
    return {"message": "Recording path", "detail": {"path": session.session_record_path, "type": session.session_record_type}}


@router.get("/session-commands", response_model=list[schemas.SessionCommandOut])
def list_commands(
    user_id: int | None = None,
    server_id: int | None = None,
    q: str | None = None,
    sudo: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    query = _apply_command_filters(_visible_commands_query(db, current_user), user_id, server_id, q, sudo, date_from, date_to)
    return [_command_out(item) for item in query.order_by(SessionCommand.executed_at.desc()).limit(1000).all()]


@router.get("/session-commands/{command_id:int}", response_model=schemas.SessionCommandOut)
def get_command(command_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = db.get(SessionCommand, command_id)
    if not item or not _visible_commands_query(db, current_user).filter(SessionCommand.id == command_id).first():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Command not found")
    return _command_out(item)


@router.get("/sessions/export.csv")
def export_sessions(
    request: Request,
    user_id: int | None = None,
    server_id: int | None = None,
    status_value: str | None = Query(default=None, alias="status"),
    active: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    if normalized_role(current_user.role) in {"admin", "operator"}:
        require_step_up(db, current_user, "export_session_logs", request, reason="Session export requires MFA step-up", force=True)
    query = _apply_session_filters(_visible_sessions_query(db, current_user), user_id, server_id, status_value, active, date_from, date_to)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user_id", "server_id", "grant_id", "linux_username", "access_mode", "gateway_session_id", "client_ip", "target_host", "target_user", "source_ip", "started_at", "ended_at", "duration_seconds", "status", "recording_enabled", "termination_reason", "command_count"])
    for item in query.order_by(Session.started_at.desc()).all():
        writer.writerow([item.id, item.user_id, item.server_id, item.grant_id, item.linux_username, item.access_mode, item.gateway_session_id, item.client_ip, item.target_host, item.target_user, item.source_ip, item.started_at, item.ended_at, item.duration_seconds, item.status, item.recording_enabled, item.termination_reason, db.query(SessionCommand).filter(SessionCommand.session_id == item.id).count()])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=sessions.csv"})


@router.get("/session-commands/export.csv")
def export_commands(
    request: Request,
    user_id: int | None = None,
    server_id: int | None = None,
    q: str | None = None,
    sudo: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    if normalized_role(current_user.role) in {"admin", "operator"}:
        require_step_up(db, current_user, "export_session_logs", request, reason="Command export requires MFA step-up", force=True)
    query = _apply_command_filters(_visible_commands_query(db, current_user), user_id, server_id, q, sudo, date_from, date_to)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "session_id", "user_id", "server_id", "grant_id", "linux_username", "command", "working_directory", "is_sudo", "source", "command_index", "exit_code", "executed_at", "raw_log"])
    for item in query.order_by(SessionCommand.executed_at.desc()).all():
        writer.writerow([item.id, item.session_id, item.user_id, item.server_id, item.grant_id, item.linux_username, item.command, item.working_directory, item.is_sudo, item.source, item.command_index, item.exit_code, item.executed_at, item.raw_log])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=session_commands.csv"})

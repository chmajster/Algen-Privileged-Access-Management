import hashlib
import json
import re
import shlex
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.config import settings
from app.models import AccessGrant, LogImportOffset, Server, Session, SessionCommand, utcnow


COMMANDS_LOG = "{username}_commands.log"
SESSIONS_LOG = "{username}_sessions.log"
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)=([^\s\"']+)"),
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)([^\s\"']+)"),
]


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return utcnow()


def _sanitize_raw_log(value: str) -> str:
    sanitized = value
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
    return sanitized


def _json_dumps(payload: dict[str, Any]) -> str:
    return _sanitize_raw_log(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str))


def _source_ip(ssh_connection: str | None) -> str | None:
    if not ssh_connection:
        return None
    parts = ssh_connection.split()
    return parts[0] if parts else None


def configure_command_logging(server: Server, linux_username: str, grant_id: int) -> None:
    from app.executor import get_executor

    get_executor().configure_command_logging(server, linux_username, grant_id)


def configure_session_recording(server: Server, linux_username: str, grant_id: int) -> None:
    from app.executor import get_executor

    get_executor().configure_session_recording(server, linux_username, grant_id)


def fetch_session_logs(server: Server, linux_username: str, grant_id: int) -> dict[str, str]:
    from app.executor import get_executor

    logs = get_executor().fetch_session_logs(server, linux_username, grant_id)
    if isinstance(logs, dict):
        return {str(key): str(value) for key, value in logs.items()}
    if isinstance(logs, list):
        result: dict[str, str] = {}
        for item in logs:
            if isinstance(item, dict) and "path" in item:
                result[str(item["path"])] = str(item.get("content", ""))
        return result
    return {}


def remove_monitoring_hooks(server: Server, linux_username: str) -> None:
    from app.executor import get_executor

    executor = get_executor()
    remover = getattr(executor, "remove_monitoring_hooks", None)
    if remover:
        remover(server, linux_username)


def detect_sudo_command(command: str) -> bool:
    command = (command or "").strip()
    if not command:
        return False
    if re.search(r"(^|[;&|]\s*)sudo(\s|$)", command):
        return True
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return any(token == "sudo" or token.endswith("/sudo") for token in tokens)


def parse_command_logs(raw_log: str | list[str]) -> list[dict[str, Any]]:
    lines = raw_log if isinstance(raw_log, list) else raw_log.splitlines()
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("type") not in {None, "command"}:
            continue
        command = payload.get("command")
        if not command:
            continue
        payload["type"] = "command"
        payload["timestamp"] = _parse_timestamp(payload.get("timestamp") or payload.get("executed_at"))
        payload["raw_log"] = _sanitize_raw_log(line)
        payload["is_sudo"] = detect_sudo_command(command)
        payload["working_directory"] = payload.get("pwd") or payload.get("working_directory")
        entries.append(payload)
    return entries


def parse_session_logs(raw_log: str | list[str]) -> list[dict[str, Any]]:
    lines = raw_log if isinstance(raw_log, list) else raw_log.splitlines()
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("type") not in {"session_started", "session_finished"}:
            continue
        payload["timestamp"] = _parse_timestamp(payload.get("timestamp"))
        payload["raw_log"] = _sanitize_raw_log(line)
        entries.append(payload)
    return entries


def _session_key(payload: dict[str, Any], grant: AccessGrant) -> str:
    return str(payload.get("session_id") or f"grant-{grant.id}")


def _find_or_create_session(db: DBSession, grant: AccessGrant, payload: dict[str, Any]) -> Session:
    session_token = _session_key(payload, grant)
    raw_marker = f"session_id={session_token}"
    session = (
        db.query(Session)
        .filter(Session.grant_id == grant.id, Session.session_record_path == raw_marker)
        .first()
    )
    if session:
        return session
    session = db.query(Session).filter(Session.grant_id == grant.id).first()
    if session and session.session_record_path in {None, raw_marker}:
        session.session_record_path = raw_marker
        return session
    started_at = _parse_timestamp(payload.get("timestamp"))
    session = Session(
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        linux_username=payload.get("linux_username") or grant.linux_username,
        source_ip=_source_ip(payload.get("ssh_connection")),
        started_at=started_at,
        status="active",
        session_record_path=raw_marker,
        session_record_type="bash_history",
    )
    db.add(session)
    db.flush()
    write_audit(
        db,
        "session_started",
        f"Session started for {grant.linux_username}",
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        session_id=session.id,
        metadata={"session_token": session_token},
    )
    return session


def _finish_session(db: DBSession, session: Session, payload: dict[str, Any]) -> None:
    ended_at = _parse_timestamp(payload.get("timestamp"))
    session.ended_at = ended_at
    session.status = "closed"
    session.duration_seconds = max(0, int((ended_at - session.started_at).total_seconds()))
    write_audit(
        db,
        "session_finished",
        f"Session {session.id} finished",
        user_id=session.user_id,
        server_id=session.server_id,
        grant_id=session.grant_id,
        session_id=session.id,
        metadata={"session_token": payload.get("session_id")},
    )


def deduplicate_command_log(entry: dict[str, Any]) -> str:
    raw = entry.get("raw_log")
    if raw:
        return hashlib.sha256(str(raw).encode("utf-8")).hexdigest()
    basis = "|".join(
        str(entry.get(key) or "")
        for key in ("session_id", "grant_id", "linux_username", "timestamp", "command", "working_directory")
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _command_exists(db: DBSession, session_id: int, raw_log: str) -> bool:
    return db.query(SessionCommand).filter(SessionCommand.session_id == session_id, SessionCommand.raw_log == raw_log).first() is not None


def _insert_command(db: DBSession, grant: AccessGrant, session: Session, entry: dict[str, Any]) -> bool:
    raw_log = _json_dumps({**entry, "dedupe": deduplicate_command_log(entry)})
    if _command_exists(db, session.id, raw_log):
        return False
    command = str(entry["command"])
    item = SessionCommand(
        session_id=session.id,
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        linux_username=str(entry.get("linux_username") or grant.linux_username),
        command=command,
        working_directory=entry.get("working_directory") or entry.get("pwd"),
        is_sudo=bool(entry.get("is_sudo", detect_sudo_command(command))),
        exit_code=entry.get("exit_code"),
        executed_at=_parse_timestamp(entry.get("timestamp")),
        raw_log=raw_log,
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return False
    write_audit(
        db,
        "command_logged",
        f"Command logged for {grant.linux_username}",
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        session_id=session.id,
        metadata={"command": command[:200], "is_sudo": item.is_sudo},
    )
    from app.policy.engine import PolicyEngine

    engine = PolicyEngine(db)
    decision = engine.evaluate_command(item)
    item.risk_score = decision.risk_score
    item.risk_severity = decision.severity
    item.matched_policy_rule_id = decision.matched_rules[0]["id"] if decision.matched_rules else None
    item.blocked_by_policy = decision.denied
    engine.record_risk_event(
        decision,
        "command_denied" if decision.denied else "command_risk_detected",
        f"Command risk detected: {command[:160]}",
        user_id=grant.user_id,
        server_id=grant.server_id,
        grant_id=grant.id,
        session_id=session.id,
        command_id=item.id,
    )
    if settings.pam_auto_revoke_on_critical_risk and decision.severity == "critical" and grant.status == "active":
        from app.services import revoke_grant

        revoke_grant(db, grant, None, "auto revoked after critical command risk")
    return True


def _offset_for(db: DBSession, grant: AccessGrant, path: str) -> LogImportOffset:
    item = (
        db.query(LogImportOffset)
        .filter(
            LogImportOffset.server_id == grant.server_id,
            LogImportOffset.grant_id == grant.id,
            LogImportOffset.linux_username == grant.linux_username,
            LogImportOffset.log_path == path,
        )
        .first()
    )
    if item:
        return item
    item = LogImportOffset(
        server_id=grant.server_id,
        grant_id=grant.id,
        linux_username=grant.linux_username,
        log_path=path,
        last_offset=0,
    )
    db.add(item)
    db.flush()
    return item


def _new_content(db: DBSession, grant: AccessGrant, path: str, content: str) -> str:
    offset = _offset_for(db, grant, path)
    encoded = content.encode("utf-8")
    if offset.last_offset > len(encoded):
        offset.last_offset = 0
    new_bytes = encoded[offset.last_offset :]
    offset.last_offset = len(encoded)
    offset.last_hash = hashlib.sha256(encoded).hexdigest()
    offset.updated_at = utcnow()
    return new_bytes.decode("utf-8", errors="replace")


def _mock_lines(grant: AccessGrant, finalize: bool = False) -> dict[str, str]:
    now = utcnow()
    session_id = f"mock-{grant.id}"
    session_lines = [
        json.dumps(
            {
                "type": "session_started",
                "timestamp": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "grant_id": grant.id,
                "session_id": session_id,
                "linux_username": grant.linux_username,
                "ssh_connection": "127.0.0.1 53000 127.0.0.1 22",
            }
        )
    ]
    if finalize:
        session_lines.append(
            json.dumps(
                {
                    "type": "session_finished",
                    "timestamp": now.isoformat().replace("+00:00", "Z"),
                    "grant_id": grant.id,
                    "session_id": session_id,
                    "linux_username": grant.linux_username,
                }
            )
        )
    commands = ["whoami", "hostname", "df -h", "sudo systemctl status nginx", "journalctl -xe"]
    command_lines = []
    for index, command in enumerate(commands):
        command_lines.append(
            json.dumps(
                {
                    "type": "command",
                    "timestamp": (now - timedelta(minutes=4, seconds=50 - index * 30)).isoformat().replace("+00:00", "Z"),
                    "grant_id": grant.id,
                    "session_id": session_id,
                    "linux_username": grant.linux_username,
                    "pwd": f"/home/{grant.linux_username}",
                    "command": command,
                    "ssh_connection": "127.0.0.1 53000 127.0.0.1 22",
                    "exit_code": 0,
                }
            )
        )
    base = settings.pam_session_log_dir.rstrip("/")
    return {
        f"{base}/{COMMANDS_LOG.format(username=grant.linux_username)}": "\n".join(command_lines) + "\n",
        f"{base}/{SESSIONS_LOG.format(username=grant.linux_username)}": "\n".join(session_lines) + "\n",
    }


def import_session_logs(db: DBSession, grant: AccessGrant, logs: dict[str, str] | None = None, finalize: bool = False) -> int:
    imported = 0
    try:
        if logs is None:
            logs = fetch_session_logs(grant.server, grant.linux_username, grant.id)
        if not logs and settings.pam_executor_mode == "mock":
            logs = _mock_lines(grant, finalize=finalize)

        session_entries: list[dict[str, Any]] = []
        command_entries: list[dict[str, Any]] = []
        for path, content in logs.items():
            content = _new_content(db, grant, path, content)
            if path.endswith("_sessions.log"):
                session_entries.extend(parse_session_logs(content))
            elif path.endswith("_commands.log"):
                command_entries.extend(parse_command_logs(content))

        sessions_by_token: dict[str, Session] = {}
        for entry in sorted(session_entries, key=lambda item: item["timestamp"]):
            session = _find_or_create_session(db, grant, entry)
            sessions_by_token[_session_key(entry, grant)] = session
            if entry.get("type") == "session_finished":
                _finish_session(db, session, entry)

        for entry in sorted(command_entries, key=lambda item: item["timestamp"]):
            token = _session_key(entry, grant)
            session = sessions_by_token.get(token) or _find_or_create_session(db, grant, entry)
            if _insert_command(db, grant, session, entry):
                imported += 1

        write_audit(
            db,
            "session_log_imported",
            f"Imported {imported} command logs for grant {grant.id}",
            user_id=grant.user_id,
            server_id=grant.server_id,
            grant_id=grant.id,
            metadata={"imported_commands": imported},
        )
        return imported
    except Exception as exc:
        write_audit(
            db,
            "session_log_import_failed",
            f"Failed to import session logs for grant {grant.id}",
            user_id=grant.user_id,
            server_id=grant.server_id,
            grant_id=grant.id,
            metadata={"error": str(exc)[:500]},
        )
        raise


def import_jsonl_commands(db: DBSession, grant: AccessGrant, lines: list[str]) -> int:
    base = settings.pam_session_log_dir.rstrip("/")
    return import_session_logs(
        db,
        grant,
        logs={f"{base}/{COMMANDS_LOG.format(username=grant.linux_username)}": "\n".join(lines) + "\n"},
    )


def import_session_logs_for_grant(db: DBSession, grant: AccessGrant, mock_seed: bool = False, finalize: bool = False) -> int:
    if mock_seed:
        return import_session_logs(db, grant, logs=_mock_lines(grant, finalize=finalize), finalize=finalize)
    return import_session_logs(db, grant, finalize=finalize)

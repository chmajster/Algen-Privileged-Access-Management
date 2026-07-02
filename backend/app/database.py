from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


DATABASE_URL = settings.database_url

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()


def _ensure_sqlite_columns() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    def add_missing(conn, table: str, definitions: dict[str, str]) -> None:
        if table not in table_names:
            return
        columns = {column["name"] for column in inspector.get_columns(table)}
        for name, definition in definitions.items():
            if name not in columns:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))

    with engine.begin() as conn:
        add_missing(
            conn,
            "servers",
            {
                "gateway_enabled": "BOOLEAN DEFAULT 1 NOT NULL",
                "gateway_target_user": "VARCHAR(64)",
                "gateway_auth_type": "VARCHAR(32) DEFAULT 'key' NOT NULL",
                "gateway_private_key_path": "VARCHAR(512)",
                "direct_access_enabled": "BOOLEAN DEFAULT 1 NOT NULL",
                "secret_ref_id": "INTEGER",
                "gateway_secret_ref_id": "INTEGER",
                "ssh_auth_secret_id": "INTEGER",
                "rotation_enabled": "BOOLEAN DEFAULT 1 NOT NULL",
                "last_secret_rotation_at": "DATETIME",
                "next_secret_rotation_at": "DATETIME",
                "risk_level": "VARCHAR(32) DEFAULT 'low' NOT NULL",
                "server_group_id": "INTEGER",
                "criticality": "VARCHAR(32) DEFAULT 'low' NOT NULL",
                "require_session_recording": "BOOLEAN DEFAULT 0 NOT NULL",
                "require_approval": "BOOLEAN DEFAULT 0 NOT NULL",
                "require_mfa": "BOOLEAN DEFAULT 0 NOT NULL",
            },
        )
        add_missing(
            conn,
            "users",
            {
                "auth_provider": "VARCHAR(32) DEFAULT 'local' NOT NULL",
                "external_id": "VARCHAR(255)",
                "display_name": "VARCHAR(255)",
                "email_verified": "BOOLEAN DEFAULT 0 NOT NULL",
                "mfa_enabled": "BOOLEAN DEFAULT 0 NOT NULL",
                "mfa_secret_encrypted": "TEXT",
                "mfa_enrolled_at": "DATETIME",
                "mfa_last_used_at": "DATETIME",
                "mfa_required": "BOOLEAN DEFAULT 0 NOT NULL",
                "risk_level": "VARCHAR(32) DEFAULT 'low' NOT NULL",
                "last_risk_score": "INTEGER DEFAULT 0 NOT NULL",
                "last_password_change_at": "DATETIME",
                "last_identity_sync_at": "DATETIME",
                "disabled_reason": "TEXT",
                "locked_until": "DATETIME",
                "failed_login_count": "INTEGER DEFAULT 0 NOT NULL",
            },
        )
        add_missing(
            conn,
            "access_requests",
            {
                "calculated_risk_score": "INTEGER DEFAULT 0 NOT NULL",
                "policy_decision_json": "TEXT",
                "mfa_required": "BOOLEAN DEFAULT 0 NOT NULL",
                "approval_required": "BOOLEAN DEFAULT 0 NOT NULL",
                "session_recording_required": "BOOLEAN DEFAULT 0 NOT NULL",
                "denied_by_policy": "BOOLEAN DEFAULT 0 NOT NULL",
            },
        )
        add_missing(
            conn,
            "access_grants",
            {
                "access_mode": "VARCHAR(32) DEFAULT 'direct' NOT NULL",
                "gateway_username": "VARCHAR(64)",
                "gateway_connection_string": "VARCHAR(512)",
                "gateway_session_required": "BOOLEAN DEFAULT 0 NOT NULL",
                "direct_ssh_enabled": "BOOLEAN DEFAULT 1 NOT NULL",
                "calculated_risk_score": "INTEGER DEFAULT 0 NOT NULL",
                "policy_decision_json": "TEXT",
                "monitoring_level": "VARCHAR(32) DEFAULT 'basic' NOT NULL",
            },
        )
        add_missing(
            conn,
            "sessions",
            {
                "access_mode": "VARCHAR(32) DEFAULT 'direct' NOT NULL",
                "gateway_session_id": "VARCHAR(128)",
                "target_host": "VARCHAR(255)",
                "target_port": "INTEGER",
                "target_user": "VARCHAR(64)",
                "client_ip": "VARCHAR(64)",
                "client_port": "INTEGER",
                "recording_enabled": "BOOLEAN DEFAULT 0 NOT NULL",
                "recording_path": "VARCHAR(512)",
                "recording_size_bytes": "INTEGER",
                "idle_timeout_seconds": "INTEGER",
                "max_session_seconds": "INTEGER",
                "termination_reason": "VARCHAR(128)",
            },
        )
        add_missing(
            conn,
            "session_commands",
            {
                "is_sudo": "BOOLEAN DEFAULT 0 NOT NULL",
                "source": "VARCHAR(32) DEFAULT 'bash_hook' NOT NULL",
                "command_index": "INTEGER",
                "stdin_fragment": "TEXT",
                "stdout_fragment": "TEXT",
                "stderr_fragment": "TEXT",
                "terminal_output_preview": "TEXT",
                "risk_score": "INTEGER DEFAULT 0 NOT NULL",
                "risk_severity": "VARCHAR(32) DEFAULT 'low' NOT NULL",
                "matched_policy_rule_id": "INTEGER",
                "blocked_by_policy": "BOOLEAN DEFAULT 0 NOT NULL",
            },
        )
        add_missing(
            conn,
            "audit_logs",
            {
                "session_id": "INTEGER",
                "metadata_json": "TEXT",
            },
        )
        add_missing(
            conn,
            "gateway_recordings",
            {
                "encryption_secret_id": "INTEGER",
                "encrypted": "BOOLEAN DEFAULT 0 NOT NULL",
            },
        )

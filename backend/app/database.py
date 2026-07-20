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
    _ensure_legacy_columns()
    from app.rbac import seed_access_control

    with SessionLocal() as db:
        seed_access_control(db)


def _ensure_legacy_columns() -> None:
    """Idempotently extend installations created before schema migrations.

    New tables are handled by metadata.create_all; this conservative helper
    only adds missing nullable/defaulted columns and works on SQLite and
    PostgreSQL without dropping or rewriting existing data.
    """
    is_postgres = engine.dialect.name == "postgresql"
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    def add_missing(conn, table: str, definitions: dict[str, str]) -> None:
        if table not in table_names:
            return
        columns = {column["name"] for column in inspector.get_columns(table)}
        for name, definition in definitions.items():
            if name not in columns:
                if is_postgres:
                    definition = definition.replace("DEFAULT 1", "DEFAULT TRUE").replace("DEFAULT 0", "DEFAULT FALSE").replace("DATETIME", "TIMESTAMP WITH TIME ZONE")
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))

    with engine.begin() as conn:
        add_missing(
            conn,
            "server_groups",
            {
                "enabled": "BOOLEAN DEFAULT 1 NOT NULL",
                "is_system": "BOOLEAN DEFAULT 0 NOT NULL",
                "created_by_id": "INTEGER",
                "updated_by_id": "INTEGER",
                "allowed_access_types": "VARCHAR(128) DEFAULT 'ssh_only' NOT NULL",
                "max_grant_minutes": "INTEGER DEFAULT 60 NOT NULL",
                "allowed_durations": "VARCHAR(128) DEFAULT '30,60' NOT NULL",
                "require_approval": "BOOLEAN DEFAULT 1 NOT NULL",
                "require_mfa": "BOOLEAN DEFAULT 0 NOT NULL",
                "require_gateway": "BOOLEAN DEFAULT 0 NOT NULL",
                "deny_direct_ssh": "BOOLEAN DEFAULT 0 NOT NULL",
                "require_command_logging": "BOOLEAN DEFAULT 1 NOT NULL",
                "require_session_recording": "BOOLEAN DEFAULT 0 NOT NULL",
                "allowed_hours": "VARCHAR(64)",
                "allowed_weekdays": "VARCHAR(32) DEFAULT '0,1,2,3,4,5,6' NOT NULL",
                "max_concurrent_grants": "INTEGER DEFAULT 1 NOT NULL",
                "max_active_sessions": "INTEGER DEFAULT 1 NOT NULL",
                "allow_self_extension": "BOOLEAN DEFAULT 0 NOT NULL",
                "allow_auto_grant": "BOOLEAN DEFAULT 0 NOT NULL",
                "require_reason": "BOOLEAN DEFAULT 1 NOT NULL",
                "min_reason_length": "INTEGER DEFAULT 10 NOT NULL",
                "revoke_on_membership_loss": "BOOLEAN DEFAULT 1 NOT NULL",
                "terminate_sessions_on_membership_loss": "BOOLEAN DEFAULT 1 NOT NULL",
            },
        )
        add_missing(conn, "server_group_members", {"created_by_id": "INTEGER"})
        add_missing(
            conn,
            "servers",
            {
                "display_name": "VARCHAR(255)",
                "ssh_auth_type": "VARCHAR(32) NOT NULL DEFAULT 'vault_secret'",
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
                "server_template_id": "INTEGER",
                "created_by_id": "INTEGER",
                "registered_at": "DATETIME",
                "registration_source": "VARCHAR(32) DEFAULT 'manual' NOT NULL",
                "registration_status": "VARCHAR(32) DEFAULT 'approved' NOT NULL",
                "registration_rejection_reason": "TEXT",
                "registration_connection_status": "VARCHAR(32)",
                "host_key_policy": "VARCHAR(32) DEFAULT 'strict' NOT NULL",
                "expected_host_key_fingerprint": "VARCHAR(128)",
                "protocol": "VARCHAR(32) DEFAULT 'ssh' NOT NULL",
                "allowed_domains": "TEXT",
                "allow_private_network": "BOOLEAN DEFAULT 0 NOT NULL",
                "allow_subdomains": "BOOLEAN DEFAULT 1 NOT NULL",
                "tags": "TEXT",
                "connection_timeout_seconds": "INTEGER DEFAULT 10 NOT NULL",
            },
        )
        add_missing(
            conn,
            "users",
            {
                "auth_provider": "VARCHAR(32) DEFAULT 'local_db' NOT NULL",
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
                "protocol": "VARCHAR(32) DEFAULT 'ssh' NOT NULL",
                "last_heartbeat_at": "DATETIME",
                "authentication_expires_at": "DATETIME",
                "absolute_timeout_seconds": "INTEGER",
                "worker_id": "VARCHAR(128)",
            },
        )
        add_missing(
            conn,
            "web_connection_profiles",
            {
                "login_timeout_seconds": "INTEGER DEFAULT 30 NOT NULL",
                "idle_timeout_seconds": "INTEGER DEFAULT 900 NOT NULL",
                "maximum_session_duration_minutes": "INTEGER DEFAULT 60 NOT NULL",
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
                "matched_policy_id": "INTEGER",
                "blocked_by_policy": "BOOLEAN DEFAULT 0 NOT NULL",
            },
        )
        add_missing(
            conn,
            "risk_events",
            {
                "matched_policy_id": "INTEGER",
            },
        )
        add_missing(
            conn,
            "audit_logs",
            {
                "session_id": "INTEGER",
                "metadata_json": "TEXT",
                "user_agent": "VARCHAR(512)",
                "object_type": "VARCHAR(64)",
                "object_id": "VARCHAR(128)",
                "result": "VARCHAR(32) NOT NULL DEFAULT 'success'",
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
        for index_name, table, columns in (
            ("ix_server_group_members_group_server", "server_group_members", "server_group_id, server_id"),
            ("ix_server_group_users_group_user", "server_group_user_memberships", "server_group_id, user_id"),
            ("ix_user_group_permissions_scope", "user_group_permissions", "server_group_id, user_id, permission_id"),
            ("ix_audit_logs_object", "audit_logs", "object_type, object_id"),
        ):
            if table in table_names:
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})"))

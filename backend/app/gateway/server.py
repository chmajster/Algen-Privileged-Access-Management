import asyncio
from dataclasses import dataclass

from app.config import settings
from app.database import SessionLocal
from app.gateway.auth import authorize_gateway_login
from app.gateway.command_detector import CommandDetector
from app.gateway.recorder import GatewayRecorder
from app.gateway.service import add_gateway_command, create_gateway_session, finish_gateway_connection, write_gateway_event
from app.models import AccessGrant, GatewayConnection, Session


@dataclass
class GatewayServerState:
    running: bool = False
    message: str = "not started"


state = GatewayServerState()


class GatewayAuthContext:
    def __init__(self) -> None:
        self.grant_id: int | None = None
        self.client_ip: str | None = None
        self.client_port: int | None = None


def _key_to_text(key) -> str:
    exported = key.export_public_key()
    return exported.decode() if isinstance(exported, bytes) else str(exported)


def _peer(conn) -> tuple[str | None, int | None]:
    peer = conn.get_extra_info("peername")
    if isinstance(peer, tuple) and len(peer) >= 2:
        return str(peer[0]), int(peer[1])
    return None, None


def build_server_classes(asyncssh):
    class PAMGatewaySSHServer(asyncssh.SSHServer):
        def __init__(self):
            self.context = GatewayAuthContext()

        def connection_made(self, conn):
            self.context.client_ip, self.context.client_port = _peer(conn)

        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return False

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            db = SessionLocal()
            try:
                grant = authorize_gateway_login(db, username, _key_to_text(key), self.context.client_ip)
                if not grant:
                    db.commit()
                    return False
                self.context.grant_id = grant.id
                db.commit()
                return True
            finally:
                db.close()

        def session_requested(self):
            return PAMGatewaySSHSession(self.context)

    class PAMGatewaySSHSession(asyncssh.SSHServerSession):
        def __init__(self, context: GatewayAuthContext):
            self.context = context
            self.channel = None
            self.connection_id: int | None = None
            self.session_id: int | None = None
            self.detector = CommandDetector()
            self.sequence = 0

        def connection_made(self, chan):
            self.channel = chan

        def pty_requested(self, term_type, term_size, term_modes):
            return True

        def shell_requested(self):
            asyncio.create_task(self._start())
            return True

        async def _start(self):
            db = SessionLocal()
            try:
                grant = db.get(AccessGrant, self.context.grant_id)
                if not grant:
                    self.channel.write("No active grant.\n")
                    self.channel.exit(1)
                    return
                connection = create_gateway_session(
                    db,
                    grant,
                    client_ip=self.context.client_ip or "unknown",
                    client_port=self.context.client_port or 0,
                    mock=settings.pam_executor_mode == "mock",
                )
                self.connection_id = connection.id
                self.session_id = connection.session_id
                db.commit()
                self.channel.write(f"Connected through PAM Gateway to {grant.server.hostname}\n")
                self.channel.write("Live target proxy is enabled when async target SSH is configured for this worker.\n")
            except Exception as exc:
                if self.context.grant_id:
                    grant = db.get(AccessGrant, self.context.grant_id)
                    if grant:
                        write_gateway_event(db, "gateway_target_connect_failed", "Gateway target connect failed", grant=grant, metadata={"error": str(exc)[:500]})
                        db.commit()
                self.channel.write("Gateway failed to start session.\n")
                self.channel.exit(1)
            finally:
                db.close()

        def data_received(self, data, datatype):
            if not self.session_id or not self.context.grant_id:
                return
            db = SessionLocal()
            try:
                session = db.get(Session, self.session_id)
                grant = db.get(AccessGrant, self.context.grant_id)
                if not session or not grant:
                    return
                self.sequence += 1
                if session.recording_enabled:
                    GatewayRecorder().append(session, "stdin", data, self.sequence)
                for detected in self.detector.feed(data):
                    add_gateway_command(db, session, grant, detected["command"], detected["command_index"], stdin=detected["command"])
                connection = db.get(GatewayConnection, self.connection_id) if self.connection_id else None
                if connection:
                    connection.bytes_in += len(data.encode() if isinstance(data, str) else data)
                db.commit()
            finally:
                db.close()

        def connection_lost(self, exc):
            if not self.connection_id:
                return
            db = SessionLocal()
            try:
                connection = db.get(GatewayConnection, self.connection_id)
                if connection:
                    finish_gateway_connection(db, connection, "completed" if exc is None else "client_disconnect")
                    db.commit()
            finally:
                db.close()

    return PAMGatewaySSHServer


async def start_gateway_server() -> None:
    try:
        import asyncssh
    except ImportError:
        state.running = False
        state.message = "asyncssh is not installed; API and mock gateway remain available"
        return
    if not settings.pam_gateway_enabled:
        state.running = False
        state.message = "gateway disabled"
        return
    server_class = build_server_classes(asyncssh)
    await asyncssh.create_server(
        server_class,
        settings.pam_gateway_host,
        settings.pam_gateway_port,
        server_host_keys=[settings.pam_gateway_host_key_path],
    )
    state.running = True
    state.message = f"listening on {settings.pam_gateway_host}:{settings.pam_gateway_port}"
    await asyncio.Future()


def start_gateway_background_task() -> None:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(start_gateway_server())
    except RuntimeError:
        state.message = "gateway background loop unavailable"


if __name__ == "__main__":
    asyncio.run(start_gateway_server())

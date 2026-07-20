import os
import shlex
import tempfile
from abc import ABC, abstractmethod

from app.config import settings
from app.database import SessionLocal
from app.models import Secret, Server
from app.vault import get_vault_backend_for_secret


class Executor(ABC):
    @abstractmethod
    def test_connection(self, server: Server) -> dict:
        raise NotImplementedError

    @abstractmethod
    def grant_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def revoke_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def grant_sudo_access(self, server: Server, linux_username: str, access_type: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def revoke_sudo_access(self, server: Server, linux_username: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def configure_command_logging(self, server: Server, linux_username: str, grant_id: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def configure_session_recording(self, server: Server, linux_username: str, grant_id: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def fetch_session_logs(self, server: Server, linux_username: str, grant_id: int) -> list[dict]:
        raise NotImplementedError

    def remove_monitoring_hooks(self, server: Server, linux_username: str) -> None:
        return None

    @abstractmethod
    def disable_linux_user(self, server: Server, linux_username: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def remove_linux_user(self, server: Server, linux_username: str) -> None:
        raise NotImplementedError


class MockExecutor(Executor):
    def test_connection(self, server: Server) -> dict:
        return {"ok": True, "mode": "mock", "host": server.hostname}

    def grant_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        return None

    def revoke_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        return None

    def grant_sudo_access(self, server: Server, linux_username: str, access_type: str) -> None:
        return None

    def revoke_sudo_access(self, server: Server, linux_username: str) -> None:
        return None

    def configure_command_logging(self, server: Server, linux_username: str, grant_id: int) -> None:
        return None

    def configure_session_recording(self, server: Server, linux_username: str, grant_id: int) -> None:
        return None

    def fetch_session_logs(self, server: Server, linux_username: str, grant_id: int) -> list[dict]:
        return []

    def remove_monitoring_hooks(self, server: Server, linux_username: str) -> None:
        return None

    def disable_linux_user(self, server: Server, linux_username: str) -> None:
        return None

    def remove_linux_user(self, server: Server, linux_username: str) -> None:
        return None


class SSHExecutor(Executor):
    def _resolve_auth(self, server: Server, use_rotation: bool = False, one_time_password: str | None = None) -> tuple[str | None, str | None, str | None]:
        if use_rotation:
            if server.rotation_auth_type == "one_time":
                if not one_time_password:
                    raise RuntimeError("One-time password required for this operation")
                return None, None, one_time_password
            secret_id = server.rotation_secret_id
        else:
            secret_id = server.ssh_auth_secret_id or server.secret_ref_id

        if not secret_id:
            if use_rotation and server.rotation_auth_type == "password":
                raise RuntimeError("Rotation password not configured")
            return server.ssh_private_key_path or settings.pam_executor_ssh_key_path, None, None
        db = SessionLocal()
        try:
            secret = db.get(Secret, secret_id)
            if not secret:
                raise RuntimeError("Configured SSH secret not found")
            value = get_vault_backend_for_secret(db, secret).get_secret_value(secret_id, {"server_id": server.id, "access_context": "executor_ssh_key"})
            db.commit()
        finally:
            db.close()
        if secret.secret_type == "ssh_password" or secret.secret_type == "password":
            return None, None, value
        handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        handle.write(value)
        handle.close()
        os.chmod(handle.name, 0o600)
        return handle.name, handle.name, None

    def _run(self, server: Server, command: str, use_rotation: bool = False, one_time_password: str | None = None) -> str:
        import paramiko

        if getattr(server, "registration_status", "approved") != "approved" or not server.enabled:
            raise RuntimeError("Server is not approved for execution")

        key_path, temp_key_path, password = self._resolve_auth(server, use_rotation=use_rotation, one_time_password=one_time_password)
        admin_user = (server.rotation_admin_user if use_rotation and server.rotation_admin_user else server.ssh_admin_user) or "root"
        key = paramiko.RSAKey.from_private_key_file(key_path) if key_path else None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=server.ip_address,
                port=server.ssh_port,
                username=admin_user,
                pkey=key,
                password=password,
                allow_agent=False,
                look_for_keys=False,
                timeout=10,
            )
            stdin, stdout, stderr = client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode() + stderr.read().decode()
            if exit_code != 0:
                raise RuntimeError(f"Remote command failed with exit {exit_code}: {output[-500:]}")
            return output
        finally:
            client.close()
            if temp_key_path:
                try:
                    os.remove(temp_key_path)
                except OSError:
                    pass
            password = None

    def test_connection(self, server: Server) -> dict:
        output = self._run(server, "id && hostname")
        return {"ok": True, "mode": "ssh", "output": output}

    def grant_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        user = shlex.quote(linux_username)
        key = shlex.quote(ssh_public_key)
        command = f"""
set -e
id -u {user} >/dev/null 2>&1 || useradd -m -s /bin/bash {user}
mkdir -p /home/{user}/.ssh
touch /home/{user}/.ssh/authorized_keys
grep -qxF {key} /home/{user}/.ssh/authorized_keys || echo {key} >> /home/{user}/.ssh/authorized_keys
chmod 700 /home/{user}/.ssh
chmod 600 /home/{user}/.ssh/authorized_keys
chown -R {user}:{user} /home/{user}/.ssh
usermod -U {user} || true
"""
        self._run(server, command)

    def revoke_ssh_access(self, server: Server, linux_username: str, ssh_public_key: str) -> None:
        user = shlex.quote(linux_username)
        key = shlex.quote(ssh_public_key)
        self._run(server, f"touch /home/{user}/.ssh/authorized_keys && grep -vxF {key} /home/{user}/.ssh/authorized_keys > /tmp/{user}.keys && mv /tmp/{user}.keys /home/{user}/.ssh/authorized_keys")

    def grant_sudo_access(self, server: Server, linux_username: str, access_type: str) -> None:
        if access_type == "ssh_only":
            return
        user = shlex.quote(linux_username)
        sudoers = (
            f"{linux_username} ALL=(root) NOPASSWD: /bin/systemctl status *, /bin/journalctl *, /bin/df, /bin/free, /usr/bin/top, /usr/bin/htop"
            if access_type == "limited_sudo"
            else f"{linux_username} ALL=(ALL) NOPASSWD: ALL"
        )
        content = shlex.quote(sudoers)
        self._run(server, f"echo {content} > /etc/sudoers.d/{user} && chmod 440 /etc/sudoers.d/{user} && visudo -cf /etc/sudoers.d/{user} || (rm -f /etc/sudoers.d/{user}; exit 1)")

    def revoke_sudo_access(self, server: Server, linux_username: str) -> None:
        self._run(server, f"rm -f /etc/sudoers.d/{shlex.quote(linux_username)}")

    def configure_command_logging(self, server: Server, linux_username: str, grant_id: int) -> None:
        user_arg = shlex.quote(linux_username)
        log_dir = shlex.quote(settings.pam_session_log_dir.rstrip("/"))
        commands_path = f"{settings.pam_session_log_dir.rstrip('/')}/{linux_username}_commands.log"
        sessions_path = f"{settings.pam_session_log_dir.rstrip('/')}/{linux_username}_sessions.log"
        profile = f"""
export PAM_LITE_LOG_DIR='{settings.pam_session_log_dir.rstrip("/")}'
export PAM_LITE_COMMAND_LOG='{commands_path}'
export PAM_LITE_SESSION_LOG='{sessions_path}'
export HISTTIMEFORMAT='%F %T '
shopt -s histappend
export PAM_LITE_GRANT_ID='{grant_id}'
export PAM_LITE_SESSION_ID="${{PAM_LITE_SESSION_ID:-$(command -v uuidgen >/dev/null 2>&1 && uuidgen || printf '%s_%s' "${{SSH_CONNECTION// /_}}" "$$")}}"
__pam_lite_previous_prompt="${{PROMPT_COMMAND:-}}"
__pam_lite_json_escape() {{ python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\\n"))[1:-1])'; }}
__pam_lite_log_session_start() {{
  [ -n "${{PAM_LITE_SESSION_STARTED:-}}" ] && return
  export PAM_LITE_SESSION_STARTED=1
  printf '{{"type":"session_started","timestamp":"%s","grant_id":%s,"session_id":"%s","linux_username":"%s","ssh_connection":"%s"}}\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PAM_LITE_GRANT_ID" "$PAM_LITE_SESSION_ID" "{linux_username}" "$SSH_CONNECTION" >> "$PAM_LITE_SESSION_LOG"
}}
__pam_lite_log_command() {{
  local last_command
  last_command="$(history 1 | sed 's/^ *[0-9]* *//')"
  [ -z "$last_command" ] && return
  [ "$last_command" = "$PAM_LITE_LAST_COMMAND" ] && return
  export PAM_LITE_LAST_COMMAND="$last_command"
  local esc_command esc_pwd
  esc_command="$(printf '%s' "$last_command" | __pam_lite_json_escape)"
  esc_pwd="$(printf '%s' "$PWD" | __pam_lite_json_escape)"
  printf '{{"type":"command","timestamp":"%s","grant_id":%s,"session_id":"%s","linux_username":"%s","pwd":"%s","command":"%s","ssh_connection":"%s"}}\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PAM_LITE_GRANT_ID" "$PAM_LITE_SESSION_ID" "{linux_username}" "$esc_pwd" "$esc_command" "$SSH_CONNECTION" >> "$PAM_LITE_COMMAND_LOG"
}}
__pam_lite_log_session_finish() {{
  printf '{{"type":"session_finished","timestamp":"%s","grant_id":%s,"session_id":"%s","linux_username":"%s"}}\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PAM_LITE_GRANT_ID" "$PAM_LITE_SESSION_ID" "{linux_username}" >> "$PAM_LITE_SESSION_LOG"
}}
__pam_lite_log_session_start
trap __pam_lite_log_session_finish EXIT
PROMPT_COMMAND='__pam_lite_log_command; '"$__pam_lite_previous_prompt"
"""
        self._run(
            server,
            f"mkdir -p {log_dir}\n"
            f"touch {shlex.quote(commands_path)} {shlex.quote(sessions_path)}\n"
            f"chown root:root {shlex.quote(commands_path)} {shlex.quote(sessions_path)} || true\n"
            f"chmod 622 {shlex.quote(commands_path)} {shlex.quote(sessions_path)}\n"
            f"chattr +a {shlex.quote(commands_path)} {shlex.quote(sessions_path)} 2>/dev/null || true\n"
            f"cat > /home/{user_arg}/.pam_lite_profile <<'EOF'\n{profile}\nEOF\n"
            f"chown {user_arg}:{user_arg} /home/{user_arg}/.pam_lite_profile\n"
            f"touch /home/{user_arg}/.bashrc\n"
            f"sed -i '/# BEGIN PAM-LITE MONITORING/,/# END PAM-LITE MONITORING/d' /home/{user_arg}/.bashrc\n"
            f"cat >> /home/{user_arg}/.bashrc <<'EOF'\n# BEGIN PAM-LITE MONITORING\n. ~/.pam_lite_profile\n# END PAM-LITE MONITORING\nEOF\n"
            f"chown {user_arg}:{user_arg} /home/{user_arg}/.bashrc\n",
        )

    def configure_session_recording(self, server: Server, linux_username: str, grant_id: int) -> None:
        return None

    def fetch_session_logs(self, server: Server, linux_username: str, grant_id: int) -> dict[str, str]:
        base = settings.pam_session_log_dir.rstrip("/")
        paths = [
            f"{base}/{linux_username}_commands.log",
            f"{base}/{linux_username}_sessions.log",
        ]
        logs: dict[str, str] = {}
        for path in paths:
            logs[path] = self._run(server, f"test -f {shlex.quote(path)} && cat {shlex.quote(path)} || true")
        return logs

    def remove_monitoring_hooks(self, server: Server, linux_username: str) -> None:
        user = shlex.quote(linux_username)
        self._run(
            server,
            f"test -f /home/{user}/.bashrc && sed -i '/# BEGIN PAM-LITE MONITORING/,/# END PAM-LITE MONITORING/d' /home/{user}/.bashrc || true\n"
            f"rm -f /home/{user}/.pam_lite_profile || true",
        )

    def disable_linux_user(self, server: Server, linux_username: str) -> None:
        self._run(server, f"usermod -L {shlex.quote(linux_username)}")

    def remove_linux_user(self, server: Server, linux_username: str) -> None:
        self._run(server, f"userdel {shlex.quote(linux_username)}")


def get_executor() -> Executor:
    if os.getenv("PAM_EXECUTOR_MODE", settings.pam_executor_mode).lower() == "ssh":
        return SSHExecutor()
    return MockExecutor()

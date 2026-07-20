import base64
import hashlib
import ipaddress
import json
import os
import socket
from pathlib import Path

from app.config import settings


SAFE_CONNECTION_ERRORS = {
    "authentication_failed",
    "host_key_mismatch",
    "host_unreachable",
    "connection_timeout",
    "connection_error",
}


def request_fingerprint(payload) -> str:
    data = payload.model_dump(mode="json", exclude={"password"})
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_target_address(address: str, allowed_cidrs: str | None, allow_special: bool, *, resolve_dns: bool) -> None:
    try:
        addresses = [ipaddress.ip_address(address)]
    except ValueError:
        addresses = []
        if resolve_dns:
            try:
                addresses = list({ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(address, None)})
            except (OSError, ValueError) as exc:
                raise ValueError("host_unreachable") from exc
    networks = []
    if allowed_cidrs:
        try:
            networks = [ipaddress.ip_network(value.strip(), strict=False) for value in allowed_cidrs.split(",") if value.strip()]
        except ValueError as exc:
            raise ValueError("invalid_template_network_policy") from exc
    for item in addresses:
        special = item.is_loopback or item.is_link_local or item.is_multicast or item.is_unspecified or item.is_reserved
        if special and not allow_special:
            raise ValueError("address_not_allowed")
        if networks and not any(item in network for network in networks):
            raise ValueError("address_outside_allowed_cidrs")


def _sha256_fingerprint(key) -> str:
    value = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"SHA256:{value}"


def test_password_connection(*, address: str, port: int, username: str, password: str, timeout: int, host_key_policy: str, expected_fingerprint: str | None) -> dict:
    if os.getenv("PAM_EXECUTOR_MODE", settings.pam_executor_mode).lower() != "ssh":
        return {"ok": True, "status": "connection_successful"}
    import paramiko

    class ManualFingerprintPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if not expected_fingerprint or _sha256_fingerprint(key) != expected_fingerprint:
                raise paramiko.SSHException("host key rejected")

    client = paramiko.SSHClient()
    known_hosts = Path(settings.pam_registration_known_hosts_path)
    try:
        if host_key_policy == "strict":
            client.load_system_host_keys()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        if host_key_policy == "trust_on_first_use":
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        elif host_key_policy == "manual_fingerprint":
            client.set_missing_host_key_policy(ManualFingerprintPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=address,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        if host_key_policy == "manual_fingerprint" and _sha256_fingerprint(client.get_transport().get_remote_server_key()) != expected_fingerprint:
            return {"ok": False, "status": "host_key_mismatch"}
        _, stdout, _ = client.exec_command("hostname", timeout=timeout)
        stdout.channel.recv_exit_status()
        if host_key_policy == "trust_on_first_use":
            client.save_host_keys(str(known_hosts))
        return {"ok": True, "status": "connection_successful"}
    except paramiko.AuthenticationException:
        return {"ok": False, "status": "authentication_failed"}
    except paramiko.BadHostKeyException:
        return {"ok": False, "status": "host_key_mismatch"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "status": "connection_timeout"}
    except (paramiko.NoValidConnectionsError, socket.gaierror, OSError):
        return {"ok": False, "status": "host_unreachable"}
    except paramiko.SSHException:
        return {"ok": False, "status": "connection_error"}
    finally:
        client.close()

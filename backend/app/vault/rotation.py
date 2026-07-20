import json
import secrets as pysecrets
from datetime import timedelta

from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.config import settings
from app.models import Secret, SecretRotationJob, SecretVersion, Server, utcnow

from . import get_vault_backend
from .audit import write_secret_access_log
from .crypto import calculate_fingerprint, encrypt_secret


def generate_mock_private_key() -> tuple[str, str]:
    token = pysecrets.token_urlsafe(48)
    private_key = f"-----BEGIN OPENSSH PRIVATE KEY-----\nmock-{settings.pam_ssh_key_type}-{token}\n-----END OPENSSH PRIVATE KEY-----\n"
    public_key = f"ssh-{settings.pam_ssh_key_type} mock-{token[:32]} pam-lite-rotated"
    return private_key, public_key


def rotate_secret_value(db: DBSession, secret: Secret, actor_id: int | None = None, reason: str = "manual_rotation") -> SecretRotationJob:
    job = SecretRotationJob(secret_id=secret.id, job_type="ssh_key_rotation", status="running", started_at=utcnow(), old_fingerprint=secret.fingerprint, metadata_json=json.dumps({"reason": reason}))
    db.add(job)
    db.flush()
    try:
        private_key, public_key = generate_mock_private_key()
        encrypted = encrypt_secret(private_key) if secret.backend_type in {"local_encrypted", "external_vault"} else None
        new_version = secret.version + 1
        fingerprint = calculate_fingerprint(private_key)
        version = SecretVersion(secret_id=secret.id, version=new_version, encrypted_value=encrypted, file_path=secret.file_path, external_ref=secret.external_ref, fingerprint=fingerprint, public_key=public_key, status="active", created_by=actor_id, activated_at=utcnow(), rotation_reason=reason)
        for item in db.query(SecretVersion).filter(SecretVersion.secret_id == secret.id, SecretVersion.status == "active").all():
            item.status = "revoked"
            item.revoked_at = utcnow()
        db.add(version)
        secret.version = new_version
        secret.encrypted_value = encrypted
        secret.fingerprint = fingerprint
        secret.public_key = public_key
        secret.status = "active"
        secret.last_rotated_at = utcnow()
        secret.next_rotation_at = utcnow() + timedelta(hours=settings.pam_secret_rotation_interval_hours)
        job.status = "completed"
        job.finished_at = utcnow()
        job.new_fingerprint = fingerprint
        write_secret_access_log(db, action="secret_rotated", secret_id=secret.id, secret_version_id=version.id, user_id=actor_id, message="Secret rotated")
        write_audit(db, "secret.rotated", f"Rotated secret {secret.name}", user_id=actor_id, metadata={"secret_id": secret.id, "fingerprint": fingerprint})
    except Exception as exc:
        job.status = "failed"
        job.finished_at = utcnow()
        job.error_message = str(exc)[:500]
        secret.status = "rotation_failed"
        write_secret_access_log(db, action="secret_rotation_failed", secret_id=secret.id, user_id=actor_id, success=False, message="Secret rotation failed", metadata={"error": job.error_message})
    return job


def rotate_server_ssh_key(db: DBSession, server_id: int, actor_id: int | None = None) -> SecretRotationJob:
    server = db.get(Server, server_id)
    if not server:
        raise ValueError("Server not found")
    secret_id = server.ssh_auth_secret_id or server.secret_ref_id
    if not secret_id:
        secret = get_vault_backend(db).create_secret(
            f"{server.hostname}-ssh-auth",
            "target_connection_key",
            generate_mock_private_key()[0],
            {"environment": server.environment, "owner": server.owner, "actor_id": actor_id, "description": "Auto-created SSH auth key"},
        )
        server.ssh_auth_secret_id = secret.id
    else:
        secret = db.get(Secret, secret_id)
    job = rotate_secret_value(db, secret, actor_id=actor_id, reason="server_ssh_key_rotation")
    server.last_secret_rotation_at = utcnow() if job.status == "completed" else server.last_secret_rotation_at
    server.next_secret_rotation_at = utcnow() + timedelta(hours=settings.pam_secret_rotation_interval_hours)
    job.server_id = server.id
    return job


def run_due_rotations(db: DBSession) -> int:
    if not settings.pam_secret_rotation_enabled:
        return 0
    due = db.query(Secret).filter(Secret.status == "active", Secret.next_rotation_at <= utcnow()).all()
    count = 0
    for secret in due:
        rotate_secret_value(db, secret, reason="scheduled_rotation")
        count += 1
    return count

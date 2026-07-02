from pathlib import Path

from sqlalchemy.orm import Session as DBSession

from app.models import Secret, SecretVersion, utcnow

from .audit import write_secret_access_log
from .base import VaultBackend
from .crypto import calculate_fingerprint


class FileReferenceBackend(VaultBackend):
    def __init__(self, db: DBSession):
        self.db = db

    def create_secret(self, name: str, secret_type: str, value: str | None, metadata: dict):
        file_path = metadata.get("file_path") or value
        fingerprint = metadata.get("fingerprint")
        secret = Secret(
            name=name,
            secret_type=secret_type,
            backend_type="file_reference",
            environment=metadata.get("environment"),
            owner=metadata.get("owner"),
            description=metadata.get("description"),
            file_path=file_path,
            fingerprint=fingerprint,
            public_key=metadata.get("public_key"),
            created_by=metadata.get("actor_id"),
            updated_by=metadata.get("actor_id"),
            status="active",
        )
        self.db.add(secret)
        self.db.flush()
        version = SecretVersion(secret_id=secret.id, version=1, file_path=file_path, fingerprint=fingerprint, public_key=secret.public_key, status="active", created_by=metadata.get("actor_id"), activated_at=utcnow(), rotation_reason="initial")
        self.db.add(version)
        self.db.flush()
        write_secret_access_log(self.db, action="secret_created", secret_id=secret.id, secret_version_id=version.id, user_id=metadata.get("actor_id"), message="File reference secret created")
        return secret

    def get_secret_value(self, secret_id: int, context: dict):
        secret = self.db.get(Secret, secret_id)
        if not secret or secret.status != "active":
            write_secret_access_log(self.db, action="secret_read", secret_id=secret_id, success=False, message="Secret unavailable", **context)
            raise ValueError("Secret unavailable")
        path = Path(secret.file_path or "")
        if not path.exists():
            write_secret_access_log(self.db, action="secret_used", secret_id=secret.id, success=False, message="Secret file not found", **context)
            raise FileNotFoundError("Secret file not found")
        value = path.read_text(encoding="utf-8")
        if not secret.fingerprint:
            secret.fingerprint = calculate_fingerprint(value)
        write_secret_access_log(self.db, action="secret_used", secret_id=secret.id, success=True, message="Secret file used", **context)
        return value

    def get_secret_metadata(self, secret_id: int):
        return self.db.get(Secret, secret_id)

    def update_secret(self, secret_id: int, value: str | None, metadata: dict):
        secret = self.db.get(Secret, secret_id)
        if not secret:
            raise ValueError("Secret not found")
        for key in ("name", "environment", "owner", "description", "status", "public_key", "file_path"):
            if key in metadata:
                setattr(secret, key, metadata[key])
        write_secret_access_log(self.db, action="secret_updated", secret_id=secret.id, user_id=metadata.get("actor_id"), message="File reference metadata updated")
        return secret

    def rotate_secret(self, secret_id: int, rotation_context: dict):
        return self.update_secret(secret_id, None, rotation_context)

    def disable_secret(self, secret_id: int):
        secret = self.db.get(Secret, secret_id)
        secret.status = "disabled"
        write_secret_access_log(self.db, action="secret_disabled", secret_id=secret.id, message="Secret disabled")
        return secret

    def list_versions(self, secret_id: int):
        return self.db.query(SecretVersion).filter(SecretVersion.secret_id == secret_id).order_by(SecretVersion.version.desc()).all()

    def activate_version(self, secret_id: int, version_id: int):
        version = self.db.get(SecretVersion, version_id)
        if not version or version.secret_id != secret_id:
            raise ValueError("Version not found")
        version.status = "active"
        version.activated_at = utcnow()
        return version

    def revoke_version(self, secret_id: int, version_id: int):
        version = self.db.get(SecretVersion, version_id)
        if not version or version.secret_id != secret_id:
            raise ValueError("Version not found")
        version.status = "revoked"
        version.revoked_at = utcnow()
        return version

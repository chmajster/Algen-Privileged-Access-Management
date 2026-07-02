from datetime import timedelta

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import Secret, SecretVersion, utcnow

from .audit import write_secret_access_log
from .base import VaultBackend
from .crypto import calculate_fingerprint, decrypt_secret, encrypt_secret


class LocalEncryptedBackend(VaultBackend):
    def __init__(self, db: DBSession):
        self.db = db

    def create_secret(self, name: str, secret_type: str, value: str | None, metadata: dict):
        encrypted = encrypt_secret(value or "") if value is not None else None
        fingerprint = metadata.get("fingerprint") or calculate_fingerprint(value)
        now = utcnow()
        secret = Secret(
            name=name,
            secret_type=secret_type,
            backend_type="local_encrypted",
            environment=metadata.get("environment"),
            owner=metadata.get("owner"),
            description=metadata.get("description"),
            encrypted_value=encrypted,
            fingerprint=fingerprint,
            public_key=metadata.get("public_key"),
            status="active",
            created_by=metadata.get("actor_id"),
            updated_by=metadata.get("actor_id"),
            last_rotated_at=now,
            next_rotation_at=now + timedelta(hours=settings.pam_secret_rotation_interval_hours),
        )
        self.db.add(secret)
        self.db.flush()
        version = SecretVersion(
            secret_id=secret.id,
            version=1,
            encrypted_value=encrypted,
            fingerprint=fingerprint,
            public_key=secret.public_key,
            status="active",
            created_by=metadata.get("actor_id"),
            activated_at=now,
            rotation_reason="initial",
        )
        self.db.add(version)
        self.db.flush()
        write_secret_access_log(self.db, action="secret_created", secret_id=secret.id, secret_version_id=version.id, user_id=metadata.get("actor_id"), message="Secret created")
        write_secret_access_log(self.db, action="secret_version_created", secret_id=secret.id, secret_version_id=version.id, user_id=metadata.get("actor_id"), message="Initial version created")
        return secret

    def get_secret_value(self, secret_id: int, context: dict):
        secret = self.db.get(Secret, secret_id)
        if not secret or secret.status != "active":
            write_secret_access_log(self.db, action="secret_read", secret_id=secret_id, success=False, message="Secret unavailable", **context)
            raise ValueError("Secret unavailable")
        version = self.db.query(SecretVersion).filter(SecretVersion.secret_id == secret.id, SecretVersion.status == "active").order_by(SecretVersion.version.desc()).first()
        ciphertext = version.encrypted_value if version else secret.encrypted_value
        value = decrypt_secret(ciphertext or "")
        write_secret_access_log(self.db, action="secret_used", secret_id=secret.id, secret_version_id=version.id if version else None, success=True, message="Secret used", **context)
        return value

    def get_secret_metadata(self, secret_id: int):
        return self.db.get(Secret, secret_id)

    def update_secret(self, secret_id: int, value: str | None, metadata: dict):
        secret = self.db.get(Secret, secret_id)
        if not secret:
            raise ValueError("Secret not found")
        for key in ("name", "environment", "owner", "description", "status", "public_key"):
            if key in metadata:
                setattr(secret, key, metadata[key])
        if value is not None:
            encrypted = encrypt_secret(value)
            version_no = secret.version + 1
            for existing in self.db.query(SecretVersion).filter(SecretVersion.secret_id == secret.id, SecretVersion.status == "active").all():
                existing.status = "revoked"
                existing.revoked_at = utcnow()
            secret.version = version_no
            secret.encrypted_value = encrypted
            secret.fingerprint = metadata.get("fingerprint") or calculate_fingerprint(value)
            version = SecretVersion(
                secret_id=secret.id,
                version=version_no,
                encrypted_value=encrypted,
                fingerprint=secret.fingerprint,
                public_key=secret.public_key,
                status="active",
                created_by=metadata.get("actor_id"),
                activated_at=utcnow(),
                rotation_reason=metadata.get("rotation_reason") or "manual_update",
            )
            self.db.add(version)
            write_secret_access_log(self.db, action="secret_version_created", secret_id=secret.id, user_id=metadata.get("actor_id"), message="Secret version created")
        secret.updated_by = metadata.get("actor_id")
        write_secret_access_log(self.db, action="secret_updated", secret_id=secret.id, user_id=metadata.get("actor_id"), message="Secret metadata updated")
        return secret

    def rotate_secret(self, secret_id: int, rotation_context: dict):
        value = rotation_context.get("value")
        if value is None:
            raise ValueError("Rotation value is required")
        return self.update_secret(secret_id, value, {**rotation_context, "rotation_reason": rotation_context.get("reason", "rotation")})

    def disable_secret(self, secret_id: int):
        secret = self.db.get(Secret, secret_id)
        if not secret:
            raise ValueError("Secret not found")
        secret.status = "disabled"
        write_secret_access_log(self.db, action="secret_disabled", secret_id=secret.id, message="Secret disabled")
        return secret

    def list_versions(self, secret_id: int):
        return self.db.query(SecretVersion).filter(SecretVersion.secret_id == secret_id).order_by(SecretVersion.version.desc()).all()

    def activate_version(self, secret_id: int, version_id: int):
        version = self.db.get(SecretVersion, version_id)
        if not version or version.secret_id != secret_id:
            raise ValueError("Version not found")
        for item in self.list_versions(secret_id):
            if item.status == "active":
                item.status = "revoked"
                item.revoked_at = utcnow()
        version.status = "active"
        version.activated_at = utcnow()
        secret = self.db.get(Secret, secret_id)
        secret.version = version.version
        secret.encrypted_value = version.encrypted_value
        secret.file_path = version.file_path
        secret.external_ref = version.external_ref
        secret.fingerprint = version.fingerprint
        secret.public_key = version.public_key
        write_secret_access_log(self.db, action="secret_version_activated", secret_id=secret_id, secret_version_id=version.id, message="Secret version activated")
        return version

    def revoke_version(self, secret_id: int, version_id: int):
        version = self.db.get(SecretVersion, version_id)
        if not version or version.secret_id != secret_id:
            raise ValueError("Version not found")
        version.status = "revoked"
        version.revoked_at = utcnow()
        write_secret_access_log(self.db, action="secret_version_revoked", secret_id=secret_id, secret_version_id=version.id, message="Secret version revoked")
        return version

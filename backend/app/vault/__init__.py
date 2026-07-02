from app.config import settings

from .external_vault import ExternalVaultBackend
from .file_reference import FileReferenceBackend
from .local_encrypted import LocalEncryptedBackend


def get_vault_backend(db):
    mode = settings.pam_vault_mode
    if mode == "external_vault":
        return ExternalVaultBackend(db)
    if mode == "file_reference":
        return FileReferenceBackend(db)
    return LocalEncryptedBackend(db)


def get_vault_backend_for_secret(db, secret):
    if secret.backend_type == "external_vault":
        return ExternalVaultBackend(db)
    if secret.backend_type == "file_reference":
        return FileReferenceBackend(db)
    return LocalEncryptedBackend(db)

import base64
import hashlib

from cryptography.fernet import Fernet

from app.config import settings


def _fernet() -> Fernet:
    raw = settings.pam_vault_master_key.encode()
    if len(raw) < 16:
        raise RuntimeError("PAM_VAULT_MASTER_KEY is missing or too short for local_encrypted vault mode")
    try:
        return Fernet(settings.pam_vault_master_key)
    except Exception:
        key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        return Fernet(key)


def encrypt_secret(plaintext: str | bytes) -> str:
    value = plaintext.encode() if isinstance(plaintext, str) else plaintext
    return _fernet().encrypt(value).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


def calculate_fingerprint(secret: str | bytes | None) -> str | None:
    if secret is None:
        return None
    value = secret.encode() if isinstance(secret, str) else secret
    return "sha256:" + hashlib.sha256(value).hexdigest()


def mask_secret(secret: str | None) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}...{secret[-4:]}"

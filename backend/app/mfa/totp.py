import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from app.config import settings
from app.vault.crypto import decrypt_secret, encrypt_secret

try:
    import pyotp
except Exception:  # pragma: no cover - fallback for environments before requirements install
    pyotp = None


def generate_secret() -> str:
    if pyotp:
        return pyotp.random_base32()
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def encrypt_mfa_secret(secret: str) -> str:
    return encrypt_secret(secret)


def decrypt_mfa_secret(ciphertext: str) -> str:
    return decrypt_secret(ciphertext)


def provisioning_uri(secret: str, username: str) -> str:
    if pyotp:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.pam_mfa_issuer)
    return f"otpauth://totp/{quote(settings.pam_mfa_issuer)}:{quote(username)}?secret={secret}&issuer={quote(settings.pam_mfa_issuer)}"


def _fallback_totp(secret: str, for_time: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(for_time / 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    code = (code or "").replace(" ", "").strip()
    if not code:
        return False
    if pyotp:
        return bool(pyotp.TOTP(secret).verify(code, valid_window=valid_window))
    now = int(time.time())
    return any(hmac.compare_digest(_fallback_totp(secret, now + offset * 30), code) for offset in range(-valid_window, valid_window + 1))


def current_totp(secret: str) -> str:
    if pyotp:
        return pyotp.TOTP(secret).now()
    return _fallback_totp(secret, int(time.time()))

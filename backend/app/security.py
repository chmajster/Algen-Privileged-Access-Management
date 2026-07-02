import re
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from app.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
LINUX_USERNAME_RE = re.compile(r"[^a-z0-9_]+")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, expires_minutes: int | None = None, token_type: str = "access", extra: dict[str, Any] | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes or settings.jwt_expire_minutes)
    payload: dict[str, Any] = {"sub": subject, "exp": expire, "typ": token_type}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def sanitize_linux_username(username: str) -> str:
    cleaned = LINUX_USERNAME_RE.sub("_", username.lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned) or "user"
    prefixed = cleaned if cleaned.startswith("pam_") else f"pam_{cleaned}"
    return prefixed[:32]


def validate_linux_username(username: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9_]{1,32}", username))

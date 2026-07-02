import secrets

from sqlalchemy.orm import Session as DBSession

from app.models import MfaRecoveryCode, User, utcnow
from app.security import hash_password, verify_password


def generate_recovery_codes(db: DBSession, user: User, count: int = 10) -> list[str]:
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)).delete()
    codes = [secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12].upper() for _ in range(count)]
    for code in codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=hash_password(code)))
    db.flush()
    return codes


def verify_recovery_code(db: DBSession, user: User, code: str) -> bool:
    code = (code or "").strip().upper()
    if not code:
        return False
    for item in db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)).all():
        if verify_password(code, item.code_hash):
            item.used_at = utcnow()
            return True
    return False

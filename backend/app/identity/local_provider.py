import logging
import hmac
import secrets
import time

try:
    import pwd
except ImportError:  # pragma: no cover - Linux-only production provider
    pwd = None

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import User
from app.security import hash_password, verify_password


logger = logging.getLogger(__name__)


class LocalAuthenticationBackendError(RuntimeError):
    """The operating-system authentication backend could not be used."""


def validate_os_auth_backend() -> None:
    if pwd is None:
        raise LocalAuthenticationBackendError("the pwd module is unavailable")
    try:
        import pam
        pam.pam()
    except (ImportError, OSError, AttributeError) as exc:
        raise LocalAuthenticationBackendError(f"PAM initialization failed: {type(exc).__name__}: {exc}") from exc


def _admin_usernames() -> set[str]:
    return {item.strip() for item in settings.pam_os_admin_users.split(",") if item.strip()}

def _is_os_admin(username: str) -> bool:
    if username in _admin_usernames():
        return True
    try:
        import grp
        for group in ["sudo", "wheel", "admin"]:
            try:
                g = grp.getgrnam(group)
                if username in g.gr_mem:
                    return True
            except KeyError:
                pass
    except ImportError:
        pass
    return False


def authenticate_shadow_account(username: str, password: str) -> bool | None:
    """Verify a local shadow password when the service can read /etc/shadow.

    ``None`` means that the shadow backend is unavailable and PAM should be
    attempted. A definite rejection is returned as ``False`` and must not fall
    through to another password backend.
    """
    try:
        import crypt
        import spwd
    except ImportError:  # pragma: no cover - platform dependent
        return None

    try:
        entry = spwd.getspnam(username)
    except PermissionError:
        return None
    except KeyError:
        return False
    except OSError as exc:
        logger.warning("Cannot read shadow entry for user=%s: %s", username, exc)
        return None

    password_hash = entry.sp_pwdp or ""
    if not password_hash or password_hash.startswith(("!", "*")):
        return False

    today = int(time.time() // 86400)
    if entry.sp_expire >= 0 and today >= entry.sp_expire:
        return False
    if entry.sp_lstchg >= 0 and entry.sp_max >= 0 and today >= entry.sp_lstchg + entry.sp_max:
        return False

    candidate = crypt.crypt(password, password_hash)
    return bool(candidate) and hmac.compare_digest(candidate, password_hash)


def authenticate_os_account(username: str, password: str) -> bool:
    shadow_result = authenticate_shadow_account(username, password)
    if shadow_result is not None:
        return shadow_result

    validate_os_auth_backend()
    try:
        import pam
        authenticator = pam.pam()
        authenticated = bool(authenticator.authenticate(username, password, service=settings.pam_os_pam_service))
        if not authenticated:
            logger.warning(
                "Linux PAM rejected user=%s service=%s code=%s reason=%s",
                username,
                settings.pam_os_pam_service,
                getattr(authenticator, "code", "unknown"),
                getattr(authenticator, "reason", "unknown"),
            )
        return authenticated
    except Exception as exc:
        raise LocalAuthenticationBackendError(f"PAM authentication call failed: {type(exc).__name__}: {exc}") from exc


def _os_account(username: str):
    if pwd is None:
        raise LocalAuthenticationBackendError("Operating-system account database is unavailable")
    try:
        return pwd.getpwnam(username)
    except KeyError:
        return None


def _available_email(db: DBSession, username: str) -> str:
    base = f"{username}@localhost.localdomain"
    if not db.query(User).filter(User.email == base).first():
        return base
    suffix = 1
    while db.query(User).filter(User.email == f"{username}+{suffix}@localhost.localdomain").first():
        suffix += 1
    return f"{username}+{suffix}@localhost.localdomain"


def _provision_os_user(db: DBSession, username: str, account) -> User:
    user = User(
        username=username,
        email=_available_email(db, username),
        password_hash=hash_password(secrets.token_urlsafe(32)),
        role="admin" if _is_os_admin(username) else "user",
        is_active=True,
        auth_provider="local_os",
        external_id=f"uid:{account.pw_uid}",
        display_name=(account.pw_gecos or username).split(",", 1)[0],
        email_verified=False,
        mfa_required=False,
    )
    db.add(user)
    db.flush()
    return user


def authenticate_local_database(db: DBSession, username: str, password: str) -> tuple[User | None, list[dict]]:
    user = db.query(User).filter(User.username == username).first()
    if not user or user.auth_provider not in {"local", "local_db", "local_os"} or not verify_password(password, user.password_hash):
        return None, []
    return user, [{"name": "application-database", "source": "local_db"}]


def authenticate_local_os(db: DBSession, username: str, password: str) -> tuple[User | None, list[dict]]:
    account = _os_account(username)
    if account is None or not authenticate_os_account(username, password):
        return None, []

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        if not settings.pam_os_auto_provision:
            return None, []
        user = _provision_os_user(db, username, account)
    else:
        if user.auth_provider not in {"local", "local_db", "local_os"}:
            return None, []
        user.auth_provider = "local_os"
        user.external_id = f"uid:{account.pw_uid}"
        user.display_name = user.display_name or (account.pw_gecos or username).split(",", 1)[0]
        if _is_os_admin(username):
            user.role = "admin"
    return user, [{"name": "linux-local", "source": "pam"}]


def authenticate_local(db: DBSession, username: str, password: str) -> tuple[User | None, list[dict]]:
    """Compatibility backend for clients still sending provider=local."""
    if settings.pam_local_auth_mode == "database":
        return authenticate_local_database(db, username, password)
    return authenticate_local_os(db, username, password)

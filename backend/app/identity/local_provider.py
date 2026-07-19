import secrets

try:
    import pwd
except ImportError:  # pragma: no cover - Linux-only production provider
    pwd = None

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import User
from app.security import hash_password, verify_password


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


def authenticate_os_account(username: str, password: str) -> bool:
    validate_os_auth_backend()
    try:
        import pam
        authenticator = pam.pam()
        return bool(authenticator.authenticate(username, password, service=settings.pam_os_pam_service))
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
        role="admin" if username in _admin_usernames() else "user",
        is_active=True,
        auth_provider="local",
        external_id=f"uid:{account.pw_uid}",
        display_name=(account.pw_gecos or username).split(",", 1)[0],
        email_verified=False,
        mfa_required=username in _admin_usernames(),
    )
    db.add(user)
    db.flush()
    return user


def authenticate_local(db: DBSession, username: str, password: str) -> tuple[User | None, list[dict]]:
    if settings.pam_local_auth_mode == "database":
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            return None, []
        return user, []

    account = _os_account(username)
    if account is None or not authenticate_os_account(username, password):
        return None, []

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        if not settings.pam_os_auto_provision:
            return None, []
        user = _provision_os_user(db, username, account)
    else:
        if user.auth_provider != "local":
            return None, []
        user.auth_provider = "local"
        user.external_id = f"uid:{account.pw_uid}"
        user.display_name = user.display_name or (account.pw_gecos or username).split(",", 1)[0]
        if username in _admin_usernames():
            user.role = "admin"
            user.mfa_required = True
    return user, [{"name": "linux-local", "source": "pam"}]

import argparse
import os
import sys

from sqlalchemy.orm import Session

from app.database import SessionLocal, init_db
from app.models import User, utcnow
from app.security import hash_password


def ensure_admin_user(db: Session, username: str, email: str, password: str, update_password: bool = False) -> tuple[User, bool]:
    email_owner = db.query(User).filter(User.email == email, User.username != username).first()
    if email_owner:
        raise ValueError(f"email {email} is already used by {email_owner.username}")

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        existing.email = email or existing.email
        existing.role = "admin"
        existing.is_active = True
        existing.auth_provider = "local_db"
        existing.mfa_required = True
        if update_password:
            existing.password_hash = hash_password(password)
            existing.last_password_change_at = utcnow()
        db.commit()
        db.refresh(existing)
        return existing, False

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
        auth_provider="local_db",
        email_verified=True,
        mfa_required=True,
        last_password_change_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, True


def parser() -> argparse.ArgumentParser:
    item = argparse.ArgumentParser(description="Create or update the first local admin account.")
    item.add_argument("--username", default=os.getenv("PAM_DEFAULT_ADMIN_USER", "admin"))
    item.add_argument("--email", default=os.getenv("PAM_DEFAULT_ADMIN_EMAIL", "admin@example.local"))
    item.add_argument("--password", default=os.getenv("PAM_DEFAULT_ADMIN_PASSWORD"))
    item.add_argument("--update-password", action="store_true")
    return item


def main() -> int:
    args = parser().parse_args()
    if not args.password:
        print("ERROR: admin password is required", file=sys.stderr)
        return 2
    if len(args.password) < 6:
        print("ERROR: admin password must have at least 6 characters", file=sys.stderr)
        return 2

    init_db()
    db = SessionLocal()
    try:
        user, created = ensure_admin_user(db, args.username, args.email, args.password, update_password=args.update_password)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
    action = "created" if created else "updated"
    print(f"Admin account {action}: {user.username} <{user.email}>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

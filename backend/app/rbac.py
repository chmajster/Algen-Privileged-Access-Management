from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Permission, RolePermission, User


PERMISSIONS = {
    "resources.view", "resources.create", "resources.update", "resources.delete",
    "resources.test_connection", "access.request", "access.approve", "sessions.launch",
    "sessions.view_own", "sessions.view_group", "sessions.terminate", "recordings.view",
    "recordings.download", "session_events.export",
}
ROLE_PERMISSIONS = {
    "admin": PERMISSIONS,
    "operator": {"resources.view", "resources.test_connection", "access.request", "access.approve",
                 "sessions.launch", "sessions.view_own", "sessions.view_group", "sessions.terminate",
                 "recordings.view", "recordings.download", "session_events.export"},
    "user": {"resources.view", "access.request", "sessions.launch", "sessions.view_own"},
}


def seed_access_control(db: Session) -> None:
    for code in sorted(PERMISSIONS):
        permission = db.query(Permission).filter_by(code=code).first()
        if not permission:
            permission = Permission(code=code, description=code.replace(".", " ").title())
            db.add(permission); db.flush()
        for role, codes in ROLE_PERMISSIONS.items():
            if code in codes and not db.query(RolePermission).filter_by(role=role, permission_id=permission.id).first():
                db.add(RolePermission(role=role, permission_id=permission.id, allowed=True))
    db.commit()


def has_permission(db: Session, user: User, code: str) -> bool:
    return db.query(RolePermission).join(Permission).filter(
        RolePermission.role == user.role, Permission.code == code, RolePermission.allowed.is_(True)
    ).first() is not None


def require_permission(code: str):
    def dependency(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if not has_permission(db, user, code):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {code}")
        return user
    return dependency

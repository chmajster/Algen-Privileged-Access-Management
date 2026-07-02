from sqlalchemy.orm import Session as DBSession

from app.models import User
from app.security import verify_password


def authenticate_local(db: DBSession, username: str, password: str) -> tuple[User | None, list[dict]]:
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return None, []
    return user, []

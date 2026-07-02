from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.models import AccessGrant, AccessRequest, User
from app.security import hash_password


router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[schemas.UserOut])
def list_users(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=schemas.UserOut)
def create_user(payload: schemas.UserCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
        ssh_public_key=payload.ssh_public_key,
        mfa_enabled=payload.mfa_enabled,
        mfa_required=payload.mfa_required,
        risk_level=payload.risk_level,
        last_risk_score=payload.last_risk_score,
        auth_provider=payload.auth_provider,
        external_id=payload.external_id,
        display_name=payload.display_name,
        email_verified=payload.email_verified,
    )
    db.add(user)
    db.flush()
    write_audit(db, "user.created", f"Created user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


@router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, payload: schemas.UserUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    data = payload.model_dump(exclude_unset=True)
    if current_user.role != "admin":
        data.pop("role", None)
        data.pop("is_active", None)
        data.pop("mfa_enabled", None)
        data.pop("mfa_required", None)
        data.pop("risk_level", None)
        data.pop("last_risk_score", None)
        data.pop("auth_provider", None)
        data.pop("external_id", None)
        data.pop("display_name", None)
        data.pop("email_verified", None)
    if "password" in data:
        user.password_hash = hash_password(data.pop("password"))
    for key, value in data.items():
        setattr(user, key, value)
    write_audit(db, "user.updated", f"Updated user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", response_model=schemas.Message)
def delete_user(user_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    linked = db.query(AccessGrant).filter(AccessGrant.user_id == user_id).count() + db.query(AccessRequest).filter(AccessRequest.user_id == user_id).count()
    if linked:
        user.is_active = False
        message = "User deactivated because linked records exist"
    else:
        user.is_active = False
        message = "User deactivated"
    write_audit(db, "user.deactivated", f"Deactivated user {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    return {"message": message}


@router.put("/{user_id}/ssh-key", response_model=schemas.UserOut)
def update_ssh_key(user_id: int, payload: schemas.SshKeyUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    user.ssh_public_key = payload.ssh_public_key
    write_audit(db, "user.ssh_key_updated", f"Updated SSH key for {user.username}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(user)
    return user

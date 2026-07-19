from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.models import Secret, SecretAccessLog, SecretVersion, Server, User
from app.mfa.step_up import require_step_up
from app.vault.audit import write_secret_access_log
from app.vault.external_vault import ExternalVaultBackend
from app.vault.file_reference import FileReferenceBackend
from app.vault.local_encrypted import LocalEncryptedBackend
from app.vault.rotation import rotate_secret_value
from app.rbac import active_memberships, has_permission, is_global_admin, normalized_role, permitted_server_ids


router = APIRouter(prefix="/api/secrets", tags=["secrets"])


def _backend(db: DBSession, backend_type: str):
    if backend_type == "file_reference":
        return FileReferenceBackend(db)
    if backend_type == "external_vault":
        return ExternalVaultBackend(db)
    return LocalEncryptedBackend(db)


def _secret_out(secret: Secret) -> dict:
    return schemas.SecretOut.model_validate(secret).model_dump()


def _get_secret(db: DBSession, secret_id: int) -> Secret:
    secret = db.get(Secret, secret_id)
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    return secret


def _visible_secret_ids(db: DBSession, user: User) -> set[int] | None:
    if is_global_admin(user):
        return None
    memberships = active_memberships(db, user)
    if normalized_role(user.role) == "operator" and any(item.group.name == "Legacy compatibility" for item in memberships):
        return None
    if not any(has_permission(db, user, "secrets.use", group_id=item.server_group_id) for item in memberships):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing secrets.use permission")
    server_ids = permitted_server_ids(db, user, "secrets.use") or set()
    if not server_ids:
        return set()
    rows = db.query(Server.secret_ref_id, Server.gateway_secret_ref_id, Server.ssh_auth_secret_id).filter(Server.id.in_(server_ids)).all()
    return {secret_id for row in rows for secret_id in row if secret_id is not None}


def _visible_secret(db: DBSession, user: User, secret_id: int) -> Secret:
    secret = _get_secret(db, secret_id)
    ids = _visible_secret_ids(db, user)
    if ids is not None and secret_id not in ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    return secret


@router.get("", response_model=list[schemas.SecretOut])
def list_secrets(current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    ids = _visible_secret_ids(db, current_user)
    query = db.query(Secret)
    if ids is not None:
        query = query.filter(Secret.id.in_(ids))
    return [_secret_out(item) for item in query.order_by(Secret.created_at.desc()).all()]


@router.post("", response_model=schemas.SecretOut)
def create_secret(payload: schemas.SecretCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    metadata = payload.model_dump(exclude={"value"})
    metadata["actor_id"] = current_user.id
    secret = _backend(db, payload.backend_type).create_secret(payload.name, payload.secret_type, payload.value or payload.file_path, metadata)
    secret.expires_at = payload.expires_at
    write_secret_access_log(db, action="secret_created", secret_id=secret.id, user_id=current_user.id, source_ip=source_ip(request), message="Secret created from API")
    db.commit()
    db.refresh(secret)
    return _secret_out(secret)


@router.get("/{secret_id}", response_model=schemas.SecretOut)
def get_secret(secret_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    return _secret_out(_visible_secret(db, current_user, secret_id))


@router.put("/{secret_id}", response_model=schemas.SecretOut)
def update_secret(secret_id: int, payload: schemas.SecretUpdate, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    metadata = payload.model_dump(exclude_none=True, exclude={"value"})
    metadata["actor_id"] = current_user.id
    updated = _backend(db, secret.backend_type).update_secret(secret_id, payload.value, metadata)
    write_secret_access_log(db, action="secret_updated", secret_id=secret.id, user_id=current_user.id, source_ip=source_ip(request), message="Secret updated from API")
    db.commit()
    db.refresh(updated)
    return _secret_out(updated)


@router.delete("/{secret_id}", response_model=schemas.Message)
def delete_secret(secret_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    secret.status = "revoked"
    write_secret_access_log(db, action="secret_deleted", secret_id=secret.id, user_id=current_user.id, source_ip=source_ip(request), message="Secret revoked via delete API")
    db.commit()
    return {"message": "secret revoked"}


@router.post("/{secret_id}/disable", response_model=schemas.SecretOut)
def disable_secret(secret_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    item = _backend(db, secret.backend_type).disable_secret(secret_id)
    write_secret_access_log(db, action="secret_disabled", secret_id=secret.id, user_id=current_user.id, source_ip=source_ip(request), message="Secret disabled from API")
    db.commit()
    db.refresh(item)
    return _secret_out(item)


@router.post("/{secret_id}/rotate", response_model=schemas.SecretRotationJobOut)
def rotate_secret(secret_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    require_step_up(db, current_user, "rotate_secret", request, reason="Secret rotation requires MFA step-up", force=True)
    job = rotate_secret_value(db, secret, actor_id=current_user.id, reason="manual_api_rotation")
    db.commit()
    db.refresh(job)
    data = schemas.SecretRotationJobOut.model_validate(job).model_dump()
    data["secret_name"] = secret.name
    return data


@router.get("/{secret_id}/versions", response_model=list[schemas.SecretVersionOut])
def list_versions(secret_id: int, current_user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    _visible_secret(db, current_user, secret_id)
    return [schemas.SecretVersionOut.model_validate(item).model_dump() for item in db.query(SecretVersion).filter(SecretVersion.secret_id == secret_id).order_by(SecretVersion.version.desc()).all()]


@router.post("/{secret_id}/versions/{version_id}/activate", response_model=schemas.SecretVersionOut)
def activate_version(secret_id: int, version_id: int, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    version = _backend(db, secret.backend_type).activate_version(secret_id, version_id)
    db.commit()
    db.refresh(version)
    return schemas.SecretVersionOut.model_validate(version).model_dump()


@router.post("/{secret_id}/versions/{version_id}/revoke", response_model=schemas.SecretVersionOut)
def revoke_version(secret_id: int, version_id: int, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    secret = _get_secret(db, secret_id)
    version = _backend(db, secret.backend_type).revoke_version(secret_id, version_id)
    db.commit()
    db.refresh(version)
    return schemas.SecretVersionOut.model_validate(version).model_dump()


@router.get("/{secret_id}/access-logs", response_model=list[schemas.SecretAccessLogOut])
def access_logs(secret_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    _get_secret(db, secret_id)
    return [schemas.SecretAccessLogOut.model_validate(item).model_dump() for item in db.query(SecretAccessLog).filter(SecretAccessLog.secret_id == secret_id).order_by(SecretAccessLog.created_at.desc()).limit(500).all()]

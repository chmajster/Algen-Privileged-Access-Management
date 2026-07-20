from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import schemas
from app.auth import get_current_user, require_roles
from app.database import get_db
from app.models import Secret, SecretAccessLog, SecretVersion, User
from app.vault import get_vault_backend_for_secret
from app.vault.external_vault import ExternalVaultBackend
from app.vault.file_reference import FileReferenceBackend
from app.vault.local_encrypted import LocalEncryptedBackend

router=APIRouter(prefix="/api/secrets",tags=["secrets"])


def backend(db:Session,kind:str):
    return ExternalVaultBackend(db) if kind=="external_vault" else FileReferenceBackend(db) if kind=="file_reference" else LocalEncryptedBackend(db)


def get_secret(db:Session,secret_id:int)->Secret:
    item=db.get(Secret,secret_id)
    if not item: raise HTTPException(404,"Secret not found")
    return item


@router.get("",response_model=list[schemas.SecretOut])
def list_secrets(_:User=Depends(get_current_user),db:Session=Depends(get_db)): return db.query(Secret).order_by(Secret.name).all()


@router.post("",response_model=schemas.SecretOut,status_code=201)
def create(payload:schemas.SecretCreate,request:Request,user:User=Depends(require_roles("admin")),db:Session=Depends(get_db)):
    data=payload.model_dump(exclude={"value","name","secret_type","backend_type","expires_at"}); data["actor_id"]=user.id
    item=backend(db,payload.backend_type).create_secret(payload.name,payload.secret_type,payload.value or payload.file_path,data); item.expires_at=payload.expires_at; db.commit(); db.refresh(item); return item


@router.get("/{secret_id}",response_model=schemas.SecretOut)
def get(secret_id:int,_:User=Depends(get_current_user),db:Session=Depends(get_db)): return get_secret(db,secret_id)


@router.put("/{secret_id}",response_model=schemas.SecretOut)
def update(secret_id:int,payload:schemas.SecretUpdate,user:User=Depends(require_roles("admin")),db:Session=Depends(get_db)):
    item=get_secret(db,secret_id); data=payload.model_dump(exclude_none=True,exclude={"value"}); data["actor_id"]=user.id
    result=get_vault_backend_for_secret(db,item).update_secret(item.id,payload.value,data); db.commit(); db.refresh(result); return result


@router.delete("/{secret_id}")
def delete(secret_id:int,_:User=Depends(require_roles("admin")),db:Session=Depends(get_db)):
    item=get_secret(db,secret_id); item.status="revoked"; db.commit(); return {"message":"Secret revoked"}


@router.get("/{secret_id}/versions",response_model=list[schemas.SecretVersionOut])
def versions(secret_id:int,_:User=Depends(get_current_user),db:Session=Depends(get_db)):
    get_secret(db,secret_id); return db.query(SecretVersion).filter_by(secret_id=secret_id).order_by(SecretVersion.version.desc()).all()


@router.get("/{secret_id}/access-logs",response_model=list[schemas.SecretAccessLogOut])
def logs(secret_id:int,_:User=Depends(require_roles("admin")),db:Session=Depends(get_db)):
    get_secret(db,secret_id); return db.query(SecretAccessLog).filter_by(secret_id=secret_id).order_by(SecretAccessLog.created_at.desc()).all()

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import require_roles
from app.database import get_db
from app.models import SecretRotationJob, User
from app.mfa.step_up import require_step_up
from app.vault.rotation import rotate_server_ssh_key, run_due_rotations


router = APIRouter(prefix="/api/secret-rotation", tags=["secret-rotation"])


def _job_out(item: SecretRotationJob) -> dict:
    data = schemas.SecretRotationJobOut.model_validate(item).model_dump()
    data["secret_name"] = item.secret.name if item.secret else None
    data["server_hostname"] = item.server.hostname if item.server else None
    return data


@router.get("/jobs", response_model=list[schemas.SecretRotationJobOut])
def list_jobs(_: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    return [_job_out(item) for item in db.query(SecretRotationJob).order_by(SecretRotationJob.created_at.desc()).limit(1000).all()]


@router.get("/jobs/{job_id}", response_model=schemas.SecretRotationJobOut)
def get_job(job_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    job = db.get(SecretRotationJob, job_id)
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rotation job not found")
    return _job_out(job)


@router.post("/run-due", response_model=schemas.Message)
def run_due(request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "rotate_secret", request, reason="Secret rotation requires MFA step-up", force=True)
    count = run_due_rotations(db)
    db.commit()
    return {"message": "due rotations completed", "detail": {"count": count}}


@router.post("/servers/{server_id}/rotate-ssh-key", response_model=schemas.SecretRotationJobOut)
def rotate_server(server_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "rotate_secret", request, reason="Secret rotation requires MFA step-up", force=True)
    job = rotate_server_ssh_key(db, server_id, actor_id=current_user.id)
    db.commit()
    db.refresh(job)
    return _job_out(job)

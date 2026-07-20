from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import require_roles, source_ip
from app.database import get_db
from app.models import Policy, User
from app.mfa.step_up import require_step_up


router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("", response_model=list[schemas.PolicyOut])
def list_policies(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    return db.query(Policy).order_by(Policy.role, Policy.environment, Policy.access_type).all()


@router.post("", response_model=schemas.PolicyOut)
def create_policy(payload: schemas.PolicyCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = Policy(**payload.model_dump())
    db.add(policy)
    db.flush()
    write_audit(db, "policy.created", f"Created policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=schemas.PolicyOut)
def update_policy(policy_id: int, payload: schemas.PolicyUpdate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, key, value)
    write_audit(db, "policy.updated", f"Updated policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", response_model=schemas.Message)
def delete_policy(policy_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    policy.enabled = False
    write_audit(db, "policy.disabled", f"Disabled policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    return {"message": "Policy disabled"}

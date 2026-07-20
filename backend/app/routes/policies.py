from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import require_roles, source_ip
from app.database import get_db
from app.models import PamPolicy, User
from app.mfa.step_up import require_step_up
from app.policy import get_all_policies


router = APIRouter(prefix="/api/policies", tags=["policies"])


@router.get("/definitions", response_model=list[schemas.PolicyDefinitionOut])
def list_policy_definitions(_: User = Depends(require_roles("admin"))):
    return get_all_policies()


@router.get("/effective", response_model=dict)
def get_effective_policies(db: Session = Depends(get_db)):
    from app.policy.resolver import resolve_effective_policies
    return resolve_effective_policies(db)


@router.get("", response_model=list[schemas.PamPolicyOut])
def list_policies(_: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    return db.query(PamPolicy).order_by(PamPolicy.priority).all()


@router.post("", response_model=schemas.PamPolicyOut)
def create_policy(payload: schemas.PamPolicyCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = PamPolicy(**payload.model_dump())
    policy.created_by_id = current_user.id
    policy.updated_by_id = current_user.id
    db.add(policy)
    db.flush()
    write_audit(db, "policy.created", f"Created policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{id}", response_model=schemas.PamPolicyOut)
def update_policy(id: int, payload: schemas.PamPolicyUpdate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = db.get(PamPolicy, id)
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, key, value)
    policy.updated_by_id = current_user.id
    write_audit(db, "policy.updated", f"Updated policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{id}", response_model=schemas.Message)
def delete_policy(id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    policy = db.get(PamPolicy, id)
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found")
    db.delete(policy)
    write_audit(db, "policy.deleted", f"Deleted policy {policy.name}", user_id=current_user.id, source_ip=source_ip(request))
    db.commit()
    return {"message": "Policy deleted"}

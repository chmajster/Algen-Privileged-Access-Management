import json
from datetime import timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session as DBSession

from app.auth import get_current_user
from app.database import get_db
from app.models import AccessWizardDraft, AccessWizardSubmission, User, utcnow
from app.rbac import has_permission
from app.wizard_schemas import (
    ConnectionTestIn,
    DraftCreate,
    DraftUpdate,
    StepValidation,
    WebDiscoveryIn,
    WizardComplete,
)
from app.wizard_service import (
    DRAFT_TTL_HOURS,
    PRESETS,
    assert_nonsensitive,
    complete_transaction,
    discover_web_login,
    draft_dict,
    test_ssh_connection,
    test_web_connection,
    validate_step,
)


router = APIRouter(prefix="/api/access-wizard", tags=["access-wizard"])


def _aware(value):
    return value.replace(tzinfo=value.tzinfo or timezone.utc)


def _authorize_mode(db: DBSession, user: User, mode: str) -> None:
    permission = "access.request" if mode == "request_access" else "servers.create"
    if mode == "assign_existing_resource" and has_permission(db, user, "access.approve"):
        return
    if not has_permission(db, user, permission):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission}")


def _owned_draft(db: DBSession, user: User, draft_id: int) -> AccessWizardDraft:
    item = db.get(AccessWizardDraft, draft_id)
    if not item or item.user_id != user.id:
        raise HTTPException(404, "Draft not found")
    if _aware(item.expires_at) <= utcnow():
        db.delete(item)
        db.commit()
        raise HTTPException(410, "Draft expired")
    return item


@router.get("/presets")
def presets(user: User = Depends(get_current_user)):
    return PRESETS


@router.post("/drafts", status_code=201)
def create_draft(payload: DraftCreate, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    _authorize_mode(db, user, payload.mode)
    try:
        assert_nonsensitive(payload.data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    from datetime import timedelta

    item = AccessWizardDraft(
        user_id=user.id,
        mode=payload.mode,
        resource_type=payload.resource_type,
        data_json=json.dumps(payload.data),
        completed_steps_json="[]",
        expires_at=utcnow() + timedelta(hours=DRAFT_TTL_HOURS),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return draft_dict(item)


@router.get("/drafts")
def list_drafts(user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    now = utcnow()
    expired = db.query(AccessWizardDraft).filter(
        AccessWizardDraft.user_id == user.id,
        AccessWizardDraft.expires_at <= now,
    ).all()
    for item in expired:
        db.delete(item)
    if expired:
        db.commit()
    return [draft_dict(item) for item in db.query(AccessWizardDraft).filter_by(user_id=user.id).order_by(AccessWizardDraft.updated_at.desc()).all()]


@router.get("/drafts/{draft_id}")
def get_draft(draft_id: int, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    return draft_dict(_owned_draft(db, user, draft_id))


@router.patch("/drafts/{draft_id}")
def update_draft(draft_id: int, payload: DraftUpdate, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    item = _owned_draft(db, user, draft_id)
    mode = payload.mode or item.mode
    _authorize_mode(db, user, mode)
    if payload.data is not None:
        try:
            assert_nonsensitive(payload.data)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        item.data_json = json.dumps(payload.data)
    item.mode = mode
    if payload.resource_type is not None:
        item.resource_type = payload.resource_type
    if payload.completed_steps is not None:
        item.completed_steps_json = json.dumps(sorted(set(payload.completed_steps)))
    from datetime import timedelta

    item.expires_at = utcnow() + timedelta(hours=DRAFT_TTL_HOURS)
    db.commit()
    db.refresh(item)
    return draft_dict(item)


@router.delete("/drafts/{draft_id}", status_code=204)
def delete_draft(draft_id: int, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    db.delete(_owned_draft(db, user, draft_id))
    db.commit()


@router.post("/validate-step")
def validate_wizard_step(payload: StepValidation, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    _authorize_mode(db, user, payload.mode)
    try:
        assert_nonsensitive(payload.data)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    errors = validate_step(payload.mode, payload.resource_type, payload.step, payload.data)
    return {"valid": not errors, "errors": errors}


@router.post("/test-connection")
async def test_connection(payload: ConnectionTestIn, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if not has_permission(db, user, "servers.test_connection"):
        raise HTTPException(403, "Missing permission: servers.test_connection")
    checks = await (
        test_ssh_connection(db, payload.connection, payload.secret_inputs)
        if payload.resource_type == "ssh"
        else test_web_connection(db, payload.resource, payload.connection, payload.secret_inputs)
    )
    return {"checks": [item.model_dump() for item in checks], "blocking": any(item.status == "error" for item in checks)}


@router.post("/discover-web-login")
async def discover(payload: WebDiscoveryIn, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if not has_permission(db, user, "servers.test_connection"):
        raise HTTPException(403, "Missing permission: servers.test_connection")
    try:
        return await discover_web_login(payload.model_dump())
    except Exception as exc:
        raise HTTPException(400, {"message": "The controlled browser could not inspect the page", "technical_detail": str(exc)[:500]}) from exc


def _all_step_errors(draft: AccessWizardDraft, data: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for step in range(1, 10):
        errors.extend(validate_step(draft.mode, draft.resource_type, step, data))
    return errors


@router.post("/complete")
async def complete(payload: WizardComplete, user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    previous = db.query(AccessWizardSubmission).filter_by(user_id=user.id, submission_key=payload.submission_key).first()
    if previous:
        return {**json.loads(previous.result_json), "duplicate": True}
    item = _owned_draft(db, user, payload.draft_id)
    _authorize_mode(db, user, item.mode)
    data = json.loads(item.data_json)
    errors = _all_step_errors(item, data)
    if errors:
        raise HTTPException(422, {"message": "The wizard contains invalid fields", "errors": errors})

    if item.mode == "create_resource":
        checks = await (
            test_ssh_connection(db, data["connection"], payload.secret_inputs)
            if item.resource_type == "ssh"
            else test_web_connection(db, data["resource"], data["connection"], payload.secret_inputs)
        )
        failures = [check for check in checks if check.status == "error"]
        warnings = [check for check in checks if check.status == "warning"]
        if failures or (warnings and not payload.accept_warnings):
            raise HTTPException(409, {
                "message": "Connection validation must pass before creation" if failures else "Accept the connection warnings to continue",
                "checks": [check.model_dump() for check in checks],
                "warnings_require_acceptance": bool(warnings and not failures),
            })
    try:
        return complete_transaction(db, user, item, payload.secret_inputs, payload.submission_key)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, {"message": str(exc)}) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, {"message": "Nic nie zostało utworzone, ponieważ transakcja nie powiodła się"}) from exc

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user
from app.database import get_db
from app.models import ServerGroup, ServerTemplate, ServerTemplateAllowedGroup, ServerTemplateDefaultGroup, User
from app.rbac import active_memberships, has_permission, is_global_admin


router = APIRouter(prefix="/api/server-templates", tags=["server-templates"])


def _group_ids(db: Session, model, template_id: int) -> list[int]:
    return [value for (value,) in db.query(model.server_group_id).filter(model.template_id == template_id).order_by(model.server_group_id).all()]


def template_out(db: Session, item: ServerTemplate) -> dict:
    return {
        **schemas.ServerTemplateOut.model_validate(item).model_dump(),
        "default_group_ids": _group_ids(db, ServerTemplateDefaultGroup, item.id),
        "allowed_group_ids": _group_ids(db, ServerTemplateAllowedGroup, item.id),
    }


def _validate_groups(db: Session, default_ids: list[int], allowed_ids: list[int]) -> None:
    all_ids = set(default_ids) | set(allowed_ids)
    if all_ids and db.query(ServerGroup).filter(ServerGroup.id.in_(all_ids), ServerGroup.enabled.is_(True)).count() != len(all_ids):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more server groups do not exist or are disabled")
    if not set(default_ids).issubset(set(allowed_ids)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Default groups must also be allowed groups")


def _replace_groups(db: Session, template_id: int, defaults: list[int], allowed: list[int]) -> None:
    db.query(ServerTemplateDefaultGroup).filter(ServerTemplateDefaultGroup.template_id == template_id).delete()
    db.query(ServerTemplateAllowedGroup).filter(ServerTemplateAllowedGroup.template_id == template_id).delete()
    for group_id in set(defaults):
        db.add(ServerTemplateDefaultGroup(template_id=template_id, server_group_id=group_id))
    for group_id in set(allowed):
        db.add(ServerTemplateAllowedGroup(template_id=template_id, server_group_id=group_id))


@router.get("", response_model=list[schemas.ServerTemplateOut])
def list_templates(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(ServerTemplate).filter(ServerTemplate.enabled.is_(True)).order_by(ServerTemplate.name).all()
    if is_global_admin(current_user):
        return [template_out(db, item) for item in items]
    member_ids = {membership.server_group_id for membership in active_memberships(db, current_user)}
    result = []
    for item in items:
        allowed = set(_group_ids(db, ServerTemplateAllowedGroup, item.id))
        usable = member_ids & allowed
        if usable and any(has_permission(db, current_user, "servers.use_template", group_id=group_id) for group_id in usable):
            result.append(template_out(db, item))
    return result


@router.post("", response_model=schemas.ServerTemplateOut, status_code=status.HTTP_201_CREATED)
def create_template(payload: schemas.ServerTemplateCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required")
    if db.query(ServerTemplate).filter(ServerTemplate.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Template name already exists")
    _validate_groups(db, payload.default_group_ids, payload.allowed_group_ids)
    item = ServerTemplate(**payload.model_dump(exclude={"default_group_ids", "allowed_group_ids"}), created_by_id=current_user.id, updated_by_id=current_user.id)
    db.add(item); db.flush()
    _replace_groups(db, item.id, payload.default_group_ids, payload.allowed_group_ids)
    write_audit(db, "server_template_created", f"Created server template {item.name}", user_id=current_user.id, object_type="server_template", object_id=item.id)
    db.commit(); db.refresh(item)
    return template_out(db, item)


@router.patch("/{template_id}", response_model=schemas.ServerTemplateOut)
def update_template(template_id: int, payload: schemas.ServerTemplateUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_global_admin(current_user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required")
    item = db.get(ServerTemplate, template_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found")
    data = payload.model_dump(exclude_unset=True)
    defaults = data.pop("default_group_ids", _group_ids(db, ServerTemplateDefaultGroup, item.id))
    allowed = data.pop("allowed_group_ids", _group_ids(db, ServerTemplateAllowedGroup, item.id))
    _validate_groups(db, defaults, allowed)
    for key, value in data.items():
        setattr(item, key, value)
    if item.host_key_policy == "manual_fingerprint" and not item.expected_host_key_fingerprint:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Manual host key policy requires a fingerprint")
    _replace_groups(db, item.id, defaults, allowed)
    item.updated_by_id = current_user.id
    write_audit(db, "server_template_updated", f"Updated server template {item.name}", user_id=current_user.id, object_type="server_template", object_id=item.id)
    db.commit(); db.refresh(item)
    return template_out(db, item)

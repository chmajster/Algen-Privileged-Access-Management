import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app import schemas
from app.auth import get_current_user, require_roles
from app.database import get_db
from app.models import PolicyRule, Server, ServerGroup, ServerGroupMember, User
from app.mfa.step_up import require_step_up
from app.policy.engine import PolicyEngine
from app.policy.rules import validate_rule_json


router = APIRouter(prefix="/api", tags=["policy-rules"])


def _rule_out(rule: PolicyRule) -> dict:
    return schemas.PolicyRuleOut.model_validate(rule).model_dump()


@router.get("/policy-rules", response_model=list[schemas.PolicyRuleOut])
def list_policy_rules(_: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    return [_rule_out(item) for item in db.query(PolicyRule).order_by(PolicyRule.priority.asc()).all()]


@router.post("/policy-rules", response_model=schemas.PolicyRuleOut)
def create_policy_rule(payload: schemas.PolicyRuleCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    try:
        validate_rule_json(payload.condition_json, payload.action_json)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    rule = PolicyRule(**payload.model_dump(), created_by=current_user.id, updated_by=current_user.id)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_out(rule)


@router.get("/policy-rules/{rule_id:int}", response_model=schemas.PolicyRuleOut)
def get_policy_rule(rule_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    rule = db.get(PolicyRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy rule not found")
    return _rule_out(rule)


@router.put("/policy-rules/{rule_id:int}", response_model=schemas.PolicyRuleOut)
def update_policy_rule(rule_id: int, payload: schemas.PolicyRuleUpdate, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    rule = db.get(PolicyRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy rule not found")
    data = payload.model_dump(exclude_unset=True)
    try:
        validate_rule_json(data.get("condition_json"), data.get("action_json"))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    for key, value in data.items():
        setattr(rule, key, value)
    rule.updated_by = current_user.id
    db.commit()
    db.refresh(rule)
    return _rule_out(rule)


@router.delete("/policy-rules/{rule_id:int}", response_model=schemas.Message)
def delete_policy_rule(rule_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    rule = db.get(PolicyRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "policy rule deleted"}


@router.post("/policy-rules/{rule_id:int}/enable", response_model=schemas.PolicyRuleOut)
def enable_policy_rule(rule_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    rule = db.get(PolicyRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy rule not found")
    rule.enabled = True
    db.commit()
    db.refresh(rule)
    return _rule_out(rule)


@router.post("/policy-rules/{rule_id:int}/disable", response_model=schemas.PolicyRuleOut)
def disable_policy_rule(rule_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    require_step_up(db, current_user, "edit_policy", request, reason="Changing security policy requires MFA step-up", force=True)
    rule = db.get(PolicyRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy rule not found")
    rule.enabled = False
    db.commit()
    db.refresh(rule)
    return _rule_out(rule)


@router.post("/policy-rules/evaluate-test", response_model=schemas.PolicyDecisionOut)
def evaluate_test(payload: schemas.PolicyEvaluateIn, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    user = db.get(User, payload.user_id)
    server = db.get(Server, payload.server_id)
    if not user or not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User or server not found")
    engine = PolicyEngine(db)
    decision = engine.evaluate_access_request(user, server, payload.access_type, payload.duration, payload.reason)
    if payload.command:
        from app.models import SessionCommand

        fake = SessionCommand(user_id=user.id, server_id=server.id, grant_id=0, session_id=0, linux_username=user.username, command=payload.command, executed_at=server.created_at, server=server)
        command_decision = engine.evaluate_command(fake)
        previous_score = decision.risk_score
        decision.risk_score = max(decision.risk_score, command_decision.risk_score)
        if command_decision.risk_score > previous_score:
            decision.severity = command_decision.severity
        decision.matched_rules.extend(command_decision.matched_rules)
        decision.actions.extend(command_decision.actions)
        if command_decision.denied:
            decision.denied = True
            decision.allowed = False
    return json.loads(decision.to_json())


@router.get("/server-groups", response_model=list[schemas.ServerGroupOut])
def list_server_groups(_: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    return [schemas.ServerGroupOut.model_validate(item).model_dump() for item in db.query(ServerGroup).order_by(ServerGroup.name).all()]


@router.post("/server-groups", response_model=schemas.ServerGroupOut)
def create_server_group(payload: schemas.ServerGroupCreate, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    group = ServerGroup(**payload.model_dump())
    db.add(group)
    db.commit()
    db.refresh(group)
    return schemas.ServerGroupOut.model_validate(group).model_dump()


@router.get("/server-groups/{group_id:int}", response_model=schemas.ServerGroupOut)
def get_server_group(group_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    group = db.get(ServerGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server group not found")
    return schemas.ServerGroupOut.model_validate(group).model_dump()


@router.put("/server-groups/{group_id:int}", response_model=schemas.ServerGroupOut)
def update_server_group(group_id: int, payload: schemas.ServerGroupUpdate, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    group = db.get(ServerGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server group not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(group, key, value)
    db.commit()
    db.refresh(group)
    return schemas.ServerGroupOut.model_validate(group).model_dump()


@router.delete("/server-groups/{group_id:int}", response_model=schemas.Message)
def delete_server_group(group_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    group = db.get(ServerGroup, group_id)
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server group not found")
    db.delete(group)
    db.commit()
    return {"message": "server group deleted"}


@router.post("/server-groups/{group_id:int}/servers/{server_id:int}", response_model=schemas.Message)
def add_group_member(group_id: int, server_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    if not db.query(ServerGroupMember).filter(ServerGroupMember.server_group_id == group_id, ServerGroupMember.server_id == server_id).first():
        db.add(ServerGroupMember(server_group_id=group_id, server_id=server_id))
    server = db.get(Server, server_id)
    if server:
        server.server_group_id = group_id
    db.commit()
    return {"message": "server added to group"}


@router.delete("/server-groups/{group_id:int}/servers/{server_id:int}", response_model=schemas.Message)
def remove_group_member(group_id: int, server_id: int, _: User = Depends(require_roles("admin")), db: DBSession = Depends(get_db)):
    member = db.query(ServerGroupMember).filter(ServerGroupMember.server_group_id == group_id, ServerGroupMember.server_id == server_id).first()
    if member:
        db.delete(member)
    server = db.get(Server, server_id)
    if server and server.server_group_id == group_id:
        server.server_group_id = None
    db.commit()
    return {"message": "server removed from group"}

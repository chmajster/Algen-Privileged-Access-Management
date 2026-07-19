from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.database import get_db
from app.models import AccessGrant, AccessRequest, Server, User
from app.mfa.step_up import has_valid_step_up, require_step_up
from app.policy.engine import PolicyEngine
from app.services import create_grant_for_request, evaluate_request_policy
from app.rbac import constraints_for_request, has_permission, is_global_admin, normalized_role, require_permission, scope_server_query


router = APIRouter(prefix="/api/access-requests", tags=["access-requests"])


def _out(item: AccessRequest) -> dict:
    return {
        **schemas.AccessRequestOut.model_validate(item).model_dump(),
        "username": item.user.username if item.user else None,
        "server_hostname": item.server.hostname if item.server else None,
    }


@router.get("", response_model=list[schemas.AccessRequestOut])
def list_requests(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(AccessRequest)
    if normalized_role(current_user.role) == "user" and not is_global_admin(current_user):
        query = query.filter(AccessRequest.user_id == current_user.id)
    elif not is_global_admin(current_user):
        query = scope_server_query(query, db, current_user, AccessRequest.server_id)
    return [_out(item) for item in query.order_by(AccessRequest.created_at.desc()).all()]


@router.post("", response_model=schemas.AccessRequestOut)
def create_request(payload: schemas.AccessRequestCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, payload.server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    require_permission(db, current_user, "access.request", server_id=server.id, conceal=True)
    constraints = constraints_for_request(db, current_user, server.id)
    if payload.requested_access_type not in constraints["allowed_access_types"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access type is not allowed by the access group")
    permission_for_type = {"limited_sudo": "access.limited_sudo", "full_sudo": "access.full_sudo"}.get(payload.requested_access_type)
    if permission_for_type:
        require_permission(db, current_user, permission_for_type, server_id=server.id)
    if payload.requested_duration_minutes > constraints["max_minutes"] or (constraints["allowed_durations"] and payload.requested_duration_minutes not in constraints["allowed_durations"]):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Requested duration exceeds access-group restrictions")
    if len(payload.reason.strip()) < constraints["min_reason_length"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Reason must contain at least {constraints['min_reason_length']} characters")
    if not constraints["time_allowed"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access is not allowed at this time")
    if constraints["require_gateway"] or constraints["deny_direct"]:
        require_permission(db, current_user, "access.connect_gateway", server_id=server.id)
    # Creating an access request is transport-neutral. Direct SSH is checked
    # only when that transport is actually selected; gateway access is checked
    # by the gateway before opening the connection.
    if constraints["command_logging"] and not server.command_logging_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Access-group policy requires command logging")
    active_count = db.query(AccessGrant).filter(AccessGrant.user_id == current_user.id, AccessGrant.server_id == server.id, AccessGrant.status == "active").count()
    if active_count >= constraints["max_concurrent_grants"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Concurrent grant limit reached")
    if not current_user.ssh_public_key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Add your SSH public key first")
    _, decision = evaluate_request_policy(db, current_user, server, payload.requested_duration_minutes, payload.requested_access_type, payload.reason)
    decision.requires_approval = decision.requires_approval or constraints["require_approval"]
    decision.requires_mfa = decision.requires_mfa or constraints["require_mfa"]
    decision.requires_gateway = decision.requires_gateway or constraints["require_gateway"] or constraints["deny_direct"]
    decision.requires_session_recording = decision.requires_session_recording or constraints["recording"]
    if decision.requires_mfa:
        context = decision.mfa_context or "access_request"
        if not current_user.mfa_enabled:
            raise HTTPException(status.HTTP_403_FORBIDDEN, {"code": "mfa_enrollment_required", "context": context, "message": decision.mfa_reason or "MFA enrollment is required"})
        if not has_valid_step_up(db, current_user, context):
            require_step_up(db, current_user, context, request, reason=decision.mfa_reason, force=True)
    item = AccessRequest(
        user_id=current_user.id,
        server_id=server.id,
        reason=payload.reason,
        requested_duration_minutes=payload.requested_duration_minutes,
        requested_access_type=payload.requested_access_type,
        status="denied" if decision.denied else "pending" if decision.requires_approval or decision.requires_mfa else "approved",
        calculated_risk_score=decision.risk_score,
        policy_decision_json=decision.to_json(),
        mfa_required=decision.requires_mfa,
        approval_required=decision.requires_approval,
        session_recording_required=decision.requires_session_recording,
        denied_by_policy=decision.denied,
    )
    db.add(item)
    db.flush()
    write_audit(db, "request.created", f"Created access request for {server.hostname}", user_id=current_user.id, server_id=server.id, request_id=item.id, source_ip=source_ip(request), metadata={"group_ids": [m.server_group_id for m in constraints["memberships"]], "decision": decision.to_json()})
    PolicyEngine(db).record_risk_event(
        decision,
        "access_request_denied" if decision.denied else "access_request_evaluated",
        decision.message,
        user_id=current_user.id,
        server_id=server.id,
        grant_id=None,
    )
    if decision.denied:
        write_audit(db, "request.denied_by_policy", decision.message, user_id=current_user.id, server_id=server.id, request_id=item.id, source_ip=source_ip(request))
    elif not decision.requires_approval and not decision.requires_mfa:
        create_grant_for_request(db, item, current_user, source_ip(request))
    db.commit()
    db.refresh(item)
    return _out(item)


@router.get("/{request_id}", response_model=schemas.AccessRequestOut)
def get_request(request_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(AccessRequest, request_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    if item.user_id != current_user.id and not is_global_admin(current_user) and not has_permission(db, current_user, "access.approve", server_id=item.server_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    return _out(item)


@router.post("/{request_id}/approve", response_model=schemas.AccessRequestOut)
def approve_request(request_id: int, payload: schemas.DecisionIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(AccessRequest, request_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    require_permission(db, current_user, "access.approve", server_id=item.server_id, conceal=True)
    if item.user_id == current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot approve your own request")
    if item.status not in {"pending", "approved"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Request cannot be approved")
    decision = PolicyEngine(db).evaluate_approval(item, current_user)
    if decision.requires_mfa:
        require_step_up(db, current_user, decision.mfa_context or "approve_high_risk_request", request, reason=decision.mfa_reason, force=True)
    if decision.denied:
        item.denied_by_policy = True
        item.policy_decision_json = decision.to_json()
        write_audit(db, "request.approval_denied_by_policy", decision.message, user_id=current_user.id, server_id=item.server_id, request_id=item.id, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, decision.message)
    item.approver_id = current_user.id
    item.approver_comment = payload.approver_comment
    item.status = "approved"
    create_grant_for_request(db, item, current_user, source_ip(request))
    PolicyEngine(db).record_risk_event(decision, "access_request_approved", f"Request {item.id} approved", user_id=item.user_id, server_id=item.server_id)
    write_audit(db, "request.approved", f"Approved request {item.id}", user_id=current_user.id, server_id=item.server_id, request_id=item.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(item)
    return _out(item)


@router.post("/{request_id}/reject", response_model=schemas.AccessRequestOut)
def reject_request(request_id: int, payload: schemas.DecisionIn, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(AccessRequest, request_id)
    if not item:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found")
    require_permission(db, current_user, "access.reject", server_id=item.server_id, conceal=True)
    if item.user_id == current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot reject your own request")
    if item.status != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Request cannot be rejected")
    item.status = "rejected"
    item.approver_id = current_user.id
    item.approver_comment = payload.approver_comment
    write_audit(db, "request.rejected", f"Rejected request {item.id}", user_id=current_user.id, server_id=item.server_id, request_id=item.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(item)
    return _out(item)

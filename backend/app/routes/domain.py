import json
import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from jose import JWTError, jwt
from sqlalchemy.orm import Session as DBSession

from app import api_schemas as api
from app.audit import write_audit
from app.auth import get_current_user, source_ip
from app.config import settings
from app.database import get_db
from app.mfa.step_up import require_step_up
from app.models import (AccessGrant, AccessProfile, AccessRequest, ConnectionProfile, PamSession,
                        AuditLog, Resource, ResourceGroup, SSHConnectionProfile, SessionArtifact, SessionEvent,
                        User, UserGroup, WebConnectionProfile, utcnow)
from app.providers import ProviderContext, provider_for
from app.providers.web import web_provider
from app.providers.ssh import ssh_provider
from app.providers.events import add_event
from app.rbac import has_permission, require_permission
from app.security import create_access_token


router = APIRouter(prefix="/api")


def as_dict(value, *extra: tuple[str, Any]) -> dict[str, Any]:
    data = {column.name: getattr(value, column.name) for column in value.__table__.columns}
    data.update(dict(extra)); return data


def profile_for(db: DBSession, resource: Resource) -> ConnectionProfile:
    profile = db.query(ConnectionProfile).filter_by(resource_id=resource.id, enabled=True).first()
    if not profile: raise HTTPException(409, "Resource has no enabled connection profile")
    return profile


def context_for(db: DBSession, session: PamSession | None = None, resource: Resource | None = None,
                grant: AccessGrant | None = None) -> ProviderContext:
    if resource is None and session is None: raise ValueError("A session or resource is required")
    resource = resource or db.get(Resource, session.resource_id)  # type: ignore[union-attr]
    if resource is None: raise ValueError("Resource not found")
    grant = grant or (db.get(AccessGrant, session.grant_id) if session else None)
    return ProviderContext(db, resource, profile_for(db, resource), grant, session)


def authorized_session(db: DBSession, user: User, session_id: int, permission: str = "sessions.view_own") -> PamSession:
    session = db.get(PamSession, session_id)
    if not session: raise HTTPException(404, "Session not found")
    if session.user_id != user.id and not has_permission(db, user, "sessions.view_group"):
        raise HTTPException(403, "Session access denied")
    if session.user_id == user.id and not has_permission(db, user, permission):
        raise HTTPException(403, f"Missing permission: {permission}")
    return session


@router.get("/resources")
def list_resources(resource_type: str | None = None, environment: str | None = None,
                   group_id: int | None = None, criticality: str | None = None,
                   _: User = Depends(require_permission("resources.view")), db: DBSession = Depends(get_db)):
    query = db.query(Resource)
    for field, value in ((Resource.resource_type, resource_type), (Resource.environment, environment),
                         (Resource.group_id, group_id), (Resource.criticality, criticality)):
        if value is not None: query = query.filter(field == value)
    return [as_dict(item, ("group_name", item.group.name if item.group else None), ("allowed_domains", (item.allowed_domains or "").split(",") if item.allowed_domains else [])) for item in query.order_by(Resource.name).all()]


@router.post("/resources", status_code=201)
def create_resource(payload: api.ResourceIn, user: User = Depends(require_permission("resources.create")), db: DBSession = Depends(get_db)):
    item = Resource(**payload.model_dump(exclude={"allowed_domains"}), allowed_domains=",".join(payload.allowed_domains))
    db.add(item); db.flush(); write_audit(db, "resource.create", f"Created resource {item.name}", user_id=user.id, resource_id=item.id); db.commit(); db.refresh(item)
    return as_dict(item, ("allowed_domains", payload.allowed_domains))


@router.get("/resources/{resource_id}")
def get_resource(resource_id: int, _: User = Depends(require_permission("resources.view")), db: DBSession = Depends(get_db)):
    item = db.get(Resource, resource_id)
    if not item: raise HTTPException(404, "Resource not found")
    return as_dict(item, ("allowed_domains", (item.allowed_domains or "").split(",") if item.allowed_domains else []))


@router.put("/resources/{resource_id}")
def update_resource(resource_id: int, payload: api.ResourceIn, user: User = Depends(require_permission("resources.update")), db: DBSession = Depends(get_db)):
    item = db.get(Resource, resource_id)
    if not item: raise HTTPException(404, "Resource not found")
    for key, value in payload.model_dump(exclude={"allowed_domains"}).items(): setattr(item, key, value)
    item.allowed_domains = ",".join(payload.allowed_domains); write_audit(db, "resource.update", f"Updated resource {item.name}", user_id=user.id, resource_id=item.id); db.commit(); return as_dict(item)


@router.delete("/resources/{resource_id}")
def delete_resource(resource_id: int, user: User = Depends(require_permission("resources.delete")), db: DBSession = Depends(get_db)):
    item = db.get(Resource, resource_id)
    if not item: raise HTTPException(404, "Resource not found")
    item.enabled = False; write_audit(db, "resource.disable", f"Disabled resource {item.name}", user_id=user.id, resource_id=item.id); db.commit(); return {"message": "Resource disabled"}


@router.get("/resource-groups")
def groups(_: User = Depends(require_permission("resources.view")), db: DBSession = Depends(get_db)): return [as_dict(i) for i in db.query(ResourceGroup).order_by(ResourceGroup.name).all()]


@router.post("/resource-groups", status_code=201)
def create_group(payload: api.ResourceGroupIn, _: User = Depends(require_permission("resources.create")), db: DBSession = Depends(get_db)):
    item = ResourceGroup(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return as_dict(item)


@router.get("/connection-profiles")
def connection_profiles(_: User = Depends(require_permission("resources.view")), db: DBSession = Depends(get_db)):
    result=[]
    for item in db.query(ConnectionProfile).all():
        data=as_dict(item)
        typed = db.query(SSHConnectionProfile).filter_by(connection_profile_id=item.id).first() or db.query(WebConnectionProfile).filter_by(connection_profile_id=item.id).first()
        if typed: data["settings"] = as_dict(typed)
        result.append(data)
    return result


@router.post("/connection-profiles", status_code=201)
def create_connection_profile(payload: api.ConnectionProfileIn, _: User = Depends(require_permission("resources.update")), db: DBSession = Depends(get_db)):
    resource = db.get(Resource, payload.resource_id)
    if not resource: raise HTTPException(404, "Resource not found")
    if db.query(ConnectionProfile).filter_by(resource_id=resource.id).first(): raise HTTPException(409, "Resource already has a connection profile")
    generic = ConnectionProfile(resource_id=resource.id, name=payload.name); db.add(generic); db.flush()
    values = payload.model_dump()
    if resource.resource_type == "ssh":
        if not values["hostname"] or not values["username"]: raise HTTPException(422, "hostname and username are required for SSH")
        values["auth_mode"] = values["auth_mode"] or "private_key"
        typed: Any = SSHConnectionProfile(connection_profile_id=generic.id, **{k: values[k] for k in ("hostname","port","username","auth_mode","secret_id","host_key_policy","expected_host_key_fingerprint","sudo_policy")})
    else:
        if not values["initial_url"]: raise HTTPException(422, "initial_url is required for web")
        values["authentication_mode"] = values["authentication_mode"] or "none"
        keys=("authentication_mode","username_secret_id","password_secret_id","auth_secret_id","username_selector","password_selector","submit_selector","success_url_pattern","success_dom_selector","header_name","cookie_name")
        typed = WebConnectionProfile(connection_profile_id=generic.id, initial_url=str(values["initial_url"]), **{k: values[k] for k in keys})
    db.add(typed); db.commit(); db.refresh(generic); return as_dict(generic, ("settings", as_dict(typed)))


@router.post("/resources/{resource_id}/test-connection")
async def test_connection(resource_id: int, user: User = Depends(require_permission("resources.test_connection")), db: DBSession = Depends(get_db)):
    resource = db.get(Resource, resource_id)
    if not resource: raise HTTPException(404, "Resource not found")
    try: result = await provider_for(resource.resource_type).test_connection(context_for(db, resource=resource))
    except Exception as exc: write_audit(db, "resource.test_connection", "Connection test failed", user_id=user.id, resource_id=resource.id, result="failure"); db.commit(); raise HTTPException(400, str(exc))
    write_audit(db, "resource.test_connection", "Connection test succeeded", user_id=user.id, resource_id=resource.id); db.commit(); return result


@router.get("/access-profiles")
def access_profiles(_: User = Depends(require_permission("resources.view")), db: DBSession = Depends(get_db)): return [as_dict(i, ("allowed_schedule", json.loads(i.allowed_schedule_json) if i.allowed_schedule_json else None)) for i in db.query(AccessProfile).all()]


@router.post("/access-profiles", status_code=201)
def create_access_profile(payload: api.AccessProfileIn, _: User = Depends(require_permission("resources.create")), db: DBSession = Depends(get_db)):
    data=payload.model_dump(exclude={"allowed_schedule"}); data["allowed_schedule_json"]=json.dumps(payload.allowed_schedule) if payload.allowed_schedule else None
    item=AccessProfile(**data); db.add(item); db.commit(); db.refresh(item); return as_dict(item)


def validate_policy(db:DBSession,user:User,resource: Resource, profile: AccessProfile, duration: int) -> None:
    if profile.resource_type and profile.resource_type != resource.resource_type: raise HTTPException(400, "Access profile does not apply to this protocol")
    if profile.resource_group_id and profile.resource_group_id != resource.group_id: raise HTTPException(400, "Access profile does not apply to this resource group")
    if profile.environment and profile.environment != resource.environment: raise HTTPException(400, "Access profile does not apply to this environment")
    if profile.criticality and profile.criticality != resource.criticality: raise HTTPException(400, "Access profile does not apply to this criticality")
    if profile.user_id and profile.user_id!=user.id: raise HTTPException(403,"Access profile does not apply to this user")
    if profile.user_group and not db.query(UserGroup).filter_by(user_id=user.id,group_name=profile.user_group).first(): raise HTTPException(403,"Access profile does not apply to this user group")
    if profile.allowed_schedule_json:
        schedule=json.loads(profile.allowed_schedule_json); now=utcnow()
        if schedule.get("weekdays") is not None and now.weekday() not in schedule["weekdays"]: raise HTTPException(403,"Access is outside the allowed schedule")
        if schedule.get("start_hour") is not None and not int(schedule["start_hour"])<=now.hour<int(schedule.get("end_hour",24)): raise HTTPException(403,"Access is outside the allowed schedule")
    if duration > profile.max_session_duration_minutes: raise HTTPException(400, "Requested duration exceeds policy maximum")


def create_grant(db: DBSession, request: AccessRequest) -> AccessGrant:
    grant=AccessGrant(request_id=request.id,user_id=request.user_id,resource_id=request.resource_id,access_profile_id=request.access_profile_id,valid_from=utcnow(),valid_to=utcnow()+timedelta(minutes=request.requested_duration_minutes),status="active")
    db.add(grant); db.flush(); return grant


@router.get("/access-requests")
def access_requests(user: User = Depends(get_current_user), db: DBSession = Depends(get_db)):
    query=db.query(AccessRequest)
    if not has_permission(db,user,"access.approve"): query=query.filter_by(user_id=user.id)
    return [as_dict(i,("resource_name",i.resource.name),("username",i.user.username)) for i in query.order_by(AccessRequest.created_at.desc()).all()]


@router.post("/access-requests", status_code=201)
def request_access(payload: api.AccessRequestIn, user: User = Depends(require_permission("access.request")), db: DBSession = Depends(get_db)):
    resource, profile=db.get(Resource,payload.resource_id),db.get(AccessProfile,payload.access_profile_id)
    if not resource or not profile or not resource.enabled: raise HTTPException(404,"Resource or access profile not found")
    validate_policy(db,user,resource,profile,payload.requested_duration_minutes)
    item=AccessRequest(user_id=user.id,**payload.model_dump(),status="pending" if profile.approval_required else "approved"); db.add(item); db.flush()
    grant=create_grant(db,item) if not profile.approval_required else None
    write_audit(db,"access.request",f"Requested access to {resource.name}",user_id=user.id,resource_id=resource.id,request_id=item.id); db.commit()
    return as_dict(item,("grant_id",grant.id if grant else None))


@router.post("/access-requests/{request_id}/approve")
def approve_request(request_id:int,payload:api.ApprovalIn,user:User=Depends(require_permission("access.approve")),db:DBSession=Depends(get_db)):
    item=db.get(AccessRequest,request_id)
    if not item or item.status!="pending": raise HTTPException(409,"Request is not pending")
    item.status="approved"; item.approver_id=user.id; item.approver_comment=payload.approver_comment; grant=create_grant(db,item)
    write_audit(db,"access.approve","Access request approved",user_id=user.id,resource_id=item.resource_id,request_id=item.id,grant_id=grant.id); db.commit(); return as_dict(grant)


@router.post("/access-requests/{request_id}/reject")
def reject_request(request_id:int,payload:api.ApprovalIn,user:User=Depends(require_permission("access.approve")),db:DBSession=Depends(get_db)):
    item=db.get(AccessRequest,request_id)
    if not item or item.status!="pending": raise HTTPException(409,"Request is not pending")
    item.status="rejected"; item.approver_id=user.id; item.approver_comment=payload.approver_comment; db.commit(); return as_dict(item)


@router.get("/access-grants")
def grants(user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    query=db.query(AccessGrant)
    if not has_permission(db,user,"access.approve"): query=query.filter_by(user_id=user.id)
    return [as_dict(i,("resource_name",i.resource.name),("resource_type",i.resource.resource_type)) for i in query.order_by(AccessGrant.valid_to.desc()).all()]


@router.post("/access-grants/{grant_id}/revoke")
async def revoke_grant(grant_id:int,payload:api.RevokeIn,user:User=Depends(require_permission("access.approve")),db:DBSession=Depends(get_db)):
    grant=db.get(AccessGrant,grant_id)
    if not grant: raise HTTPException(404,"Grant not found")
    grant.status="revoked"; grant.revoked_at=utcnow(); grant.revoke_reason=payload.reason
    for session in db.query(PamSession).filter_by(grant_id=grant.id,status="active").all(): await terminate(db,session,payload.reason,user)
    db.commit(); return as_dict(grant)


@router.get("/sessions")
def sessions(user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    query=db.query(PamSession)
    if not has_permission(db,user,"sessions.view_group"): query=query.filter_by(user_id=user.id)
    return [as_dict(i,("resource_name",i.resource.name),("username",i.user.username)) for i in query.order_by(PamSession.created_at.desc()).all()]


@router.post("/sessions", status_code=201)
def create_session(payload:api.SessionCreate,request:Request,user:User=Depends(require_permission("sessions.launch")),db:DBSession=Depends(get_db)):
    grant=db.get(AccessGrant,payload.grant_id); now=utcnow()
    if not grant or grant.user_id!=user.id or grant.status!="active" or grant.valid_to.replace(tzinfo=grant.valid_to.tzinfo or timezone.utc)<=now: raise HTTPException(403,"No active grant")
    profile=db.get(AccessProfile,grant.access_profile_id)
    if not profile: raise HTTPException(409,"Access profile is unavailable")
    maximum=min(profile.max_session_duration_minutes*60,settings.pam_web_absolute_timeout_seconds,int((grant.valid_to.replace(tzinfo=grant.valid_to.tzinfo or timezone.utc)-now).total_seconds()))
    auth_expiry=None
    try:
        raw=request.headers.get("authorization","").removeprefix("Bearer ")
        auth_expiry=datetime.fromtimestamp(jwt.get_unverified_claims(raw)["exp"],timezone.utc)
    except Exception: pass
    session=PamSession(user_id=user.id,resource_id=grant.resource_id,grant_id=grant.id,protocol=grant.resource.resource_type,source_ip=source_ip(request),idle_timeout_seconds=payload.idle_timeout_seconds or settings.pam_web_idle_timeout_seconds,absolute_timeout_seconds=maximum,authentication_expires_at=auth_expiry)
    db.add(session); db.commit(); db.refresh(session); return as_dict(session)


@router.get("/sessions/{session_id}")
def get_session(session_id:int,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    item=authorized_session(db,user,session_id); return as_dict(item,("resource",as_dict(item.resource)),("grant",as_dict(item.grant)),("request",as_dict(item.grant.request)))


@router.post("/sessions/{session_id}/launch")
async def launch_session(session_id:int,request:Request,user:User=Depends(require_permission("sessions.launch")),db:DBSession=Depends(get_db)):
    session=authorized_session(db,user,session_id); grant=session.grant; now=utcnow(); valid_to=grant.valid_to.replace(tzinfo=grant.valid_to.tzinfo or timezone.utc)
    if session.status!="created" or grant.status!="active" or valid_to<=now: raise HTTPException(409,"Session or grant is not launchable")
    policy=db.get(AccessProfile,grant.access_profile_id)
    if not policy: raise HTTPException(409,"Access profile is unavailable")
    if policy.mfa_required: require_step_up(db,user,f"session_launch:{session.id}",request,reason="MFA required to launch session",force=True)
    try: result=await provider_for(session.protocol).launch_session(context_for(db,session))
    except Exception as exc: session.status="failed"; session.termination_reason="launch_failed"; db.commit(); raise HTTPException(400,str(exc))
    session.status="active"; session.started_at=now; session.last_heartbeat_at=now; session.worker_id=f"integrated-{session.protocol}"
    result["stream_token"]=create_access_token(user.username,expires_minutes=max(1,settings.pam_web_stream_token_ttl_seconds//60),token_type="session_stream",extra={"sid":session.id})
    write_audit(db,"session.launch",f"Launched {session.protocol} session",user_id=user.id,resource_id=session.resource_id,grant_id=grant.id,session_id=session.id); db.commit(); return {**as_dict(session),**result}


async def terminate(db:DBSession,session:PamSession,reason:str,actor:User|None=None)->None:
    if session.status not in {"active","created"}: return
    await provider_for(session.protocol).terminate_session(context_for(db,session),reason)
    session.status="terminated"; session.ended_at=utcnow(); session.termination_reason=reason
    write_audit(db,"session.terminate",f"Session terminated: {reason}",user_id=actor.id if actor else None,resource_id=session.resource_id,grant_id=session.grant_id,session_id=session.id)


@router.post("/sessions/{session_id}/terminate")
async def terminate_session(session_id:int,payload:api.RevokeIn,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=authorized_session(db,user,session_id)
    if session.user_id!=user.id and not has_permission(db,user,"sessions.terminate"): raise HTTPException(403,"Termination denied")
    await terminate(db,session,payload.reason,user); db.commit(); return as_dict(session)


@router.post("/sessions/{session_id}/heartbeat")
def heartbeat(session_id:int,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=authorized_session(db,user,session_id)
    if session.status!="active": raise HTTPException(409,"Session is not active")
    session.last_heartbeat_at=utcnow(); db.commit(); return {"message":"ok"}


@router.post("/sessions/{session_id}/stream-token")
def renew_stream_token(session_id:int,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=authorized_session(db,user,session_id)
    if session.status!="active": raise HTTPException(409,"Session is not active")
    return {"stream_token":create_access_token(user.username,expires_minutes=max(1,settings.pam_web_stream_token_ttl_seconds//60),token_type="session_stream",extra={"sid":session.id})}


@router.get("/sessions/{session_id}/events")
def events(session_id:int,event_type:str|None=None,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    authorized_session(db,user,session_id); query=db.query(SessionEvent).filter_by(session_id=session_id)
    if event_type: query=query.filter_by(event_type=event_type)
    return [as_dict(i,("metadata",json.loads(i.metadata_json))) for i in query.order_by(SessionEvent.sequence_number).all()]


@router.get("/sessions/{session_id}/events/export")
def export_events(session_id:int,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=authorized_session(db,user,session_id)
    if not has_permission(db,user,"session_events.export"): raise HTTPException(403,"Missing session_events.export")
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["sequence_number","timestamp","event_type","source","sensitive","metadata_json"])
    for event in db.query(SessionEvent).filter_by(session_id=session_id).order_by(SessionEvent.sequence_number): writer.writerow([event.sequence_number,event.timestamp.isoformat(),event.event_type,event.source,event.sensitive,event.metadata_json])
    write_audit(db,"session_events.export","Session events exported",user_id=user.id,resource_id=session.resource_id,session_id=session.id); db.commit()
    return Response(output.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="session-{session_id}-events.csv"'})


@router.get("/sessions/{session_id}/artifacts")
def artifacts(session_id:int,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    authorized_session(db,user,session_id)
    if not has_permission(db,user,"recordings.view"): raise HTTPException(403,"Missing recordings.view")
    return [{k:v for k,v in as_dict(i).items() if k!="storage_path"} for i in db.query(SessionArtifact).filter_by(session_id=session_id).all()]


@router.get("/audit-logs")
def audit_logs(user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    if user.role!="admin": raise HTTPException(403,"Audit logs require administrator role")
    return [as_dict(item) for item in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(1000).all()]


def recording_access(db:DBSession,user:User,session_id:int,request:Request,permission:str)->PamSession:
    session=authorized_session(db,user,session_id)
    if not has_permission(db,user,permission): raise HTTPException(403,f"Missing {permission}")
    if user.role in {"admin","operator"}: require_step_up(db,user,"recording_access",request,reason="MFA step-up required for recording access",force=True)
    return session


def safe_artifact_path(artifact:SessionArtifact)->Path:
    path=Path(artifact.storage_path).resolve(); root=Path(settings.pam_artifact_dir).resolve()
    if not path.is_relative_to(root) or not path.is_file(): raise HTTPException(404,"Artifact file is unavailable")
    return path


@router.get("/sessions/{session_id}/artifacts/{artifact_id}/play")
def play_artifact(session_id:int,artifact_id:int,request:Request,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=recording_access(db,user,session_id,request,"recordings.view"); artifact=db.get(SessionArtifact,artifact_id)
    if not artifact or artifact.session_id!=session.id: raise HTTPException(404,"Artifact not found")
    write_audit(db,"recording.view","Recording viewed",user_id=user.id,resource_id=session.resource_id,session_id=session.id,object_type="session_artifact",object_id=artifact.id); db.commit()
    return FileResponse(safe_artifact_path(artifact),media_type=artifact.mime_type)


@router.get("/sessions/{session_id}/artifacts/{artifact_id}/download")
def download_artifact(session_id:int,artifact_id:int,request:Request,user:User=Depends(get_current_user),db:DBSession=Depends(get_db)):
    session=recording_access(db,user,session_id,request,"recordings.download"); artifact=db.get(SessionArtifact,artifact_id)
    if not artifact or artifact.session_id!=session.id: raise HTTPException(404,"Artifact not found")
    write_audit(db,"recording.download","Recording downloaded",user_id=user.id,resource_id=session.resource_id,session_id=session.id,object_type="session_artifact",object_id=artifact.id); db.commit()
    path=safe_artifact_path(artifact); return FileResponse(path,media_type=artifact.mime_type,filename=path.name)


def verify_stream_token(token:str,session_id:int)->dict[str,Any]:
    try: payload=jwt.decode(token,settings.secret_key,algorithms=[settings.jwt_algorithm])
    except JWTError as exc: raise HTTPException(401,"Invalid stream token") from exc
    if payload.get("typ")!="session_stream" or payload.get("sid")!=session_id: raise HTTPException(401,"Stream token is not valid for this session")
    return payload


@router.post("/web-sessions/{session_id}/input")
async def browser_input(session_id:int,payload:api.SessionInput,db:DBSession=Depends(get_db)):
    claims=verify_stream_token(payload.token,session_id); session=db.get(PamSession,session_id)
    if not session or session.protocol!="web" or session.status!="active" or session.user.username!=claims.get("sub"): raise HTTPException(403,"Web session is unavailable")
    try: result=await web_provider.handle_input(context_for(db,session),payload.event)
    except ValueError as exc: raise HTTPException(400,str(exc))
    session.last_heartbeat_at=utcnow(); db.commit(); return {"message":"ok",**result}


@router.post("/web-sessions/{session_id}/upload")
async def browser_upload(session_id:int,token:str=Form(...),selector:str=Form(...),file:UploadFile=File(...),db:DBSession=Depends(get_db)):
    claims=verify_stream_token(token,session_id); session=db.get(PamSession,session_id)
    if not session or session.protocol!="web" or session.status!="active" or session.user.username!=claims.get("sub"): raise HTTPException(403,"Web session is unavailable")
    policy=db.get(AccessProfile,session.grant.access_profile_id); limit=policy.max_upload_bytes if policy else 0
    data=await file.read(limit+1)
    try: await web_provider.handle_upload(context_for(db,session),selector,file.filename or "upload.bin",data)
    except ValueError as exc: raise HTTPException(400,str(exc))
    session.last_heartbeat_at=utcnow(); db.commit(); return {"message":"uploaded","size_bytes":len(data)}


@router.websocket("/web-sessions/{session_id}/stream")
async def browser_stream(websocket:WebSocket,session_id:int,token:str=Query(...)):
    try: claims=verify_stream_token(token,session_id)
    except HTTPException:
        await websocket.close(code=4401); return
    db=next(get_db())
    try:
        session=db.get(PamSession,session_id); runtime=web_provider.runtimes.get(session_id)
        if not session or session.protocol!="web" or session.status!="active" or session.user.username!=claims.get("sub") or not runtime:
            await websocket.close(code=4403); return
        await websocket.accept()
        expires_at=datetime.fromtimestamp(claims["exp"],timezone.utc)
        while session_id in web_provider.runtimes:
            remaining=(expires_at-utcnow()).total_seconds()
            if remaining<=0: await websocket.close(code=4401); return
            try: frame=await __import__("asyncio").wait_for(runtime.frames.get(),timeout=min(remaining,5))
            except __import__("asyncio").TimeoutError: continue
            await websocket.send_json(frame)
    except WebSocketDisconnect: pass
    finally: db.close()


@router.websocket("/ssh-sessions/{session_id}/stream")
async def ssh_stream(websocket:WebSocket,session_id:int,token:str=Query(...)):
    try: claims=verify_stream_token(token,session_id)
    except HTTPException:
        await websocket.close(code=4401); return
    db=next(get_db())
    try:
        session=db.get(PamSession,session_id); client=ssh_provider.clients.get(session_id)
        if not session or session.protocol!="ssh" or session.status!="active" or session.user.username!=claims.get("sub") or not client:
            await websocket.close(code=4403); return
        await websocket.accept(); channel=client.invoke_shell(term="xterm-256color",width=120,height=36); expires_at=datetime.fromtimestamp(claims["exp"],timezone.utc)
        async def output():
            while not channel.closed:
                if channel.recv_ready(): await websocket.send_bytes(await __import__("asyncio").to_thread(channel.recv,32768))
                else: await __import__("asyncio").sleep(.02)
        task=__import__("asyncio").create_task(output())
        try:
            while True:
                remaining=(expires_at-utcnow()).total_seconds()
                if remaining<=0: await websocket.close(code=4401); break
                message=await __import__("asyncio").wait_for(websocket.receive(),timeout=remaining)
                if message.get("bytes"): channel.send(message["bytes"])
                elif message.get("text"): channel.send(message["text"].encode())
                submitted=message.get("bytes") or (message.get("text") or "").encode()
                if b"\n" in submitted or b"\r" in submitted:
                    add_event(db,session,"command_executed","ssh",{"input_submitted":True})
                session.last_heartbeat_at=utcnow(); db.commit()
        finally: task.cancel(); channel.close()
    except WebSocketDisconnect: pass
    finally: db.close()

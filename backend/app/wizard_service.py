import asyncio
import base64
import hashlib
import json
import re
import socket
from datetime import datetime
from io import StringIO
from typing import Any
from urllib.parse import urlsplit,urlunsplit

import paramiko
from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.models import (AccessAssignment,AccessPolicy,AccessProfile,AccessRequest,
                        AccessWizardDraft,AccessWizardSubmission,ConnectionProfile,
                        Resource,SSHConnectionProfile,Secret,User,WebConnectionProfile)
from app.providers.web import web_provider
from app.providers.web_security import NavigationGuard,UnsafeNavigation
from app.vault import get_vault_backend_for_secret
from app.vault.local_encrypted import LocalEncryptedBackend
from app.wizard_schemas import CheckResult,SecretInput


DRAFT_TTL_HOURS=24
SENSITIVE_DRAFT_KEYS={"password","secret_value","credential","private_key","token","authorization","cookie_value","plaintext","secret_inputs"}
PRESETS={
    "ssh_terminal":{"resource_type":"ssh","access_option":"terminal_only","connection":{"port":22,"host_key_policy":"strict","sudo_mode":"none","gateway_enabled":True,"direct_access_enabled":False},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"idle_timeout_minutes":15,"maximum_duration_minutes":60}},
    "ssh_limited_sudo":{"resource_type":"ssh","access_option":"limited_sudo","connection":{"port":22,"host_key_policy":"strict","sudo_mode":"limited","gateway_enabled":True,"direct_access_enabled":False},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"maximum_duration_minutes":60}},
    "ssh_full_sudo":{"resource_type":"ssh","access_option":"full_sudo","connection":{"port":22,"host_key_policy":"strict","sudo_mode":"full","gateway_enabled":True,"direct_access_enabled":False},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"maximum_duration_minutes":30}},
    "web_no_auth":{"resource_type":"web","access_option":"standard","connection":{"authentication_type":"none","allow_downloads":False,"allow_uploads":False,"clipboard_policy":"deny","record_video":True,"record_trace":True,"record_events":True},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"maximum_duration_minutes":60}},
    "web_form":{"resource_type":"web","access_option":"standard","connection":{"authentication_type":"form","allow_downloads":False,"allow_uploads":False,"clipboard_policy":"deny","record_video":True,"record_trace":True,"record_events":True},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"maximum_duration_minutes":60}},
    "web_manual":{"resource_type":"web","access_option":"standard","connection":{"authentication_type":"manual","allow_downloads":False,"allow_uploads":False,"clipboard_policy":"deny","record_video":True,"record_trace":True,"record_events":True},"policy":{"require_approval":True,"require_mfa":True,"require_recording":True,"record_events":True,"maximum_duration_minutes":60}},
    "custom":{"resource_type":None,"access_option":"custom","connection":{},"policy":{}},
}


def assert_nonsensitive(value:Any,path:str="data")->None:
    if isinstance(value,dict):
        for key,item in value.items():
            normalized=str(key).lower()
            if normalized in SENSITIVE_DRAFT_KEYS or normalized.endswith("_secret_value"):
                raise ValueError(f"Plaintext secret field is not allowed in drafts: {path}.{key}")
            assert_nonsensitive(item,f"{path}.{key}")
    elif isinstance(value,list):
        for index,item in enumerate(value): assert_nonsensitive(item,f"{path}[{index}]")


def draft_dict(draft:AccessWizardDraft)->dict[str,Any]:
    return {"id":draft.id,"mode":draft.mode,"resource_type":draft.resource_type,"data":json.loads(draft.data_json),"completed_steps":json.loads(draft.completed_steps_json),"expires_at":draft.expires_at,"created_at":draft.created_at,"updated_at":draft.updated_at}


def normalize_url(raw:str)->tuple[str,str]:
    value=raw.strip()
    if "://" not in value: value="https://"+value
    parsed=urlsplit(value)
    if parsed.scheme.lower() not in {"http","https"}: raise ValueError("Only HTTP and HTTPS URLs are allowed")
    if not parsed.hostname or parsed.username or parsed.password: raise ValueError("Enter a valid URL without embedded credentials")
    normalized=urlunsplit((parsed.scheme.lower(),parsed.netloc.lower(),parsed.path or "/",parsed.query,""))
    return normalized,parsed.hostname.lower()


def validate_step(mode:str,resource_type:str|None,step:int,data:dict[str,Any])->list[dict[str,str]]:
    errors=[]
    def required(container:dict[str,Any],fields:list[str],prefix:str)->None:
        for field in fields:
            if container.get(field) in (None,""): errors.append({"field":f"{prefix}.{field}","message":"This field is required"})
    if step==1:
        if mode not in {"create_resource","assign_existing_resource","request_access"}: errors.append({"field":"mode","message":"Choose a wizard mode"})
        if mode=="create_resource" and resource_type not in {"ssh","web"}: errors.append({"field":"resource_type","message":"Choose SSH or web"})
    elif step==2:
        if mode=="create_resource": required(data.get("resource",{}),["name","environment","criticality"],"resource")
        else: required(data,["resource_id"],"data")
    elif step==3 and mode=="create_resource":
        connection=data.get("connection",{})
        if resource_type=="ssh":
            required(connection,["hostname","target_username"],"connection")
            port=connection.get("port",22)
            if not isinstance(port,int) or not 1<=port<=65535: errors.append({"field":"connection.port","message":"Port must be between 1 and 65535"})
        else:
            required(connection,["start_url"],"connection")
            if connection.get("start_url"):
                try: normalize_url(connection["start_url"])
                except ValueError as exc: errors.append({"field":"connection.start_url","message":str(exc)})
    elif step==4 and mode=="create_resource":
        connection=data.get("connection",{}); auth=connection.get("authentication_type","none")
        if resource_type=="ssh" and auth in {"password","private_key"} and not (connection.get("secret_ref_id") or connection.get("secret_input_key")): errors.append({"field":"connection.secret_ref_id","message":"Select or create an authentication secret"})
        if resource_type=="web" and auth=="form": required(connection,["username_selector","password_selector","submit_selector"],"connection")
    elif step==5 and mode!="request_access" and not data.get("access_profile_id"): required(data.get("access_profile",{}),["name","access_option"],"access_profile")
    elif step==6 and mode!="request_access":
        policy=data.get("policy",{}); criticality=data.get("resource",{}).get("criticality")
        disabled=[name for name in ("require_approval","require_mfa","require_recording") if criticality in {"high","critical"} and policy.get(name) is False]
        if disabled and not policy.get("control_override_justification"): errors.append({"field":"policy.control_override_justification","message":"Explain why recommended controls are disabled"})
    elif step==7 and mode!="request_access":
        if not data.get("assignments"): errors.append({"field":"assignments","message":"Assign at least one user, group, directory group, or role"})
    elif step==8:
        if mode=="request_access": required(data,["duration_minutes","justification"],"data")
        elif int(data.get("policy",{}).get("maximum_duration_minutes",0) or 0)<1: errors.append({"field":"policy.maximum_duration_minutes","message":"Maximum duration must be positive"})
    return errors


def _secret_value(db:DBSession,reference:int|None,input_key:str|None,inputs:dict[str,SecretInput])->str|None:
    if input_key:
        item=inputs.get(input_key)
        if not item: raise ValueError("A transient secret required for testing was not supplied")
        return item.value
    if reference:
        secret=db.get(Secret,reference)
        if not secret: raise ValueError("Selected secret was not found")
        return get_vault_backend_for_secret(db,secret).get_secret_value(secret.id,{"access_context":"access_wizard_test"})
    return None


def _safe_error(exc:Exception)->str:
    value=re.sub(r"(?i)(password|token|secret)=\S+",r"\1=[REDACTED]",str(exc))
    return value[:500]


def _ssh_probe(connection:dict[str,Any],secret_value:str|None)->list[CheckResult]:
    host=str(connection.get("hostname","")); port=int(connection.get("port",22)); timeout=int(connection.get("connection_timeout_seconds",10)); checks=[]
    try:
        answers=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM); checks.append(CheckResult(name="dns",status="success",message=f"Resolved {len({item[4][0] for item in answers})} address(es)"))
    except Exception as exc:
        checks.append(CheckResult(name="dns",status="error",message="The host could not be resolved",technical_detail=_safe_error(exc)))
        return checks+[CheckResult(name=name,status="skipped",message="Skipped because DNS failed") for name in ("tcp","host_key","authentication","required_privileges","session_start")]
    client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        sock=socket.create_connection((host,port),timeout=timeout); checks.append(CheckResult(name="tcp",status="success",message=f"TCP port {port} is reachable")); sock.close()
        kwargs:dict[str,Any]={"hostname":host,"port":port,"username":connection.get("target_username"),"timeout":timeout,"banner_timeout":timeout,"auth_timeout":timeout}
        auth=connection.get("authentication_type","private_key")
        if auth=="password" and secret_value: kwargs["password"]=secret_value
        elif auth=="private_key" and secret_value:
            for key_type in (paramiko.Ed25519Key,paramiko.RSAKey,paramiko.ECDSAKey):
                try: kwargs["pkey"]=key_type.from_private_key(StringIO(secret_value)); break
                except (paramiko.SSHException,ValueError): continue
            if "pkey" not in kwargs: raise ValueError("The selected private key format is invalid")
        elif auth!="agent": raise ValueError("Authentication secret is required")
        client.connect(**kwargs)
        key=client.get_transport().get_remote_server_key(); fingerprint="SHA256:"+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        expected=connection.get("expected_host_key_fingerprint")
        if expected and expected.lower()!=fingerprint.lower(): checks.append(CheckResult(name="host_key",status="error",message="Host fingerprint does not match",technical_detail=f"Received {fingerprint}"))
        elif not expected and connection.get("host_key_policy","strict")=="strict": checks.append(CheckResult(name="host_key",status="warning",message="Strict host-key policy needs a trusted known-host entry",technical_detail=f"Observed {fingerprint}"))
        else: checks.append(CheckResult(name="host_key",status="success",message="Host fingerprint validated",technical_detail=fingerprint))
        checks.append(CheckResult(name="authentication",status="success",message="Authentication succeeded"))
        transport=client.get_transport(); channel=transport.open_session(timeout=timeout); channel.close(); checks.append(CheckResult(name="session_start",status="success",message="SSH session channel opened"))
        command="sudo -n true" if connection.get("sudo_mode") in {"limited","full"} else "true"
        _,stdout,_=client.exec_command(command,timeout=timeout); code=stdout.channel.recv_exit_status()
        checks.append(CheckResult(name="required_privileges",status="success" if code==0 else "error",message="Required privileges are available" if code==0 else "Required privileges are unavailable"))
    except Exception as exc:
        existing={item.name for item in checks}
        stage="tcp" if "tcp" not in existing else "authentication"
        checks.append(CheckResult(name=stage,status="error",message="TCP connection failed" if stage=="tcp" else "SSH authentication failed",technical_detail=_safe_error(exc)))
        for name in ("host_key","authentication","required_privileges","session_start"):
            if name not in {item.name for item in checks}: checks.append(CheckResult(name=name,status="skipped",message="Skipped after an earlier failure"))
    finally: client.close()
    order={name:i for i,name in enumerate(("dns","tcp","host_key","authentication","required_privileges","session_start"))}
    return sorted(checks,key=lambda item:order[item.name])


async def test_ssh_connection(db:DBSession,connection:dict[str,Any],inputs:dict[str,SecretInput])->list[CheckResult]:
    try: value=_secret_value(db,connection.get("secret_ref_id"),connection.get("secret_input_key"),inputs)
    except Exception as exc:
        return [CheckResult(name=name,status="skipped" if name!="authentication" else "error",message="Secret validation failed" if name=="authentication" else "Skipped because the secret is unavailable",technical_detail=_safe_error(exc) if name=="authentication" else None) for name in ("dns","tcp","host_key","authentication","required_privileges","session_start")]
    return await asyncio.to_thread(_ssh_probe,connection,value)


async def _guarded_web_context(url:str,allowed:list[str],blocked:list[str],allow_private:bool):
    guard=NavigationGuard(allowed,allow_private,blocked); await guard.validate(url)
    await web_provider.semaphore.acquire(); context=None
    try:
        context=await (await web_provider._browser()).new_context(viewport={"width":1440,"height":900})
        async def route_request(route):
            try: await guard.validate(route.request.url); await route.continue_()
            except (UnsafeNavigation,OSError): await route.abort("blockedbyclient")
        await context.route("**/*",route_request)
        return context
    except Exception:
        if context: await context.close()
        web_provider.semaphore.release(); raise


async def test_web_connection(db:DBSession,resource:dict[str,Any],connection:dict[str,Any],inputs:dict[str,SecretInput])->list[CheckResult]:
    checks=[]; context=None
    try:
        url,domain=normalize_url(connection.get("start_url",connection.get("initial_url","")))
        allowed=connection.get("allowed_domains") or resource.get("allowed_domains") or [domain]
        checks.append(CheckResult(name="url_validation",status="success",message=f"Normalized URL: {url}"))
        guard=NavigationGuard(allowed,bool(connection.get("allow_private_network",resource.get("allow_private_network",False))),connection.get("blocked_domains",[]))
        addresses=await guard.validate(url); checks.append(CheckResult(name="dns_resolution",status="success",message=f"Resolved {len(addresses)} safe address(es)")); checks.append(CheckResult(name="ssrf_policy",status="success",message="Destination passed SSRF policy")); checks.append(CheckResult(name="allowed_domains",status="success",message="Domain policy accepted the destination"))
        checks.append(CheckResult(name="browser_worker",status="success" if web_provider.healthy() else "error",message="Browser worker is available" if web_provider.healthy() else "Browser worker is unavailable"))
        context=await _guarded_web_context(url,allowed,connection.get("blocked_domains",[]),bool(connection.get("allow_private_network",resource.get("allow_private_network",False))))
        await context.tracing.start(screenshots=True,snapshots=True); page=await context.new_page(); response=await page.goto(url,wait_until="domcontentloaded",timeout=int(connection.get("login_timeout_seconds",30))*1000)
        if not response: raise ValueError("The page did not return a response")
        redirect_message=f"Page loaded with HTTP {response.status}"
        if url.startswith("http://") and page.url.startswith("https://"): redirect_message+=" and redirected securely to HTTPS"
        checks.append(CheckResult(name="page_load",status="success" if response.status<400 else "error",message=redirect_message,technical_detail=page.url))
        auth=connection.get("authentication_type","none")
        if auth=="form":
            username=_secret_value(db,connection.get("username_secret_id"),connection.get("username_secret_input_key"),inputs) or ""
            password=_secret_value(db,connection.get("password_secret_id"),connection.get("password_secret_input_key"),inputs) or ""
            await page.locator(connection["username_selector"]).fill(username); await page.locator(connection["password_selector"]).fill(password); await page.locator(connection["submit_selector"]).click()
            if connection.get("success_url_pattern"): await page.wait_for_url(connection["success_url_pattern"],timeout=int(connection.get("login_timeout_seconds",30))*1000)
            if connection.get("success_dom_selector"): await page.locator(connection["success_dom_selector"]).wait_for(timeout=int(connection.get("login_timeout_seconds",30))*1000)
            checks.append(CheckResult(name="authentication",status="success",message="Form authentication and success detection passed"))
        else: checks.append(CheckResult(name="authentication",status="skipped" if auth in {"none","manual"} else "warning",message="No automatic authentication required" if auth in {"none","manual"} else "Authentication is configured and will be injected only at launch"))
        checks.append(CheckResult(name="success_detection",status="success" if auth!="form" or connection.get("success_url_pattern") or connection.get("success_dom_selector") else "warning",message="Success detection is configured" if auth!="form" or connection.get("success_url_pattern") or connection.get("success_dom_selector") else "Add a success URL pattern or page element"))
        await context.tracing.stop(); checks.append(CheckResult(name="recording_initialization",status="success",message="Browser trace initialized successfully"))
    except Exception as exc:
        existing={item.name for item in checks}; failed="url_validation" if not checks else "page_load"
        checks.append(CheckResult(name=failed,status="error",message="Web validation failed",technical_detail=_safe_error(exc)))
        for name in ("dns_resolution","ssrf_policy","allowed_domains","browser_worker","page_load","authentication","success_detection","recording_initialization"):
            if name not in existing and name!=failed: checks.append(CheckResult(name=name,status="skipped",message="Skipped after an earlier failure"))
    finally:
        if context: await context.close(); web_provider.semaphore.release()
    return checks


async def discover_web_login(payload:dict[str,Any])->dict[str,Any]:
    url,domain=normalize_url(payload["start_url"]); context=None
    try:
        context=await _guarded_web_context(url,payload.get("allowed_domains") or [domain],payload.get("blocked_domains",[]),payload.get("allow_private_network",False))
        page=await context.new_page(); await page.goto(url,wait_until="domcontentloaded",timeout=30_000)
        candidates=await page.evaluate("""() => { const esc=v=>CSS.escape(v); const stable=e=>{if(e.id)return '#'+esc(e.id); if(e.name)return e.tagName.toLowerCase()+'[name="'+CSS.escape(e.name)+'"]'; for(const a of ['data-testid','data-test','data-qa'])if(e.hasAttribute(a))return '['+a+'="'+CSS.escape(e.getAttribute(a))+'"]'; const role=e.getAttribute('role'),label=e.getAttribute('aria-label'); if(role&&label)return '[role="'+CSS.escape(role)+'"][aria-label="'+CSS.escape(label)+'"]'; const cls=[...e.classList].filter(x=>!/[0-9]{3,}/.test(x)).slice(0,2); return e.tagName.toLowerCase()+(cls.length?'.'+cls.map(esc).join('.'):'');}; return [...document.querySelectorAll('input,button,[role="button"]')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0}).map((e,index)=>({index,selector:stable(e),tag:e.tagName.toLowerCase(),type:e.type||'',name:e.name||'',role:e.getAttribute('role')||'',accessible_name:e.getAttribute('aria-label')||e.innerText?.trim().slice(0,120)||'',suggested:e.type==='password'?'password':e.tagName==='BUTTON'||e.type==='submit'?'submit':e.autocomplete==='username'||/user|email|login/i.test(e.name||e.id)?'username':'other'})); }""")
        screenshot=base64.b64encode(await page.screenshot(type="jpeg",quality=70,full_page=False)).decode()
        return {"normalized_url":page.url,"screenshot":screenshot,"mime_type":"image/jpeg","candidates":candidates,"selector_priority":["stable id","name","data-* attribute","role and accessible name","relative selector","CSS fallback"]}
    finally:
        if context: await context.close(); web_provider.semaphore.release()


def _create_secret(db:DBSession,item:SecretInput,user_id:int)->Secret:
    return LocalEncryptedBackend(db).create_secret(item.name,item.secret_type,item.value,{"actor_id":user_id,"description":"Created by access wizard","rotation_enabled":item.rotating})


def apply_security_defaults(resource:dict[str,Any],policy:dict[str,Any])->dict[str,Any]:
    result={"require_approval":True,"approval_mode":"any_approver","require_mfa":False,"require_recording":True,"record_events":True,"capture_screenshots":False,"idle_timeout_minutes":15,"default_duration_minutes":60,"maximum_duration_minutes":60,"allow_downloads":False,"allow_uploads":False,"clipboard_policy":"deny","allowed_weekdays":"0,1,2,3,4,5,6",**policy}
    criticality=resource.get("criticality","low")
    if criticality in {"high","critical"}:
        recommended={"require_approval":True,"require_mfa":True,"require_recording":True}
        for key,value in recommended.items():
            if key not in policy: result[key]=value
        if "maximum_duration_minutes" not in policy: result["maximum_duration_minutes"]=30 if criticality=="high" else 15
        disabled=[key for key in recommended if result.get(key) is False]
        if disabled and not result.get("control_override_justification"): raise ValueError("A justification is required to disable recommended controls")
    return result


def _resolve_secret(db:DBSession,connection:dict[str,Any],field:str,input_field:str,inputs:dict[str,SecretInput],user_id:int)->int|None:
    if connection.get(field): return int(connection[field])
    key=connection.get(input_field)
    if key:
        if key not in inputs: raise ValueError(f"Secret input {key} was not supplied")
        return _create_secret(db,inputs[key],user_id).id
    return None


def _before_commit_hook()->None: return None


def complete_transaction(db:DBSession,user:User,draft:AccessWizardDraft,inputs:dict[str,SecretInput],submission_key:str)->dict[str,Any]:
    existing=db.query(AccessWizardSubmission).filter_by(user_id=user.id,submission_key=submission_key).first()
    if existing: return {**json.loads(existing.result_json),"duplicate":True}
    data=json.loads(draft.data_json); mode=draft.mode
    if mode=="request_access":
        resource=db.get(Resource,int(data["resource_id"])); profile=db.get(AccessProfile,int(data["access_profile_id"]))
        if not resource or not profile: raise ValueError("Resource or access profile no longer exists")
        request=AccessRequest(user_id=user.id,resource_id=resource.id,access_profile_id=profile.id,reason=data["justification"],requested_duration_minutes=int(data["duration_minutes"]),status="pending")
        db.add(request); db.flush(); result={"mode":mode,"request_id":request.id,"resource_id":resource.id,"access_profile_id":profile.id}
        write_audit(db,"access_wizard.request",f"Requested access to {resource.name}",user_id=user.id,resource_id=resource.id,request_id=request.id)
    else:
        if mode=="create_resource":
            resource_data=data["resource"]; connection=data["connection"]
            resource=Resource(name=resource_data["name"],resource_type=draft.resource_type,environment=resource_data["environment"],criticality=resource_data.get("criticality","low"),group_id=resource_data.get("group_id"),owner=resource_data.get("owner"),description=resource_data.get("description"),enabled=True,allow_private_network=bool(connection.get("allow_private_network",False)),allowed_domains=",".join(connection.get("allowed_domains",[])))
            db.add(resource); db.flush(); generic=ConnectionProfile(resource_id=resource.id,name=connection.get("name","Default")); db.add(generic); db.flush()
            if draft.resource_type=="ssh":
                secret_id=_resolve_secret(db,connection,"secret_ref_id","secret_input_key",inputs,user.id)
                typed=SSHConnectionProfile(connection_profile_id=generic.id,hostname=connection["hostname"],port=int(connection.get("port",22)),username=connection["target_username"],administrative_username=connection.get("administrative_username"),auth_mode=connection.get("authentication_type","private_key"),secret_id=secret_id,host_key_policy=connection.get("host_key_policy","strict"),expected_host_key_fingerprint=connection.get("expected_host_key_fingerprint"),connection_timeout_seconds=int(connection.get("connection_timeout_seconds",10)),gateway_enabled=bool(connection.get("gateway_enabled",True)),direct_access_enabled=bool(connection.get("direct_access_enabled",False)),sudo_mode=connection.get("sudo_mode","none"),sudo_policy=connection.get("command_allowlist"))
            else:
                url,domain=normalize_url(connection["start_url"]); allowed=connection.get("allowed_domains") or [domain]
                typed=WebConnectionProfile(connection_profile_id=generic.id,initial_url=url,blocked_domains=",".join(connection.get("blocked_domains",[])),authentication_mode=connection.get("authentication_type","none"),username_secret_id=_resolve_secret(db,connection,"username_secret_id","username_secret_input_key",inputs,user.id),password_secret_id=_resolve_secret(db,connection,"password_secret_id","password_secret_input_key",inputs,user.id),auth_secret_id=_resolve_secret(db,connection,"auth_secret_id","auth_secret_input_key",inputs,user.id),username_selector=connection.get("username_selector"),password_selector=connection.get("password_selector"),submit_selector=connection.get("submit_selector"),success_url_pattern=connection.get("success_url_pattern"),success_dom_selector=connection.get("success_dom_selector"),header_name=connection.get("header_name"),cookie_name=connection.get("cookie_name"),login_timeout_seconds=int(connection.get("login_timeout_seconds",30)),idle_timeout_seconds=int(connection.get("idle_timeout_seconds",900)),maximum_session_duration_minutes=int(connection.get("maximum_session_duration",60)),allow_downloads=bool(connection.get("allow_downloads",False)),allow_uploads=bool(connection.get("allow_uploads",False)),clipboard_policy=connection.get("clipboard_policy","deny"),record_video=bool(connection.get("record_video",True)),record_trace=bool(connection.get("record_trace",True)),record_events=bool(connection.get("record_events",True)))
                resource.allowed_domains=",".join(allowed)
            db.add(typed)
        else:
            resource=db.get(Resource,int(data["resource_id"]))
            if not resource: raise ValueError("Selected resource no longer exists")
        policy_data=apply_security_defaults(data.get("resource",{"criticality":resource.criticality}),data.get("policy",{}))
        profile=db.get(AccessProfile,int(data["access_profile_id"])) if mode=="assign_existing_resource" and data.get("access_profile_id") else None
        if profile:
            if profile.resource_type and profile.resource_type!=resource.resource_type: raise ValueError("The selected access profile does not support this resource type")
            policy=db.query(AccessPolicy).filter_by(access_profile_id=profile.id).first()
        else:
            profile_data=data["access_profile"]
            profile=AccessProfile(name=profile_data["name"],resource_type=resource.resource_type,resource_group_id=resource.group_id,environment=resource.environment,criticality=resource.criticality,access_option=profile_data.get("access_option","standard"),max_session_duration_minutes=int(policy_data["maximum_duration_minutes"]),approval_required=bool(policy_data["require_approval"]),mfa_required=bool(policy_data["require_mfa"]),recording_required=bool(policy_data["require_recording"]),allowed_schedule_json=json.dumps({"weekdays":[int(x) for x in str(policy_data.get("allowed_weekdays","0,1,2,3,4,5,6")).split(",")],"time_ranges":policy_data.get("allowed_time_ranges",[])}),upload_policy="allow" if policy_data["allow_uploads"] else "deny",download_policy="allow" if policy_data["allow_downloads"] else "deny",clipboard_policy=policy_data["clipboard_policy"])
            db.add(profile); db.flush(); policy=AccessPolicy(access_profile_id=profile.id,require_approval=policy_data["require_approval"],approval_mode=policy_data.get("approval_mode","any_approver"),approval_group=policy_data.get("approval_group"),approval_stages_json=json.dumps(policy_data.get("approval_stages",[])),approval_expiration_minutes=int(policy_data.get("approval_expiration_minutes",1440)),require_mfa=policy_data["require_mfa"],require_recording=policy_data["require_recording"],record_events=policy_data["record_events"],capture_screenshots=policy_data["capture_screenshots"],idle_timeout_minutes=int(policy_data["idle_timeout_minutes"]),default_duration_minutes=int(policy_data["default_duration_minutes"]),maximum_duration_minutes=int(policy_data["maximum_duration_minutes"]),allow_downloads=policy_data["allow_downloads"],allow_uploads=policy_data["allow_uploads"],clipboard_policy=policy_data["clipboard_policy"],allowed_weekdays=str(policy_data.get("allowed_weekdays","0,1,2,3,4,5,6")),allowed_time_ranges_json=json.dumps(policy_data.get("allowed_time_ranges",[])),scheduled_access=bool(policy_data.get("scheduled_access",False)),control_override_justification=policy_data.get("control_override_justification")); db.add(policy)
        assignments=[]
        for item in data.get("assignments",[]):
            expires_at=item.get("expires_at")
            if isinstance(expires_at,str): expires_at=datetime.fromisoformat(expires_at.replace("Z","+00:00"))
            assignment=AccessAssignment(resource_id=resource.id,access_profile_id=profile.id,subject_type=item["subject_type"],subject_identifier=str(item["subject_identifier"]),assignment_mode=item.get("assignment_mode","request_required"),expires_at=expires_at); db.add(assignment); assignments.append(assignment)
        db.flush(); result={"mode":mode,"resource_id":resource.id,"connection_profile_id":generic.id if mode=="create_resource" else None,"access_profile_id":profile.id,"access_policy_id":policy.id if policy else None,"assignment_ids":[item.id for item in assignments]}
        write_audit(db,"access_wizard.complete",f"Created access configuration for {resource.name}",user_id=user.id,resource_id=resource.id,object_type="access_profile",object_id=profile.id,metadata={"mode":mode,"policy_summary":policy_summary(resource,policy,data.get("assignments",[])) if policy else "Existing access profile assigned","control_override_justification":policy.control_override_justification if policy else None})
    _before_commit_hook(); submission=AccessWizardSubmission(user_id=user.id,submission_key=submission_key,result_json=json.dumps(result)); db.add(submission); db.delete(draft); db.commit(); return {**result,"duplicate":False}


def policy_summary(resource:Resource,policy:AccessPolicy,assignments:list[dict[str,Any]])->str:
    subjects=", ".join(str(item.get("subject_identifier")) for item in assignments[:3]) or "Assigned users"
    action="may launch" if any(item.get("assignment_mode")=="direct_launch" for item in assignments) else "may request"
    controls=[name for enabled,name in ((policy.require_mfa,"MFA"),(policy.require_approval,"approval"),(policy.require_recording,"recording")) if enabled]
    suffix=(", ".join(controls)+" required") if controls else "no additional controls"
    return f"{subjects} {action} {policy.maximum_duration_minutes}-minute {resource.resource_type.upper()} access. {suffix.capitalize()}."

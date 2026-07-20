import asyncio
import base64
import hashlib
import json
import re
import socket
from datetime import datetime
from io import StringIO
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import paramiko
from sqlalchemy.orm import Session as DBSession

from app.audit import write_audit
from app.models import (
    AccessRequest, AccessWizardDraft, AccessWizardSubmission, Secret, Server,
    ServerGroup, ServerGroupMember, ServerGroupUserMembership, User, UserGroup,
    WebConnectionProfile,
)
from app.providers.web import web_provider
from app.providers.web_security import NavigationGuard, UnsafeNavigation
from app.vault import get_vault_backend_for_secret
from app.vault.local_encrypted import LocalEncryptedBackend
from app.wizard_schemas import CheckResult, SecretInput

DRAFT_TTL_HOURS = 24
SENSITIVE_DRAFT_KEYS = {"password", "secret_value", "credential", "private_key", "token", "authorization", "cookie_value", "plaintext", "secret_inputs"}
PRESETS = {
    "ssh_standard": {"label": "SSH — zwykły dostęp", "resource_type": "ssh", "access_option": "ssh_only", "connection": {"port": 22, "authentication_type": "private_key", "host_key_policy": "strict", "sudo_mode": "none", "gateway_enabled": True, "direct_access_enabled": False, "connection_timeout_seconds": 10}, "policy": {"require_approval": True, "require_mfa": False, "require_recording": True, "require_command_logging": True, "maximum_duration_minutes": 60}},
    "ssh_limited_sudo": {"label": "SSH — dostęp z ograniczonym sudo", "resource_type": "ssh", "access_option": "limited_sudo", "connection": {"port": 22, "authentication_type": "private_key", "host_key_policy": "strict", "sudo_mode": "limited", "gateway_enabled": True, "direct_access_enabled": False, "connection_timeout_seconds": 10}, "policy": {"require_approval": True, "require_mfa": True, "require_recording": True, "require_command_logging": True, "maximum_duration_minutes": 60}},
    "ssh_full_sudo": {"label": "SSH — pełne sudo", "resource_type": "ssh", "access_option": "full_sudo", "connection": {"port": 22, "authentication_type": "private_key", "host_key_policy": "strict", "sudo_mode": "full", "gateway_enabled": True, "direct_access_enabled": False, "connection_timeout_seconds": 10}, "policy": {"require_approval": True, "require_mfa": True, "require_recording": True, "require_command_logging": True, "maximum_duration_minutes": 30}},
    "web_no_auth": {"label": "WWW — strona bez logowania", "resource_type": "web", "access_option": "ssh_only", "connection": {"authentication_type": "none", "allow_downloads": False, "allow_uploads": False, "clipboard_policy": "deny", "popup_policy": "same_origin", "login_timeout_seconds": 30, "idle_timeout_seconds": 900, "maximum_session_duration_minutes": 60}, "policy": {"require_approval": True, "require_mfa": False, "require_recording": True, "maximum_duration_minutes": 60}},
    "web_form": {"label": "WWW — automatyczne logowanie formularzem", "resource_type": "web", "access_option": "ssh_only", "connection": {"authentication_type": "form", "allow_downloads": False, "allow_uploads": False, "clipboard_policy": "deny", "popup_policy": "same_origin", "login_timeout_seconds": 30, "idle_timeout_seconds": 900, "maximum_session_duration_minutes": 60}, "policy": {"require_approval": True, "require_mfa": True, "require_recording": True, "maximum_duration_minutes": 60}},
    "web_manual": {"label": "WWW — ręczne logowanie użytkownika", "resource_type": "web", "access_option": "ssh_only", "connection": {"authentication_type": "manual", "allow_downloads": False, "allow_uploads": False, "clipboard_policy": "deny", "popup_policy": "same_origin", "login_timeout_seconds": 30, "idle_timeout_seconds": 900, "maximum_session_duration_minutes": 60}, "policy": {"require_approval": True, "require_mfa": True, "require_recording": True, "maximum_duration_minutes": 60}},
    "custom": {"label": "Konfiguracja niestandardowa", "resource_type": None, "access_option": "ssh_only", "connection": {}, "policy": {}},
}


def _before_commit_hook() -> None:
    """Test seam used to verify that the wizard remains all-or-nothing."""


def assert_nonsensitive(value: Any, path: str = "data") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_DRAFT_KEYS or normalized.endswith("_secret_value"):
                raise ValueError(f"Plaintext secret field is not allowed in drafts: {path}.{key}")
            assert_nonsensitive(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value): assert_nonsensitive(item, f"{path}[{index}]")


def draft_dict(draft: AccessWizardDraft) -> dict[str, Any]:
    return {"id": draft.id, "mode": draft.mode, "resource_type": draft.resource_type, "data": json.loads(draft.data_json), "completed_steps": json.loads(draft.completed_steps_json), "expires_at": draft.expires_at, "created_at": draft.created_at, "updated_at": draft.updated_at}


def normalize_url(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if "://" not in value: value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}: raise ValueError("Dozwolone są wyłącznie adresy HTTP i HTTPS")
    if not parsed.hostname or parsed.username or parsed.password: raise ValueError("Podaj poprawny URL bez danych logowania")
    normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
    return normalized, parsed.hostname.rstrip(".").lower()


def validate_step(mode: str, resource_type: str | None, step: int, data: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    def required(container, fields, prefix):
        for field in fields:
            if container.get(field) in (None, "", []): errors.append({"field": f"{prefix}.{field}", "message": "To pole jest wymagane"})
    if step == 1:
        if mode not in {"create_resource", "assign_existing_resource", "request_access"}: errors.append({"field": "mode", "message": "Wybierz tryb kreatora"})
        if mode == "create_resource" and resource_type not in {"ssh", "web"}: errors.append({"field": "resource_type", "message": "Wybierz preset SSH lub WWW"})
    elif step == 2:
        if mode == "create_resource": required(data.get("resource", {}), ["name", "environment", "criticality"], "resource")
        else: required(data, ["resource_id"], "data")
    elif step == 3 and mode == "create_resource":
        connection = data.get("connection", {})
        if resource_type == "ssh":
            required(connection, ["hostname", "target_username"], "connection")
            if not 1 <= int(connection.get("port", 22) or 0) <= 65535: errors.append({"field": "connection.port", "message": "Port musi mieścić się w zakresie 1–65535"})
        else:
            required(connection, ["start_url", "allowed_domains"], "connection")
            try:
                if connection.get("start_url"): normalize_url(connection["start_url"])
            except ValueError as exc: errors.append({"field": "connection.start_url", "message": str(exc)})
    elif step == 4 and mode == "create_resource":
        connection = data.get("connection", {}); auth = connection.get("authentication_type", "none")
        if resource_type == "ssh" and auth in {"password", "private_key"} and not (connection.get("secret_ref_id") or connection.get("secret_input_key")): errors.append({"field": "connection.secret_ref_id", "message": "Wybierz istniejący sekret lub utwórz nowy"})
        if resource_type == "web" and auth == "form": required(connection, ["username_selector", "password_selector", "submit_selector"], "connection")
    elif step == 5 and mode != "request_access":
        if not data.get("access_group_id"): required(data.get("access_profile", {}), ["name", "access_option"], "access_profile")
    elif step == 6 and mode != "request_access":
        policy = data.get("policy", {}); criticality = data.get("resource", {}).get("criticality", "low")
        if criticality in {"high", "critical"} and policy.get("require_recording") is False and not policy.get("control_override_justification"): errors.append({"field": "policy.control_override_justification", "message": "Uzasadnij wyłączenie nagrywania dla zasobu krytycznego"})
    elif step == 7 and mode != "request_access" and not data.get("assignments"): errors.append({"field": "assignments", "message": "Przydziel co najmniej jednego użytkownika, grupę lub rolę"})
    elif step == 8:
        if mode == "request_access": required(data, ["access_group_id", "duration_minutes", "justification"], "data")
        elif int(data.get("policy", {}).get("maximum_duration_minutes", 0) or 0) < 1: errors.append({"field": "policy.maximum_duration_minutes", "message": "Maksymalny czas musi być dodatni"})
    elif step == 9 and mode == "create_resource" and not data.get("connection_test", {}).get("passed"):
        errors.append({"field": "connection_test", "message": "Przed utworzeniem wykonaj poprawny test połączenia"})
    return errors


def _secret_value(db: DBSession, reference: int | None, input_key: str | None, inputs: dict[str, SecretInput]) -> str | None:
    if input_key:
        item = inputs.get(input_key)
        if not item: raise ValueError("Nie dostarczono tymczasowego sekretu")
        return item.value
    if reference:
        secret = db.get(Secret, reference)
        if not secret: raise ValueError("Wybrany sekret nie istnieje")
        return get_vault_backend_for_secret(db, secret).get_secret_value(secret.id, {"access_context": "access_wizard_test"})
    return None


def _safe_error(exc: Exception) -> str:
    value = re.sub(r"(?i)(password|token|secret|authorization|cookie)(\s*[=:]\s*)\S+", r"\1\2[REDACTED]", str(exc))
    return value[:500]


def _ssh_probe(connection: dict[str, Any], secret_value: str | None) -> list[CheckResult]:
    host = str(connection.get("hostname", "")); port = int(connection.get("port", 22)); timeout = int(connection.get("connection_timeout_seconds", 10)); checks = []
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        checks.append(CheckResult(name="dns", status="success", message=f"DNS: {len({row[4][0] for row in answers})} adres(y)"))
    except Exception as exc:
        return [CheckResult(name="dns", status="error", message="Nie udało się rozwiązać nazwy", technical_detail=_safe_error(exc))] + [CheckResult(name=name, status="skipped", message="Pominięto po błędzie DNS") for name in ("tcp", "host_key", "authentication", "required_privileges")]
    try:
        sock = socket.create_connection((host, port), timeout=timeout); sock.close(); checks.append(CheckResult(name="tcp", status="success", message=f"Port {port} jest osiągalny"))
    except Exception as exc:
        return checks + [CheckResult(name="tcp", status="error", message="Nie udało się połączyć z portem", technical_detail=_safe_error(exc))] + [CheckResult(name=name, status="skipped", message="Pominięto po błędzie TCP") for name in ("host_key", "authentication", "required_privileges")]
    client = paramiko.SSHClient(); client.load_system_host_keys()
    if connection.get("host_key_policy", "strict") == "trust_on_first_use": client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else: client.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs: dict[str, Any] = {"hostname": host, "port": port, "username": connection.get("administrative_username") or connection.get("target_username"), "timeout": timeout, "allow_agent": connection.get("authentication_type") == "agent", "look_for_keys": False}
    if connection.get("authentication_type") == "password": kwargs["password"] = secret_value
    elif connection.get("authentication_type") == "private_key" and secret_value:
        for key_type in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try: kwargs["pkey"] = key_type.from_private_key(StringIO(secret_value)); break
            except (ValueError, paramiko.SSHException): pass
        if "pkey" not in kwargs: return checks + [CheckResult(name="host_key", status="skipped", message="Nie można sprawdzić bez poprawnego klucza"), CheckResult(name="authentication", status="error", message="Niepoprawny klucz prywatny"), CheckResult(name="required_privileges", status="skipped", message="Pominięto po błędzie uwierzytelnienia")]
    try:
        client.connect(**kwargs)
        remote = client.get_transport().get_remote_server_key(); fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(remote.asbytes()).digest()).decode().rstrip("=")
        expected = connection.get("expected_host_key_fingerprint")
        if expected and expected.lower() != fingerprint.lower(): raise ValueError("Fingerprint hosta nie jest zgodny")
        checks += [CheckResult(name="host_key", status="success", message="Klucz hosta zweryfikowany", technical_detail=fingerprint), CheckResult(name="authentication", status="success", message="Uwierzytelnienie zakończone powodzeniem")]
        command = "sudo -n -l" if connection.get("sudo_mode") in {"limited", "full"} else "id"
        _, stdout, stderr = client.exec_command(command, timeout=timeout); code = stdout.channel.recv_exit_status()
        checks.append(CheckResult(name="required_privileges", status="success" if code == 0 else "error", message="Wymagane uprawnienia są dostępne" if code == 0 else "Konto nie ma wymaganych uprawnień", technical_detail=(stderr.read().decode(errors="replace")[:300] if code else None)))
    except Exception as exc:
        existing = {item.name for item in checks}; failed = "host_key" if isinstance(exc, paramiko.BadHostKeyException) else "authentication"
        if failed not in existing: checks.append(CheckResult(name=failed, status="error", message="Weryfikacja SSH nie powiodła się", technical_detail=_safe_error(exc)))
        for name in ("host_key", "authentication", "required_privileges"):
            if name not in {item.name for item in checks}: checks.append(CheckResult(name=name, status="skipped", message="Pominięto po wcześniejszym błędzie"))
    finally: client.close()
    order = {name: index for index, name in enumerate(("dns", "tcp", "host_key", "authentication", "required_privileges"))}
    return sorted(checks, key=lambda item: order[item.name])


async def test_ssh_connection(db: DBSession, connection: dict[str, Any], inputs: dict[str, SecretInput]) -> list[CheckResult]:
    try: value = _secret_value(db, connection.get("secret_ref_id"), connection.get("secret_input_key"), inputs)
    except Exception as exc: return [CheckResult(name="authentication", status="error", message="Nie udało się odczytać sekretu", technical_detail=_safe_error(exc))]
    return await asyncio.to_thread(_ssh_probe, connection, value)


async def _guarded_web_context(url: str, allowed: list[str], blocked: list[str], allow_private: bool, allow_subdomains: bool = True):
    guard = NavigationGuard(allowed, allow_private, blocked, allow_subdomains); await guard.validate(url)
    await web_provider.semaphore.acquire(); context = None
    try:
        context = await (await web_provider._browser()).new_context(viewport={"width": 1440, "height": 900})
        async def route_request(route):
            try: await guard.validate(route.request.url); await route.continue_()
            except (UnsafeNavigation, OSError): await route.abort("blockedbyclient")
        await context.route("**/*", route_request)
        return context
    except Exception:
        if context: await context.close()
        web_provider.semaphore.release(); raise


async def test_web_connection(db: DBSession, resource: dict[str, Any], connection: dict[str, Any], inputs: dict[str, SecretInput]) -> list[CheckResult]:
    checks: list[CheckResult] = []; context = None
    try:
        url, domain = normalize_url(connection.get("start_url", connection.get("initial_url", ""))); allowed = connection.get("allowed_domains") or [domain]
        if isinstance(allowed, str): allowed = [x.strip() for x in allowed.split(",")]
        blocked = connection.get("blocked_domains", [])
        if isinstance(blocked, str): blocked = [x.strip() for x in blocked.split(",")]
        checks.append(CheckResult(name="url_validation", status="success", message=f"URL znormalizowany: {url}"))
        guard = NavigationGuard(allowed, bool(connection.get("allow_private_network", False)), blocked, bool(connection.get("allow_subdomains", True))); _, addresses = await guard.validate(url)
        checks += [CheckResult(name="dns_resolution", status="success", message=f"DNS: {len(addresses)} bezpieczny adres"), CheckResult(name="ssrf_policy", status="success", message="Cel przeszedł politykę SSRF")]
        context = await _guarded_web_context(url, allowed, connection.get("blocked_domains", []), bool(connection.get("allow_private_network", False)), bool(connection.get("allow_subdomains", True)))
        page = await context.new_page(); response = await page.goto(url, wait_until="domcontentloaded", timeout=int(connection.get("login_timeout_seconds", 30)) * 1000)
        if not response: raise ValueError("Brak odpowiedzi HTTP")
        redirect = url.startswith("http://") and page.url.startswith("https://")
        checks.append(CheckResult(name="page_load", status="success" if response.status < 400 else "error", message=f"HTTP {response.status}" + ("; wykryto przekierowanie do HTTPS" if redirect else ""), technical_detail=page.url))
        auth = connection.get("authentication_type", "none")
        if auth == "form":
            username = _secret_value(db, connection.get("username_secret_id"), connection.get("username_secret_input_key"), inputs) or ""
            password = _secret_value(db, connection.get("password_secret_id"), connection.get("password_secret_input_key"), inputs) or ""
            await page.locator(connection["username_selector"]).fill(username); await page.locator(connection["password_selector"]).fill(password); await page.locator(connection["submit_selector"]).click()
            if connection.get("success_url_pattern"): await page.wait_for_url(connection["success_url_pattern"], timeout=int(connection.get("login_timeout_seconds", 30)) * 1000)
            if connection.get("success_dom_selector"): await page.locator(connection["success_dom_selector"]).wait_for(timeout=int(connection.get("login_timeout_seconds", 30)) * 1000)
            checks.append(CheckResult(name="authentication", status="success", message="Próbne logowanie powiodło się"))
        else: checks.append(CheckResult(name="authentication", status="skipped", message="Automatyczne logowanie nie jest wymagane"))
        checks.append(CheckResult(name="browser_worker", status="success", message="Kontrolowana przeglądarka działa poprawnie"))
    except Exception as exc:
        checks.append(CheckResult(name="browser_worker", status="error", message="Test WWW nie powiódł się", technical_detail=_safe_error(exc)))
    finally:
        if context: await context.close(); web_provider.semaphore.release()
    return checks


async def discover_web_login(payload: dict[str, Any]) -> dict[str, Any]:
    url, domain = normalize_url(payload["start_url"]); context = None
    try:
        allowed = payload.get("allowed_domains") or [domain]
        if isinstance(allowed, str): allowed = [x.strip() for x in allowed.split(",")]
        blocked = payload.get("blocked_domains", [])
        if isinstance(blocked, str): blocked = [x.strip() for x in blocked.split(",")]
        context = await _guarded_web_context(url, allowed, blocked, payload.get("allow_private_network", False), payload.get("allow_subdomains", True))
        page = await context.new_page(); await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        candidates = await page.evaluate("""() => { const esc=v=>CSS.escape(v); const stable=e=>{if(e.id)return '#'+esc(e.id);if(e.name)return e.tagName.toLowerCase()+'[name="'+CSS.escape(e.name)+'"]';for(const a of [...e.attributes].filter(a=>a.name.startsWith('data-')).map(a=>a.name))if(e.getAttribute(a))return '['+a+'="'+CSS.escape(e.getAttribute(a))+'"]';const role=e.getAttribute('role'),label=e.getAttribute('aria-label');if(role&&label)return '[role="'+esc(role)+'"][aria-label="'+esc(label)+'"]';const form=e.closest('form');if(form&&(form.id||form.name)){const parent=form.id?'#'+esc(form.id):'form[name="'+esc(form.name)+'"]';return parent+' '+e.tagName.toLowerCase()+(e.type?'[type="'+esc(e.type)+'"]':'');}const cls=[...e.classList].filter(x=>!/[0-9]{3,}/.test(x)).slice(0,2);return e.tagName.toLowerCase()+(cls.length?'.'+cls.map(esc).join('.'):'');};return [...document.querySelectorAll('input,button,[role="button"],a,main,nav,[aria-label]')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0}).map((e,index)=>{const r=e.getBoundingClientRect();return {index,selector:stable(e),tag:e.tagName.toLowerCase(),type:e.type||'',name:e.name||'',role:e.getAttribute('role')||'',accessible_name:e.getAttribute('aria-label')||e.innerText?.trim().slice(0,120)||'',suggested:e.type==='password'?'password':e.tagName==='BUTTON'||e.type==='submit'?'submit':e.autocomplete==='username'||/user|email|login/i.test(e.name||e.id)?'username':'success',rect:{x:r.x,y:r.y,width:r.width,height:r.height}}})} """)
        screenshot = base64.b64encode(await page.screenshot(type="jpeg", quality=75, full_page=False)).decode()
        return {"normalized_url": page.url, "screenshot": screenshot, "mime_type": "image/jpeg", "viewport": {"width": 1440, "height": 900}, "candidates": candidates, "selector_priority": ["stable id", "name", "data-*", "role + accessible name", "relative selector", "CSS fallback"]}
    finally:
        if context: await context.close(); web_provider.semaphore.release()


def apply_security_defaults(resource: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    result = {"require_approval": True, "require_mfa": False, "require_recording": True, "require_command_logging": True, "idle_timeout_minutes": 15, "maximum_duration_minutes": 60, "allowed_weekdays": "0,1,2,3,4,5,6", **policy}
    if resource.get("criticality", "low") in {"high", "critical"}:
        for key in ("require_approval", "require_mfa", "require_recording"): result[key] = policy.get(key, True)
        result["maximum_duration_minutes"] = policy.get("maximum_duration_minutes", 30)
        if not result["require_recording"] and not result.get("control_override_justification"): raise ValueError("Wyłączenie nagrywania wymaga uzasadnienia")
    return result


def _create_secret(db: DBSession, item: SecretInput, user_id: int) -> Secret:
    return LocalEncryptedBackend(db).create_secret(item.name, item.secret_type, item.value, {"actor_id": user_id, "description": "Utworzono w kreatorze dostępu"})


def _resolve_secret(db: DBSession, connection: dict[str, Any], field: str, input_field: str, inputs: dict[str, SecretInput], user_id: int) -> int | None:
    if connection.get(field): return int(connection[field])
    key = connection.get(input_field)
    if key:
        if key not in inputs: raise ValueError("Brakuje nowego sekretu")
        return _create_secret(db, inputs[key], user_id).id
    return None


def _assignment_user_ids(db: DBSession, assignment: dict[str, Any]) -> set[int]:
    kind = assignment.get("subject_type"); identifier = str(assignment.get("subject_identifier", ""))
    if kind == "user": return {int(identifier)} if db.get(User, int(identifier)) else set()
    if kind == "role": return {row.id for row in db.query(User).filter(User.role == identifier, User.is_active.is_(True)).all()}
    if kind in {"group", "directory_group"}: return {row.user_id for row in db.query(UserGroup).filter(UserGroup.group_name == identifier).all()}
    return set()


def complete_transaction(db: DBSession, user: User, draft: AccessWizardDraft, inputs: dict[str, SecretInput], submission_key: str) -> dict[str, Any]:
    previous = db.query(AccessWizardSubmission).filter_by(user_id=user.id, submission_key=submission_key).first()
    if previous: return {**json.loads(previous.result_json), "duplicate": True}
    data = json.loads(draft.data_json); mode = draft.mode
    if mode == "request_access":
        server = db.get(Server, int(data["resource_id"])); group = db.get(ServerGroup, int(data["access_group_id"]))
        if not server or not group or not db.query(ServerGroupMember).filter_by(server_group_id=group.id, server_id=server.id).first(): raise ValueError("Wybrany profil nie jest dostępny dla zasobu")
        membership = db.query(ServerGroupUserMembership).filter_by(server_group_id=group.id, user_id=user.id, enabled=True).first()
        if not membership: raise ValueError("Wybrany profil nie jest dostępny dla użytkownika")
        request = AccessRequest(user_id=user.id, server_id=server.id, reason=data["justification"], requested_duration_minutes=int(data["duration_minutes"]), requested_access_type=(group.allowed_access_types.split(",")[0] or "ssh_only"), status="pending", approval_required=group.require_approval, mfa_required=group.require_mfa, session_recording_required=group.require_session_recording)
        db.add(request); db.flush(); result = {"mode": mode, "request_id": request.id, "server_id": server.id, "access_group_id": group.id}
        write_audit(db, "access_wizard.request", f"Utworzono wniosek o dostęp do {server.hostname}", user_id=user.id, server_id=server.id, request_id=request.id)
    else:
        if mode == "create_resource":
            resource = data["resource"]; connection = data["connection"]
            if draft.resource_type == "ssh":
                secret_id = _resolve_secret(db, connection, "secret_ref_id", "secret_input_key", inputs, user.id)
                server = Server(hostname=connection["hostname"], display_name=resource["name"], ip_address=connection["hostname"], ssh_port=int(connection.get("port", 22)), environment=resource["environment"], owner=resource.get("owner"), description=resource.get("description"), enabled=bool(resource.get("enabled", True)), criticality=resource.get("criticality", "low"), tags=",".join(resource.get("tags", [])), protocol="ssh", ssh_admin_user=connection.get("administrative_username"), gateway_target_user=connection.get("target_username"), ssh_auth_type="vault_secret" if secret_id else connection.get("authentication_type", "agent"), ssh_auth_secret_id=secret_id, secret_ref_id=secret_id, host_key_policy=connection.get("host_key_policy", "strict"), expected_host_key_fingerprint=connection.get("expected_host_key_fingerprint"), connection_timeout_seconds=int(connection.get("connection_timeout_seconds", 10)), gateway_enabled=bool(connection.get("gateway_enabled", True)), direct_access_enabled=bool(connection.get("direct_access_enabled", False)))
            else:
                url, domain = normalize_url(connection["start_url"]); parsed = urlsplit(url)
                server = Server(hostname=domain, display_name=resource["name"], ip_address=domain, ssh_port=443 if parsed.scheme == "https" else 80, environment=resource["environment"], owner=resource.get("owner"), description=resource.get("description"), enabled=bool(resource.get("enabled", True)), criticality=resource.get("criticality", "low"), tags=",".join(resource.get("tags", [])), protocol="web", allowed_domains=",".join(connection.get("allowed_domains") or [domain]), allow_private_network=bool(connection.get("allow_private_network", False)), allow_subdomains=bool(connection.get("allow_subdomains", True)), gateway_enabled=False, direct_access_enabled=False)
            db.add(server); db.flush()
            if draft.resource_type == "web":
                profile = WebConnectionProfile(server_id=server.id, initial_url=url, authentication_mode=connection.get("authentication_type", "none"), username_secret_id=_resolve_secret(db, connection, "username_secret_id", "username_secret_input_key", inputs, user.id), password_secret_id=_resolve_secret(db, connection, "password_secret_id", "password_secret_input_key", inputs, user.id), auth_secret_id=_resolve_secret(db, connection, "auth_secret_id", "auth_secret_input_key", inputs, user.id), username_selector=connection.get("username_selector"), password_selector=connection.get("password_selector"), submit_selector=connection.get("submit_selector"), success_url_pattern=connection.get("success_url_pattern"), success_dom_selector=connection.get("success_dom_selector"), blocked_domains=",".join(connection.get("blocked_domains", [])), upload_policy="allow" if connection.get("allow_uploads") else "deny", download_policy="allow" if connection.get("allow_downloads") else "deny", clipboard_policy=connection.get("clipboard_policy", "deny"), popup_policy=connection.get("popup_policy", "same_origin"), login_timeout_seconds=int(connection.get("login_timeout_seconds", 30)), idle_timeout_seconds=int(connection.get("idle_timeout_seconds", 900)), maximum_session_duration_minutes=int(connection.get("maximum_session_duration_minutes", 60)))
                db.add(profile)
        else:
            server = db.get(Server, int(data["resource_id"]))
            if not server: raise ValueError("Wybrany zasób nie istnieje")
        resource_data = data.get("resource", {})
        resource_group = db.get(ServerGroup, int(resource_data["resource_group_id"])) if resource_data.get("resource_group_id") else None
        if resource_data.get("new_group_name"):
            resource_group = ServerGroup(name=resource_data["new_group_name"], description="Grupa zasobów utworzona przez kreator", environment=server.environment, enabled=True, created_by_id=user.id, updated_by_id=user.id)
            db.add(resource_group); db.flush()
        if resource_group and not db.query(ServerGroupMember).filter_by(server_group_id=resource_group.id, server_id=server.id).first(): db.add(ServerGroupMember(server_group_id=resource_group.id, server_id=server.id, created_by_id=user.id))
        policy = apply_security_defaults(data.get("resource", {"criticality": server.criticality}), data.get("policy", {}))
        group = db.get(ServerGroup, int(data["access_group_id"])) if data.get("access_group_id") else None
        if not group:
            profile = data["access_profile"]
            group = ServerGroup(name=profile["name"], description=profile.get("description"), environment=server.environment, enabled=True, created_by_id=user.id, updated_by_id=user.id, allowed_access_types=profile.get("access_option", "ssh_only"), max_grant_minutes=int(policy["maximum_duration_minutes"]), allowed_durations=",".join(str(item) for item in profile.get("allowed_durations", [30, 60])), require_approval=bool(policy["require_approval"]), require_mfa=bool(policy["require_mfa"]), require_gateway=bool(data.get("connection", {}).get("gateway_enabled", server.protocol == "ssh")), deny_direct_ssh=not bool(data.get("connection", {}).get("direct_access_enabled", False)), require_command_logging=bool(policy.get("require_command_logging", True)), require_session_recording=bool(policy["require_recording"]), allowed_weekdays=str(policy.get("allowed_weekdays", "0,1,2,3,4,5,6")), allow_auto_grant=any(item.get("assignment_mode") == "direct_launch" for item in data.get("assignments", [])), require_reason=True)
            db.add(group); db.flush()
        if not db.query(ServerGroupMember).filter_by(server_group_id=group.id, server_id=server.id).first(): db.add(ServerGroupMember(server_group_id=group.id, server_id=server.id, created_by_id=user.id))
        assigned: set[int] = set()
        for item in data.get("assignments", []): assigned |= _assignment_user_ids(db, item)
        for user_id in assigned:
            if not db.query(ServerGroupUserMembership).filter_by(server_group_id=group.id, user_id=user_id).first(): db.add(ServerGroupUserMembership(server_group_id=group.id, user_id=user_id, group_role="user", enabled=True, created_by_id=user.id, updated_by_id=user.id))
        db.flush(); result = {"mode": mode, "server_id": server.id, "access_group_id": group.id, "assigned_user_ids": sorted(assigned)}
        write_audit(db, "access_wizard.complete", f"Utworzono konfigurację dostępu do {server.hostname}", user_id=user.id, server_id=server.id, metadata={"mode": mode, "access_group_id": group.id, "assigned_user_count": len(assigned)})
    submission = AccessWizardSubmission(user_id=user.id, submission_key=submission_key, result_json=json.dumps(result)); db.add(submission); db.delete(draft)
    _before_commit_hook()
    db.commit()
    return {**result, "duplicate": False}

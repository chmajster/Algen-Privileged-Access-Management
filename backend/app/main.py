from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import schemas
from app.audit import reset_audit_user_agent, set_audit_user_agent
from app.auth import get_current_user
from app.config import settings
from app.database import SessionLocal, init_db
from app.identity.local_provider import LocalAuthenticationBackendError, validate_os_auth_backend
from app.models import User
from app.routes import access_grants, access_groups, access_requests, alerts, audit_logs, auth, gateway, identity, mfa, policies, policy_rules, risk_events, secret_rotation, secrets, server_registrations, server_templates, servers, sessions, users
from app.scheduler import start_scheduler, stop_scheduler, tick
from app.seed import seed_demo_data


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    tick()
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="Linux PAM Lite", version="1.0.0", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def redact_validation_secrets(_: Request, exc: RequestValidationError):
    errors = exc.errors()
    for error in errors:
        if any(str(part).lower() in {"password", "secret", "token", "private_key"} for part in error.get("loc", ())):
            error["input"] = "[REDACTED]"
            error.pop("ctx", None)
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


@app.middleware("http")
async def bind_audit_request_context(request: Request, call_next):
    token = set_audit_user_agent(request.headers.get("user-agent"))
    try:
        return await call_next(request)
    finally:
        reset_audit_user_agent(token)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(identity.router)
app.include_router(users.router)
app.include_router(access_groups.router)
app.include_router(servers.router)
app.include_router(server_templates.router)
app.include_router(server_registrations.register_router)
app.include_router(server_registrations.approval_router)
app.include_router(access_requests.router)
app.include_router(access_grants.router)
app.include_router(policies.router)
app.include_router(audit_logs.router)
app.include_router(sessions.router)
app.include_router(gateway.router)
app.include_router(secrets.router)
app.include_router(secret_rotation.router)
app.include_router(policy_rules.router)
app.include_router(risk_events.router)
app.include_router(alerts.router)


@app.get("/api/settings", response_model=schemas.SettingsOut)
def get_settings(_: User = Depends(get_current_user)):
    return {
        "executor_mode": settings.pam_executor_mode,
        "session_log_import_enabled": settings.pam_session_log_import_enabled,
        "session_log_dir": settings.pam_session_log_dir,
        "scheduler_interval_seconds": settings.scheduler_interval_seconds,
        "access_mode": settings.pam_access_mode,
        "group_scoped_access": settings.pam_group_scoped_access,
        "gateway_enabled": settings.pam_gateway_enabled,
        "gateway_host": settings.pam_gateway_host,
        "gateway_port": settings.pam_gateway_port,
        "gateway_session_recording": settings.pam_gateway_session_recording,
        "gateway_command_logging": settings.pam_gateway_command_logging,
        "gateway_idle_timeout_seconds": settings.pam_gateway_idle_timeout_seconds,
        "gateway_max_session_seconds": settings.pam_gateway_max_session_seconds,
        "vault_mode": settings.pam_vault_mode,
        "secret_rotation_enabled": settings.pam_secret_rotation_enabled,
        "secret_rotation_interval_hours": settings.pam_secret_rotation_interval_hours,
        "ssh_key_rotation_enabled": settings.pam_ssh_key_rotation_enabled,
        "policy_engine_enabled": settings.pam_policy_engine_enabled,
        "risk_engine_enabled": settings.pam_risk_engine_enabled,
        "alerts_enabled": settings.pam_alerts_enabled,
        "auto_revoke_on_critical_risk": settings.pam_auto_revoke_on_critical_risk,
        "critical_risk_score": settings.pam_critical_risk_score,
        "high_risk_score": settings.pam_high_risk_score,
        "medium_risk_score": settings.pam_medium_risk_score,
        "auth_providers": settings.pam_auth_providers,
        "default_auth_provider": settings.pam_default_auth_provider,
        "local_auth_mode": settings.pam_local_auth_mode,
        "os_pam_service": settings.pam_os_pam_service,
        "os_auto_provision": settings.pam_os_auto_provision,
        "mfa_enabled": settings.pam_mfa_enabled,
        "mfa_issuer": settings.pam_mfa_issuer,
        "mfa_required_for_admin": settings.pam_mfa_required_for_admin,
        "mfa_required_for_prod": settings.pam_mfa_required_for_prod,
        "mfa_required_for_full_sudo": settings.pam_mfa_required_for_full_sudo,
        "mfa_required_for_gateway": settings.pam_mfa_required_for_gateway,
        "mfa_required_for_secret_rotation": settings.pam_mfa_required_for_secret_rotation,
        "mfa_token_ttl_seconds": settings.pam_mfa_token_ttl_seconds,
        "step_up_ttl_seconds": settings.pam_step_up_ttl_seconds,
        "ldap_enabled": settings.pam_ldap_enabled,
        "oidc_enabled": settings.pam_oidc_enabled,
    }


@app.get("/api/health", response_model=schemas.Message)
def health():
    detail = {"local_auth_mode": settings.pam_local_auth_mode}
    if settings.pam_local_auth_mode == "os":
        try:
            validate_os_auth_backend()
        except LocalAuthenticationBackendError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Linux PAM backend unavailable") from exc
        detail["pam"] = "available"
        detail["pam_service"] = settings.pam_os_pam_service
    return {"message": "ok", "detail": detail}


FRONTEND_DIR = Path(__file__).parents[2] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")

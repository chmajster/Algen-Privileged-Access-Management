from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.audit import reset_audit_user_agent, set_audit_user_agent
from app.database import SessionLocal, init_db
from app.lifecycle import start_lifecycle_monitor, stop_lifecycle_monitor
from app.providers.web import web_provider
from app.routes import access_wizard, auth, domain, identity, mfa, secrets
from app.seed import seed_demo_data


@asynccontextmanager
async def lifespan(_:FastAPI):
    init_db()
    with SessionLocal() as db: seed_demo_data(db)
    start_lifecycle_monitor()
    yield
    await stop_lifecycle_monitor(); await web_provider.shutdown()


app=FastAPI(title="Algen Multi-Protocol PAM",version="3.0.0",lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def redact_validation_secrets(_:Request,exc:RequestValidationError):
    errors=exc.errors()
    for error in errors:
        if any(str(part).lower() in {"password","secret","token","private_key","value"} for part in error.get("loc",())):
            error["input"]="[REDACTED]"; error.pop("ctx",None)
    return JSONResponse(status_code=422,content={"detail":jsonable_encoder(errors)})


@app.middleware("http")
async def audit_context(request:Request,call_next):
    token=set_audit_user_agent(request.headers.get("user-agent"))
    try: return await call_next(request)
    finally: reset_audit_user_agent(token)


app.add_middleware(CORSMiddleware,allow_origins=[],allow_credentials=True,allow_methods=["GET","POST","PUT","DELETE"],allow_headers=["Authorization","Content-Type"])
for route in (auth.router,mfa.router,identity.router,secrets.router,domain.router,access_wizard.router): app.include_router(route)


@app.get("/api/health")
def health(): return {"message":"ok","schema":3,"browser_worker":"healthy" if web_provider.healthy() else "unhealthy","active_browser_sessions":len(web_provider.runtimes)}


FRONTEND_DIR=Path(__file__).parents[2]/"frontend"
if FRONTEND_DIR.exists(): app.mount("/static",StaticFiles(directory=FRONTEND_DIR),name="static")


@app.get("/")
def index(): return FileResponse(FRONTEND_DIR/"index.html")

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import schemas
from app.audit import write_audit
from app.auth import get_current_user, require_roles, source_ip
from app.database import get_db
from app.executor import get_executor
from app.models import AccessGrant, AccessRequest, Server, User


router = APIRouter(prefix="/api/servers", tags=["servers"])


@router.get("", response_model=list[schemas.ServerOut])
def list_servers(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Server)
    if current_user.role == "user":
        query = query.filter(Server.enabled.is_(True))
    return query.order_by(Server.hostname).all()


@router.post("", response_model=schemas.ServerOut)
def create_server(payload: schemas.ServerCreate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    server = Server(**payload.model_dump())
    db.add(server)
    db.flush()
    write_audit(db, "server.created", f"Created server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(server)
    return server


@router.get("/{server_id}", response_model=schemas.ServerOut)
def get_server(server_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server or (current_user.role == "user" and not server.enabled):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server


@router.put("/{server_id}", response_model=schemas.ServerOut)
def update_server(server_id: int, payload: schemas.ServerUpdate, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(server, key, value)
    write_audit(db, "server.updated", f"Updated server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request))
    db.commit()
    db.refresh(server)
    return server


@router.delete("/{server_id}", response_model=schemas.Message)
def delete_server(server_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    linked = db.query(AccessGrant).filter(AccessGrant.server_id == server_id).count() + db.query(AccessRequest).filter(AccessRequest.server_id == server_id).count()
    server.enabled = False
    write_audit(db, "server.deactivated", f"Deactivated server {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request))
    db.commit()
    return {"message": "Server deactivated because linked records exist" if linked else "Server deactivated"}


@router.post("/{server_id}/test-connection", response_model=schemas.Message)
def test_connection(server_id: int, request: Request, current_user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    result = get_executor().test_connection(server)
    write_audit(db, "server.test_connection", f"Tested connection to {server.hostname}", user_id=current_user.id, server_id=server.id, source_ip=source_ip(request), metadata=result)
    db.commit()
    return {"message": "Connection test completed", "detail": result}

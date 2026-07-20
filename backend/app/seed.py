from sqlalchemy.orm import Session

from app.config import settings
from app.models import (AccessProfile, ConnectionProfile, Resource, ResourceGroup,
                        SSHConnectionProfile, User, WebConnectionProfile)
from app.rbac import seed_access_control
from app.security import hash_password


def seed_demo_data(db: Session) -> None:
    for username,email,password,role in (
        (settings.pam_default_admin_user,settings.pam_default_admin_email,settings.pam_default_admin_password,"admin"),
        ("operator","operator@example.local","operator123","operator"),
        ("user","user@example.local","user123","user"),
    ):
        if not db.query(User).filter_by(username=username).first():
            db.add(User(username=username,email=email,password_hash=hash_password(password),role=role,is_active=True,mfa_required=False))
    db.flush(); seed_access_control(db)
    group=db.query(ResourceGroup).filter_by(name="Demo resources").first()
    if not group: group=ResourceGroup(name="Demo resources",description="SSH and web provider examples"); db.add(group); db.flush()
    ssh=db.query(Resource).filter_by(name="Demo SSH").first()
    if not ssh:
        ssh=Resource(name="Demo SSH",resource_type="ssh",environment="dev",criticality="low",group_id=group.id,description="Local SSH demonstration target")
        db.add(ssh); db.flush(); generic=ConnectionProfile(resource_id=ssh.id,name="Default SSH"); db.add(generic); db.flush()
        db.add(SSHConnectionProfile(connection_profile_id=generic.id,hostname="host.docker.internal",port=22,username="pam-demo",auth_mode="agent",host_key_policy="strict"))
    web=db.query(Resource).filter_by(name="Demo Web").first()
    if not web:
        web=Resource(name="Demo Web",resource_type="web",environment="dev",criticality="low",group_id=group.id,description="Public browser demonstration target",allowed_domains="example.com")
        db.add(web); db.flush(); generic=ConnectionProfile(resource_id=web.id,name="Default Web"); db.add(generic); db.flush()
        db.add(WebConnectionProfile(connection_profile_id=generic.id,initial_url="https://example.com",authentication_mode="none"))
    for name,kind in (("Demo SSH access","ssh"),("Demo Web access","web")):
        if not db.query(AccessProfile).filter_by(name=name).first():
            db.add(AccessProfile(name=name,resource_type=kind,max_session_duration_minutes=60,approval_required=False,mfa_required=False,recording_required=True,upload_policy="deny",download_policy="deny",clipboard_policy="deny",max_upload_bytes=settings.pam_web_max_upload_bytes,max_download_bytes=settings.pam_web_max_download_bytes))
    db.commit()

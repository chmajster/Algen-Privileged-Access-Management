import socket
import threading
import time

import pytest
import uvicorn

from app.database import SessionLocal
from app.models import ConnectionProfile, Resource, SessionArtifact, SessionEvent, WebConnectionProfile
from app.providers.web import web_provider
from app.vault.local_encrypted import LocalEncryptedBackend
from tests.conftest import auth_headers
from tests.test_domain import create_grant
from tests.webapp import app as local_web_app


@pytest.fixture(scope="module")
def web_target():
    address=socket.gethostbyname(socket.gethostname())
    if address.startswith("127."): pytest.skip("No non-loopback interface for SSRF-safe local E2E target")
    sock=socket.socket(); sock.bind((address,0)); port=sock.getsockname()[1]; sock.close()
    config=uvicorn.Config(local_web_app,host=address,port=port,log_level="error")
    server=uvicorn.Server(config); thread=threading.Thread(target=server.run,daemon=True); thread.start()
    for _ in range(50):
        if server.started: break
        time.sleep(.05)
    yield f"http://{address}:{port}"
    server.should_exit=True; thread.join(timeout=5)


def test_web_form_login_isolation_recording_and_cleanup(client,web_target):
    headers=auth_headers(client)
    with SessionLocal() as db:
        username=LocalEncryptedBackend(db).create_secret("e2e username","username","demo",{"actor_id":1})
        password=LocalEncryptedBackend(db).create_secret("e2e password","password","correct",{"actor_id":1})
        resource=db.query(Resource).filter_by(name="Demo Web").one(); resource.allow_private_network=True
        resource.allowed_domains=web_target.split("//",1)[1].split(":",1)[0]
        profile=db.query(WebConnectionProfile).join(ConnectionProfile).filter(ConnectionProfile.resource_id==resource.id).one()
        profile.initial_url=web_target; profile.authentication_mode="form"; profile.username_secret_id=username.id; profile.password_secret_id=password.id
        profile.username_selector="#username"; profile.password_selector="#password"; profile.submit_selector="#submit"; profile.success_dom_selector="#authenticated"
        db.commit()
    _,grant=create_grant(client,headers)
    first=client.post("/api/sessions",headers=headers,json={"grant_id":grant["id"]}).json()
    second=client.post("/api/sessions",headers=headers,json={"grant_id":grant["id"]}).json()
    one=client.post(f"/api/sessions/{first['id']}/launch",headers=headers); two=client.post(f"/api/sessions/{second['id']}/launch",headers=headers)
    assert one.status_code==200,one.text; assert two.status_code==200,two.text
    assert web_provider.runtimes[first["id"]].context is not web_provider.runtimes[second["id"]].context
    profile_dirs=[web_provider.runtimes[x["id"]].profile_dir for x in (first,second)]
    for item in (first,second): assert client.post(f"/api/sessions/{item['id']}/terminate",headers=headers,json={"reason":"e2e complete"}).status_code==200
    assert all(not path.exists() for path in profile_dirs)
    with SessionLocal() as db:
        assert db.query(SessionArtifact).filter(SessionArtifact.session_id.in_([first["id"],second["id"]]),SessionArtifact.artifact_type=="trace").count()==2
        form=db.query(SessionEvent).filter_by(session_id=first["id"],event_type="form_submit").one()
        assert "correct" not in form.metadata_json and "demo" not in form.metadata_json

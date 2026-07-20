# Algen Privileged Access Management

Algen PAM is a FastAPI application for controlled SSH and web-browser access. Its domain is protocol-independent: resources, connection/access profiles, requests, grants, sessions, events and artifacts. Provider dispatch selects SSH (Paramiko) or web (Playwright/Chromium) from `Resource.resource_type`.

## Start with Docker

```bash
cp .env.example .env
# replace every placeholder in .env
docker compose build
docker compose up -d
```

Open `http://localhost:8080`. The API and integrated browser worker health are at `/api/health`.

## Developer start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
playwright install chromium
export PYTHONPATH=backend
uvicorn app.main:app --reload --port 8080
```

On PowerShell, activate with `.venv\Scripts\Activate.ps1` and set `$env:PYTHONPATH='backend'`.

## Schema safety

Startup accepts only a fresh database or schema version 2. It never converts or deletes an older schema.

```bash
PYTHONPATH=backend python -m app.schema backup --output pam-before-v2.db
PYTHONPATH=backend python -m app.schema reset --confirm-reset
```

See [INSTALL.md](INSTALL.md) for manual SSH/web tests and [web-session security](docs/WEB_SESSION_SECURITY.md) for the transport threat model.

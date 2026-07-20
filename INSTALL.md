# Installation and validation

## Requirements

Use Docker Engine with Compose, or Python 3.12 plus Chromium installed through Playwright. Allocate at least 2 GB RAM; browser concurrency defaults to four.

Copy `.env.example` to `.env`, replace all placeholders, then run `./install.sh` or `docker compose up --build -d`. Persistent volumes hold the database, artifacts (video and traces), and logs. Browser profile directories are temporary and cleaned on termination and container shutdown.

## Existing databases

Before changing versions, run `docker compose exec pam python -m app.schema backup --output /data/db/pam-v1-backup.db`. A v1 database produces a clear startup error and is untouched. After preserving it, explicitly create v2 with `docker compose run --rm pam python -m app.schema reset --confirm-reset`. There is no implicit destructive migration.

## Manual SSH test

1. Create a secret containing the target password/private key if agent authentication is not used.
2. Create an `ssh` resource and connection profile with host, port, account, host-key policy and secret reference.
3. Test the resource connection.
4. Request the matching SSH access profile and approve it if required.
5. Launch the active grant. Confirm the terminal is embedded, input works, and no credential appears in browser developer tools.
6. Terminate it and confirm `session_started`/`session_finished` events and the termination audit record.

## Manual web test

1. Create a `web` resource with an HTTPS allowed domain. Enable private networks only when the target requires them.
2. Add a web connection profile. For form login, store username/password as separate secrets and configure username, password, submit and success selectors.
3. Test the resource, request access, and launch the grant.
4. Confirm the controlled page is rendered inside PAM and popup/blocked-scheme navigation is denied.
5. Terminate the session. Open replay and verify video, trace checksum/size/MIME metadata and event filtering/jump controls.
6. Verify an unprivileged user cannot read recordings and a privileged reviewer receives an MFA step-up challenge.

## Checks

```bash
PYTHONPATH=backend pytest backend/tests
ruff check backend
mypy backend/app
docker compose config
docker compose build
```

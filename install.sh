#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }
docker compose version >/dev/null
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env. Set SECRET_KEY, PAM_VAULT_MASTER_KEY and the administrator password, then rerun." >&2
  exit 2
fi
if grep -q 'replace-' .env; then
  echo "Refusing to start with placeholder secrets in .env" >&2
  exit 2
fi
docker compose build
docker compose up -d
docker compose ps

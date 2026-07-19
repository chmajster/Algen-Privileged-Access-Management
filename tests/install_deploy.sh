#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALGEN_PAM_INSTALLER_SOURCE_ONLY=1 source "$ROOT_DIR/install.sh"

deploy_root="$(mktemp -d)"
STAGE_ROOT="$deploy_root/stage"
STAGED_APP="$STAGE_ROOT/release"
INSTALL_DIR="$deploy_root/opt/algen-pam"
DATA_DIR="$INSTALL_DIR/data"
CONFIG_FILE="$deploy_root/config.env"
LOG_DIR="$deploy_root/logs"
SCOPE=user

mkdir -p "$STAGED_APP/backend/app" "$STAGED_APP/backend/.venv/bin"
touch "$STAGED_APP/backend/app/main.py" "$STAGED_APP/backend/.venv/bin/python" "$STAGED_APP/backend/.venv/bin/uvicorn" "$CONFIG_FILE"
chmod +x "$STAGED_APP/backend/.venv/bin/python" "$STAGED_APP/backend/.venv/bin/uvicorn"

marker_valid() { return 1; }
target_cmd() { "$@"; }

deploy_release
deployed_release_valid
[[ -d "$INSTALL_DIR/backend" ]]
[[ ! -e "$INSTALL_DIR/release" ]]

rm -rf -- "$deploy_root"
STAGE_ROOT=""

printf 'Installer deployment layout tests passed.\n'

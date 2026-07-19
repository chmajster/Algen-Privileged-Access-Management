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
touch "$STAGED_APP/backend/app/main.py" "$STAGED_APP/backend/.venv/bin/uvicorn" "$CONFIG_FILE"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$STAGED_APP/backend/.venv/bin/python"
chmod +x "$STAGED_APP/backend/.venv/bin/python"

marker_valid() { return 1; }
target_cmd() { "$@"; }

deploy_release
deployed_release_valid
[[ -d "$INSTALL_DIR/backend" ]]
[[ ! -e "$INSTALL_DIR/release" ]]

# A legacy nested .env pointing at the configured file is recoverable, while
# every other external symlink remains forbidden.
marker_valid() {
  [[ -f "$INSTALL_DIR/.algen-pam-install" ]] \
    && grep -qx 'app=algen-pam' "$INSTALL_DIR/.algen-pam-install" \
    && grep -Fqx "install_dir=$INSTALL_DIR" "$INSTALL_DIR/.algen-pam-install"
}
mkdir -p "$INSTALL_DIR/legacy"
ln -s "$CONFIG_FILE" "$INSTALL_DIR/legacy/.env"
safe_target
ln -s /etc/passwd "$INSTALL_DIR/legacy/unsafe-link"
if (safe_target) >/dev/null 2>&1; then
  echo 'Unsafe external symlink was accepted.' >&2
  exit 1
fi
rm "$INSTALL_DIR/legacy/unsafe-link"

rm -rf -- "$deploy_root"
STAGE_ROOT=""

printf 'Installer deployment layout tests passed.\n'

#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALGEN_PAM_INSTALLER_SOURCE_ONLY=1 source "$ROOT_DIR/install.sh"

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

INSTALL_DIR="$test_root/install"
first="$test_root/first"
second="$test_root/second"
mkdir -p "$INSTALL_DIR" "$first/backend/.venv" "$first/__pycache__" "$second"
printf 'same\n' >"$first/app.txt"
printf 'ignored\n' >"$first/backend/.venv/runtime.txt"
printf 'ignored\n' >"$first/__pycache__/cache.pyc"
cp -a "$first/." "$second/"

first_revision="$(source_fingerprint "$first")"
second_revision="$(source_fingerprint "$second")"
[[ "$first_revision" == "$second_revision" ]]

printf 'app=algen-pam\nsource_revision=%s\ninstall_dir=%s\n' "$first_revision" "$INSTALL_DIR" >"$INSTALL_DIR/.algen-pam-install"
MODE=update
SOURCE_REVISION="$second_revision"
source_is_unchanged
APP_PORT_EXPLICIT=0; GATEWAY_PORT_EXPLICIT=0; SERVICE_CHOICE_EXPLICIT=0
DESKTOP_CHOICE_EXPLICIT=0; ADMIN_PASSWORD_SUPPLIED=0; ADMIN_PASSWORD_GENERATED=0; AUTO_PORT=0
! update_requests_reconfiguration
APP_PORT_EXPLICIT=1
update_requests_reconfiguration
CONFIG_FILE="$test_root/config.env"
printf 'ALGEN_PAM_PORT=8080\n' >"$CONFIG_FILE"
APP_PORT=8080
! update_requests_reconfiguration
APP_PORT=9090
update_requests_reconfiguration
APP_PORT_EXPLICIT=0

printf 'changed\n' >"$second/app.txt"
SOURCE_REVISION="$(source_fingerprint "$second")"
if source_is_unchanged; then
  echo "Changed sources were incorrectly treated as current." >&2
  exit 1
fi

printf 'Installer version check tests passed.\n'

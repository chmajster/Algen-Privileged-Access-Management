#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALGEN_PAM_INSTALLER_SOURCE_ONLY=1 source "$ROOT_DIR/install.sh"

assert_mapping() {
  local choice="$1" expected="$2"
  MODE=""; AUTO_UPDATE_SELECTED=0
  map_existing_action "$choice"
  [[ "$MODE" == "$expected" ]] || {
    printf 'Choice %q mapped to %q instead of %q\n' "$choice" "$MODE" "$expected" >&2
    exit 1
  }
}

assert_mapping "" update
assert_mapping 1 update
assert_mapping 2 reinstall
assert_mapping 3 backup
assert_mapping 4 remove-app
assert_mapping 5 uninstall

MODE=""; if map_existing_action 6; then status=0; else status=$?; fi
[[ "$status" -eq 2 && "$MODE" == cancel ]]

assert_mapping __timeout__ update
[[ "$AUTO_UPDATE_SELECTED" -eq 1 ]]

MODE=""; if map_existing_action invalid; then status=0; else status=$?; fi
[[ "$status" -eq 1 && -z "$MODE" ]]

# A CLI mode and a previously completed interactive choice must both bypass
# the menu, preventing the former double-menu regression in main().
MODE=update; MODE_EXPLICIT=1; MODE_SELECTED_INTERACTIVELY=0
interactive_mode_selection
[[ "$MODE" == update && "$MODE_SELECTED_INTERACTIVELY" -eq 0 ]]

MODE=reinstall; MODE_EXPLICIT=0; MODE_SELECTED_INTERACTIVELY=1
interactive_mode_selection
[[ "$MODE" == reinstall && "$MODE_SELECTED_INTERACTIVELY" -eq 1 ]]

# Enter accepts the configured yes/no default used by the text prompts.
read_from_tty() { printf ''; }
prompt_yes_no "test" yes
if prompt_yes_no "test" no; then
  echo 'No-default prompt accepted an empty answer.' >&2
  exit 1
fi

# The system service account has no login shell and must never become the
# default PAM administrator.
unset SUDO_USER
LOCAL_AUTH_MODE=os; TARGET_USER=algen-pam
[[ "$(default_admin_username)" == administrator ]]
LOCAL_AUTH_MODE=database
[[ "$(default_admin_username)" == administrator ]]

# Legacy defaults named root are migrated to an application-only administrator
# account. This never invokes passwd or changes the operating-system root user.
legacy_config="$(mktemp)"
CONFIG_FILE="$legacy_config"; SCOPE=user; MODE=update
ADMIN_USER=""; ADMIN_EMAIL=""; ADMIN_USER_EXPLICIT=0; ADMIN_EMAIL_EXPLICIT=0
ADMIN_PASSWORD_GENERATED=0
printf '%s\n' \
  'PAM_DEFAULT_ADMIN_USER=root' \
  'PAM_DEFAULT_ADMIN_EMAIL=root@localhost.localdomain' \
  'PAM_LOCAL_AUTH_MODE=database' >"$legacy_config"
load_existing_configuration
[[ "$ADMIN_USER" == administrator ]]
[[ "$ADMIN_EMAIL" == administrator@localhost.localdomain ]]
[[ "$ADMIN_PASSWORD_GENERATED" -eq 1 ]]
rm -f -- "$legacy_config"

(
  LOCAL_AUTH_MODE=os; SCOPE=system; TARGET_USER=algen-pam; SERVICE_CHOICE=1
  ADMIN_USER=administrator; ADMIN_EMAIL=administrator@localhost.localdomain
  ADMIN_USER_EXPLICIT=0; ADMIN_EMAIL_EXPLICIT=0
  ADMIN_PASSWORD=""; ADMIN_PASSWORD_SUPPLIED=0; ADMIN_PASSWORD_GENERATED=0
  DRY_RUN=1
  prepare_admin_defaults
  [[ "$LOCAL_AUTH_MODE" == os && "$ADMIN_PASSWORD_GENERATED" -eq 0 ]]
) 2>/dev/null

# Interactive execution uses a visible 3-2-1 countdown without another prompt.
sleep() { :; }
SILENT=0; YES=0; DRY_RUN=0
countdown_output="$(start_countdown 2>&1)"
[[ "$countdown_output" == $'Start za 3...\nStart za 2...\nStart za 1...\nUruchamiam.' ]]
SILENT=1
[[ -z "$(start_countdown 2>&1)" ]]

# Without an explicit mode the installer selects update only for an existing
# installation; otherwise it selects a fresh install.
installation_present() { return 0; }
marker_valid() { return 0; }
MODE=""
determine_mode
[[ "$MODE" == update ]]

installation_present() { return 1; }
marker_valid() { return 1; }
MODE=""
determine_mode
[[ "$MODE" == install ]]

installation_present() { return 1; }
marker_valid() { return 0; }
MODE=""; AUTO_REPAIR_SELECTED=0
determine_mode
[[ "$MODE" == reinstall && "$AUTO_REPAIR_SELECTED" -eq 1 ]]

printf 'Installer menu mapping tests passed.\n'

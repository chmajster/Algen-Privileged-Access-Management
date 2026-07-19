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

MODE=""; set +e; map_existing_action 6; status=$?; set -e
[[ "$status" -eq 2 && "$MODE" == cancel ]]

assert_mapping __timeout__ update
[[ "$AUTO_UPDATE_SELECTED" -eq 1 ]]

MODE=""; set +e; map_existing_action invalid; status=$?; set -e
[[ "$status" -eq 1 && -z "$MODE" ]]

printf 'Installer menu mapping tests passed.\n'

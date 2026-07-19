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

printf 'Installer menu mapping tests passed.\n'

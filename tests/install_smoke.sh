#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"

expect_failure() {
  local description="$1"; shift
  if bash "$INSTALLER" "$@" >/dev/null 2>&1; then
    echo "Expected failure: $description" >&2
    exit 1
  fi
}

bash -n "$INSTALLER"
bash "$INSTALLER" --help >/dev/null
bash "$INSTALLER" --help | grep -F -- '--reinstall' >/dev/null
bash "$INSTALLER" --help | grep -F -- '--remove-app' >/dev/null
bash "$ROOT_DIR/tests/install_menu.sh"
bash "$ROOT_DIR/tests/install_deploy.sh"

if grep -Eq 'COLOR_|whiptail|dialog|\\033|\\e\[' "$INSTALLER"; then
  echo 'Installer contains terminal colors or TUI dependencies.' >&2
  exit 1
fi

expect_failure 'conflicting modes' --update --uninstall --dry-run
expect_failure 'conflicting scopes' --user --system --dry-run
expect_failure 'conflicting source refs' --branch develop --tag v1 --dry-run
expect_failure 'invalid HTTP port' --port 0 --dry-run
expect_failure 'invalid gateway port' --gateway-port 65536 --dry-run
expect_failure 'unsafe root target' --install-dir / --dry-run
expect_failure 'relative target' --install-dir relative/path --dry-run
expect_failure 'newline in environment value' --admin-email $'admin@example.test\nINJECTED=yes' --dry-run
expect_failure 'silent destructive mode without consent' --silent --uninstall --user

if [[ "$(uname -s)" != Linux ]]; then
  echo "Installer syntax/parser tests passed; Linux dry runs skipped."
  exit 0
fi

bash "$INSTALLER" --dry-run --user >/dev/null
bash "$INSTALLER" --dry-run --system >/dev/null
bash "$INSTALLER" --install --system --service --dry-run >/dev/null
bash "$INSTALLER" --dry-run --update >/dev/null
bash "$INSTALLER" --reinstall --system --dry-run >/dev/null
bash "$INSTALLER" --backup --system --dry-run >/dev/null
bash "$INSTALLER" --remove-app --system --dry-run >/dev/null
bash "$INSTALLER" --uninstall --system --keep-data --dry-run >/dev/null
bash "$INSTALLER" --dry-run --uninstall >/dev/null
bash "$INSTALLER" --silent --yes --user --no-service --dry-run >/dev/null
bash "$INSTALLER" --silent --yes --system --service --dry-run >/dev/null
bash "$INSTALLER" --silent --user --no-service --dry-run >/dev/null
bash "$INSTALLER" --silent --system --dry-run >/dev/null

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$INSTALLER"
fi

echo 'Installer smoke tests passed.'

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"

bash -n "$INSTALLER"

bash "$INSTALLER" --help >/dev/null
bash "$INSTALLER" --help | grep -F -- "--port PORT" >/dev/null
bash "$INSTALLER" --help | grep -F -- "--gateway-port PORT" >/dev/null
if bash "$INSTALLER" --silent --yes --port 0 --dry-run >/dev/null 2>&1; then
  echo "Installer accepted an invalid HTTP port." >&2
  exit 1
fi
if bash "$INSTALLER" --silent --yes --gateway-port 65536 --dry-run >/dev/null 2>&1; then
  echo "Installer accepted an invalid gateway port." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Installer parser smoke tests passed; Linux dry-run checks skipped on $(uname -s)."
  exit 0
fi

bash "$INSTALLER" --silent --yes --user --no-service --dry-run >/dev/null
bash "$INSTALLER" --silent --yes --no-service --dry-run | grep -F "/opt/algen-pam" >/dev/null
bash "$INSTALLER" --silent --yes --user --no-service --admin-user admin --admin-email admin@example.local --admin-password admin123 --dry-run >/dev/null
bash "$INSTALLER" --uninstall --user --yes --dry-run --keep-config --keep-logs >/dev/null

if [[ -t 0 ]]; then
  bash "$INSTALLER" --dry-run >/dev/null
fi

echo "Installer smoke tests passed."

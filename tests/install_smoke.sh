#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"

bash -n "$INSTALLER"

"$INSTALLER" --help >/dev/null

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Installer parser smoke tests passed; Linux dry-run checks skipped on $(uname -s)."
  exit 0
fi

"$INSTALLER" --silent --yes --user --no-service --dry-run >/dev/null
"$INSTALLER" --silent --yes --user --no-service --admin-user admin --admin-email admin@example.local --admin-password admin123 --dry-run >/dev/null
"$INSTALLER" --uninstall --user --yes --dry-run --keep-config --keep-logs >/dev/null

if [[ -t 0 ]]; then
  "$INSTALLER" --dry-run >/dev/null
fi

echo "Installer smoke tests passed."

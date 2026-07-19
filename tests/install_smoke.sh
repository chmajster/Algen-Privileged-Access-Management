#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"

bash -n "$INSTALLER"
grep -F "libpam0g" "$INSTALLER" >/dev/null
grep -F "find_library(\"pam\")" "$INSTALLER" >/dev/null

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
DRY_RUN_OUTPUT="$(bash "$INSTALLER" --silent --yes --no-service --dry-run)"
grep -F "/opt/algen-pam" <<<"$DRY_RUN_OUTPUT" >/dev/null
grep -F "/archive/refs/heads/main.tar.gz" <<<"$DRY_RUN_OUTPUT" >/dev/null
if grep -E '^\[dry-run\] git clone' <<<"$DRY_RUN_OUTPUT" >/dev/null; then
  echo "Installer dry-run unexpectedly uses git clone." >&2
  exit 1
fi
bash "$INSTALLER" --silent --yes --user --no-service --admin-user admin --admin-email admin@example.local --admin-password admin123 --dry-run >/dev/null
bash "$INSTALLER" --uninstall --user --yes --dry-run --keep-config --keep-logs >/dev/null

if [[ -t 0 ]]; then
  bash "$INSTALLER" --dry-run >/dev/null
fi

echo "Installer smoke tests passed."

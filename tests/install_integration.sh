#!/usr/bin/env bash
set -euo pipefail

[[ "$(uname -s)" == "Linux" ]] || {
  echo "Installer integration test requires Linux; skipped on $(uname -s)."
  exit 0
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"
TEST_ROOT="$(mktemp -d)"
TEST_HOME="$TEST_ROOT/home"
INSTALL_DIR="$TEST_ROOT/opt/algen-pam"
MOCK_BIN="$TEST_ROOT/bin"
MOCK_SYSTEMD_STATE_DIR="$TEST_ROOT/systemd-state"
CONFIG_FILE="$TEST_HOME/.config/algen-pam/.env"
SERVICE_FILE="$TEST_HOME/.config/systemd/user/algen-pam.service"
PID_FILE="$MOCK_SYSTEMD_STATE_DIR/algen-pam.pid"
OS_TEST_USER="$(id -un)"

cleanup() {
  if [[ -x "$MOCK_BIN/systemctl" ]]; then
    "$MOCK_BIN/systemctl" --user stop algen-pam.service >/dev/null 2>&1 || true
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$TEST_HOME" "$MOCK_BIN" "$MOCK_SYSTEMD_STATE_DIR"
cp "$ROOT_DIR/tests/fixtures/systemctl" "$MOCK_BIN/systemctl"
chmod +x "$MOCK_BIN/systemctl"

export HOME="$TEST_HOME"
export PATH="$MOCK_BIN:$PATH"
export MOCK_SYSTEMD_STATE_DIR
export MOCK_SYSTEMD_SERVICE_FILE="$SERVICE_FILE"

INSTALL_ARGS=(
  --silent --yes --user --service
  --install-dir "$INSTALL_DIR"
  --repo "$ROOT_DIR"
  --admin-user "$OS_TEST_USER"
  --admin-email "$OS_TEST_USER@localhost.localdomain"
  --admin-password integration-pass
)
UPDATE_ARGS=(
  --silent --yes --user
  --install-dir "$INSTALL_DIR"
  --repo "$ROOT_DIR"
)

echo "[integration] fresh installation"
bash "$INSTALLER" "${INSTALL_ARGS[@]}"

[[ -f "$INSTALL_DIR/.algen-pam-install" ]]
[[ -d "$INSTALL_DIR/backend" ]]
[[ -x "$INSTALL_DIR/backend/.venv/bin/uvicorn" ]]
[[ ! -e "$INSTALL_DIR/release" ]]
[[ ! -e "$INSTALL_DIR/.git" ]]
[[ -x "$TEST_HOME/.local/bin/algen-pam" ]]
[[ -f "$CONFIG_FILE" ]]
[[ -f "$SERVICE_FILE" ]]
[[ -f "$PID_FILE" ]]
[[ ! -e "$INSTALL_DIR/.git" ]]
grep -Eq '^ALGEN_PAM_HOST="?0\.0\.0\.0"?$' "$CONFIG_FILE"
APP_PORT="$(sed -n 's/^ALGEN_PAM_PORT=//p' "$CONFIG_FILE" | tail -n 1 | tr -d '"')"
curl -fsS "http://127.0.0.1:$APP_PORT/api/health" | grep -F '"message":"ok"' >/dev/null
systemctl --user is-active --quiet algen-pam.service
systemctl --user is-enabled --quiet algen-pam.service
FIRST_PID="$(cat "$PID_FILE")"
kill -0 "$FIRST_PID"

printf '# integration-config-sentinel\n' >>"$CONFIG_FILE"
printf 'integration-data-sentinel\n' >"$INSTALL_DIR/data/integration-sentinel"

echo "[integration] unchanged update is a no-op"
bash "$INSTALLER" "${UPDATE_ARGS[@]}"

[[ -f "$PID_FILE" ]]
SECOND_PID="$(cat "$PID_FILE")"
[[ "$SECOND_PID" == "$FIRST_PID" ]]
kill -0 "$SECOND_PID"
systemctl --user is-active --quiet algen-pam.service
systemctl --user is-enabled --quiet algen-pam.service
curl -fsS "http://127.0.0.1:$APP_PORT/api/health" | grep -F '"message":"ok"' >/dev/null
grep -q '^# integration-config-sentinel$' "$CONFIG_FILE"
grep -q '^integration-data-sentinel$' "$INSTALL_DIR/data/integration-sentinel"
! grep -q '^PAM_DEFAULT_ADMIN_PASSWORD=' "$CONFIG_FILE"
[[ "$(stat -c '%a' "$CONFIG_FILE")" == 600 ]]
[[ "$(stat -c '%a' "$INSTALL_DIR/data")" == 700 ]]
grep -q '^app=algen-pam$' "$INSTALL_DIR/.algen-pam-install"
grep -Fqx "install_dir=$INSTALL_DIR" "$INSTALL_DIR/.algen-pam-install"
[[ ! -d "$TEST_HOME/.config/algen-pam/backups" ]]
grep -q "ExecStart=.*--host 0.0.0.0 --port $APP_PORT" "$SERVICE_FILE"
grep -q 'ExecStart=.*/bin/python -m uvicorn ' "$SERVICE_FILE"
grep -q '^NoNewPrivileges=true$' "$SERVICE_FILE"
grep -q '^ProtectSystem=strict$' "$SERVICE_FILE"
grep -q '^UMask=0077$' "$SERVICE_FILE"
grep -q "^EnvironmentFile=$CONFIG_FILE$" "$SERVICE_FILE"

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$SERVICE_FILE"
fi

echo "[integration] uninstall and service shutdown"
bash "$INSTALLER" --uninstall --user --yes --install-dir "$INSTALL_DIR"
[[ ! -e "$INSTALL_DIR" ]]
[[ ! -e "$SERVICE_FILE" ]]
[[ ! -e "$PID_FILE" ]]

echo "Installer integration tests passed."

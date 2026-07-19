#!/usr/bin/env bash
set -euo pipefail

APP_NAME="algen-pam"
APP_TITLE="Linux PAM Lite"
APP_VERSION="1.0.0"
DEFAULT_REPO_URL="https://github.com/chmajster/Algen-Privileged-Access-Management"
DEFAULT_BRANCH="main"

SILENT=0
ASSUME_YES=0
INSTALL_SCOPE=""
INSTALL_DIR=""
CREATE_SERVICE=""
CREATE_DESKTOP=""
REPO_URL="$DEFAULT_REPO_URL"
BRANCH_NAME=""
TAG_NAME=""
DO_UPDATE=0
DO_UNINSTALL=0
REINSTALL_APP=0
INSTALL_ACTION=""
DRY_RUN=0
VERBOSE=0
KEEP_CONFIG=0
KEEP_LOGS=0
PACKAGE_MANAGER=""
LOG_FILE=""
INSTALL_OWNER="${SUDO_USER:-${USER:-$(id -un)}}"
SERVICE_WAS_ACTIVE=0
TEMP_SERVER_PID=""
ADMIN_USER="${PAM_DEFAULT_ADMIN_USER:-admin}"
ADMIN_EMAIL="${PAM_DEFAULT_ADMIN_EMAIL:-admin@example.local}"
ADMIN_PASSWORD="${PAM_DEFAULT_ADMIN_PASSWORD:-}"
ADMIN_PASSWORD_GENERATED=0
ADMIN_PASSWORD_SUPPLIED=0
ADMIN_BOOTSTRAP=1
UPDATE_ADMIN_PASSWORD=0
APP_PORT="${ALGEN_PAM_PORT:-8080}"
APP_HOST="0.0.0.0"
GATEWAY_PORT="${PAM_GATEWAY_PORT:-2222}"
APP_PORT_EXPLICIT=0
GATEWAY_PORT_EXPLICIT=0
PORTS_CHECKED=0
[[ -n "${ALGEN_PAM_PORT:-}" ]] && APP_PORT_EXPLICIT=1
[[ -n "${PAM_GATEWAY_PORT:-}" ]] && GATEWAY_PORT_EXPLICIT=1
[[ -n "$ADMIN_PASSWORD" ]] && ADMIN_PASSWORD_SUPPLIED=1 && UPDATE_ADMIN_PASSWORD=1

abort() {
  echo "ERROR: $*" >&2
  exit 1
}

on_interrupt() {
  if [[ -n "$TEMP_SERVER_PID" ]]; then
    kill "$TEMP_SERVER_PID" 2>/dev/null || true
  fi
  echo
  abort "Installation interrupted."
}
trap on_interrupt INT TERM

usage() {
  cat <<'EOF'
Linux PAM Lite installer

Usage:
  ./install.sh [options]

Modes:
  --silent              run without UI and prompts
  --update              update an existing installation
  --uninstall           remove an existing installation

Confirmation:
  --yes, -y             accept requested operations
  --dry-run             print actions without changing files
  --verbose             show more detailed logs

Install target:
  --install-dir PATH    installation directory
  --user                install for the current user
  --system              install system-wide
  --port PORT           HTTP port (default: 8080)
  --gateway-port PORT   SSH gateway port (default: 2222)

Optional integration:
  --service             create and enable a systemd service
  --no-service          skip systemd service creation
  --desktop             create a desktop launcher
  --no-desktop          skip desktop launcher creation

Admin bootstrap:
  --admin-user NAME     create or update this local admin account
  --admin-email EMAIL   email address for the local admin account
  --admin-password PASS password for the local admin account
  --generate-admin-password
                       generate a random admin password

Source selection:
  --branch NAME         install from a branch
  --tag NAME            install from a tag
  --repo URL            override repository URL

Uninstall:
  --keep-config         keep configuration files
  --keep-logs           keep log files

Other:
  --help, -h            show this help

Examples:
  ./install.sh
  ./install.sh --silent --yes --user --no-service
  ./install.sh --silent --yes --admin-user admin --admin-password 'change-me-now'
  ./install.sh --silent --install-dir /opt/algen-pam --system --service --yes
  ./install.sh --update --system --yes
  ./install.sh --uninstall --user --yes
EOF
}

expand_path() {
  local path="$1"
  path="${path/#\~/$HOME}"
  printf '%s\n' "$path"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --silent) SILENT=1 ;;
      --yes|-y) ASSUME_YES=1 ;;
      --install-dir) shift; [[ $# -gt 0 ]] || abort "--install-dir requires PATH"; INSTALL_DIR="$(expand_path "$1")" ;;
      --user) INSTALL_SCOPE="user" ;;
      --system) INSTALL_SCOPE="system" ;;
      --port) shift; [[ $# -gt 0 ]] || abort "--port requires PORT"; APP_PORT="$1"; APP_PORT_EXPLICIT=1 ;;
      --gateway-port) shift; [[ $# -gt 0 ]] || abort "--gateway-port requires PORT"; GATEWAY_PORT="$1"; GATEWAY_PORT_EXPLICIT=1 ;;
      --service) CREATE_SERVICE=1 ;;
      --no-service) CREATE_SERVICE=0 ;;
      --desktop) CREATE_DESKTOP=1 ;;
      --no-desktop) CREATE_DESKTOP=0 ;;
      --admin-user) shift; [[ $# -gt 0 ]] || abort "--admin-user requires NAME"; ADMIN_USER="$1" ;;
      --admin-email) shift; [[ $# -gt 0 ]] || abort "--admin-email requires EMAIL"; ADMIN_EMAIL="$1" ;;
      --admin-password) shift; [[ $# -gt 0 ]] || abort "--admin-password requires PASS"; ADMIN_PASSWORD="$1"; ADMIN_PASSWORD_GENERATED=0; ADMIN_PASSWORD_SUPPLIED=1; UPDATE_ADMIN_PASSWORD=1 ;;
      --generate-admin-password) ADMIN_PASSWORD=""; ADMIN_PASSWORD_GENERATED=1; ADMIN_PASSWORD_SUPPLIED=1; UPDATE_ADMIN_PASSWORD=1 ;;
      --branch) shift; [[ $# -gt 0 ]] || abort "--branch requires NAME"; BRANCH_NAME="$1" ;;
      --tag) shift; [[ $# -gt 0 ]] || abort "--tag requires NAME"; TAG_NAME="$1" ;;
      --repo) shift; [[ $# -gt 0 ]] || abort "--repo requires URL"; REPO_URL="$1" ;;
      --update) DO_UPDATE=1 ;;
      --uninstall) DO_UNINSTALL=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --verbose) VERBOSE=1 ;;
      --keep-config) KEEP_CONFIG=1 ;;
      --keep-logs) KEEP_LOGS=1 ;;
      --help|-h) usage; exit 0 ;;
      *) abort "Unknown argument: $1" ;;
    esac
    shift
  done

  [[ -z "$BRANCH_NAME" || -z "$TAG_NAME" ]] || abort "Use either --branch or --tag, not both."
  [[ "$DO_UPDATE" -eq 0 || "$DO_UNINSTALL" -eq 0 ]] || abort "Use either --update or --uninstall, not both."
  validate_port "$APP_PORT" "--port"
  validate_port "$GATEWAY_PORT" "--gateway-port"
  if [[ "$SILENT" -eq 1 && "$ASSUME_YES" -eq 0 && "$DRY_RUN" -eq 0 ]]; then
    abort "--silent requires --yes unless --dry-run is used."
  fi
}

validate_port() {
  local port="$1"
  local option="$2"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) \
    || abort "$option must be an integer between 1 and 65535."
}

generate_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 18
  else
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(27))
PY
  fi
}

is_system_install() {
  [[ "$INSTALL_SCOPE" == "system" ]]
}

resolve_paths() {
  if [[ -z "$INSTALL_SCOPE" ]]; then
    INSTALL_SCOPE="user"
  fi

  if is_system_install; then
    INSTALL_DIR="${INSTALL_DIR:-/opt/algen-pam}"
    BIN_PATH="/usr/local/bin/algen-pam"
    CONFIG_DIR="/etc/algen-pam"
    LOG_DIR="/var/log/algen-pam"
    DESKTOP_FILE="/usr/local/share/applications/algen-pam.desktop"
    SERVICE_FILE="/etc/systemd/system/algen-pam.service"
    SYSTEMD_USER=0
  else
    INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/algen-pam}"
    BIN_PATH="$HOME/.local/bin/algen-pam"
    CONFIG_DIR="$HOME/.config/algen-pam"
    LOG_DIR="$HOME/.local/state/algen-pam/logs"
    DESKTOP_FILE="$HOME/.local/share/applications/algen-pam.desktop"
    SERVICE_FILE="$HOME/.config/systemd/user/algen-pam.service"
    SYSTEMD_USER=1
  fi

  DATA_DIR="$INSTALL_DIR/data"
  CONFIG_FILE="$CONFIG_DIR/.env"
  LOG_FILE="$LOG_DIR/install.log"
}

configured_value() {
  local key="$1"
  [[ -f "$CONFIG_FILE" ]] || return 1
  sed -n "s/^${key}=//p" "$CONFIG_FILE" | tail -n 1
}

load_configured_ports() {
  local configured=""
  if [[ "$APP_PORT_EXPLICIT" -eq 0 ]]; then
    configured="$(configured_value "ALGEN_PAM_PORT" || true)"
    [[ -z "$configured" ]] || APP_PORT="$configured"
  fi
  if [[ "$GATEWAY_PORT_EXPLICIT" -eq 0 ]]; then
    configured="$(configured_value "PAM_GATEWAY_PORT" || true)"
    [[ -z "$configured" ]] || GATEWAY_PORT="$configured"
  fi
  validate_port "$APP_PORT" "configured HTTP port"
  validate_port "$GATEWAY_PORT" "configured gateway port"
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk -v port="$port" '
      { address=$4; sub(/^.*:/, "", address); if (address == port) found=1 }
      END { exit(found ? 0 : 1) }
    '
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | grep -q .
    return $?
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$port" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    raise SystemExit(0)
finally:
    sock.close()
raise SystemExit(1)
PY
    return $?
  fi
  log "Warning: cannot check port $port because ss, lsof, and python3 are unavailable."
  return 1
}

find_available_port() {
  local start="$1"
  local candidate="$start"
  local reserved="${2:-0}"
  while (( candidate <= 65535 )); do
    if [[ "$candidate" -ne "$reserved" ]] && ! port_in_use "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    ((candidate += 1))
  done
  candidate=1024
  while (( candidate < start && candidate <= 65535 )); do
    if [[ "$candidate" -ne "$reserved" ]] && ! port_in_use "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    ((candidate += 1))
  done
  abort "No free TCP port found."
}

choose_port() {
  local label="$1"
  local current="$2"
  local reserved="${3:-0}"
  local output_var="$4"
  local candidate="$current"

  if [[ "$current" -eq "$reserved" ]] || port_in_use "$current"; then
    candidate="$(find_available_port "$((current + 1))" "$reserved")"
    if [[ "$SILENT" -eq 1 ]]; then
      log "$label port $current is already in use; selecting available port $candidate."
    else
      while true; do
        candidate="$(ui_input "Port conflict" "$label port $current is already in use. Choose another port" "$candidate")"
        if [[ "$candidate" =~ ^[0-9]+$ ]] && (( candidate >= 1 && candidate <= 65535 )) \
          && [[ "$candidate" -ne "$reserved" ]] && ! port_in_use "$candidate"; then
          break
        fi
        ui_msg "Port conflict" "Port $candidate is invalid or already in use."
        candidate="$(find_available_port "$((current + 1))" "$reserved")"
      done
    fi
  fi
  printf -v "$output_var" '%s' "$candidate"
}

choose_ports() {
  [[ "$PORTS_CHECKED" -eq 0 ]] || return 0
  choose_port "HTTP" "$APP_PORT" "$GATEWAY_PORT" APP_PORT
  choose_port "SSH gateway" "$GATEWAY_PORT" "$APP_PORT" GATEWAY_PORT
  APP_PORT_EXPLICIT=1
  GATEWAY_PORT_EXPLICIT=1
  PORTS_CHECKED=1
}

sudo_cmd() {
  if is_system_install; then
    command -v sudo >/dev/null 2>&1 || abort "System installation requires sudo."
    sudo "$@"
  else
    "$@"
  fi
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
    return 0
  fi
  [[ "$VERBOSE" -eq 1 ]] && echo "+ $*"
  "$@"
}

run_privileged() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $(is_system_install && printf 'sudo ')$*"
    return 0
  fi
  if is_system_install; then
    [[ "$VERBOSE" -eq 1 ]] && echo "+ sudo $*"
    sudo_cmd "$@"
  else
    [[ "$VERBOSE" -eq 1 ]] && echo "+ $*"
    "$@"
  fi
}

log() {
  local line
  line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$line"
  if [[ -n "$LOG_FILE" && "$DRY_RUN" -eq 0 && -d "$(dirname "$LOG_FILE")" ]]; then
    printf '%s\n' "$line" >>"$LOG_FILE" || true
  fi
}

confirm() {
  local prompt="$1"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  [[ "$SILENT" -eq 0 ]] || abort "$prompt Use --yes to accept in silent mode."
  read -r -p "$prompt [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" || "$answer" == "YES" ]]
}

ensure_admin_settings() {
  if [[ "$DO_UNINSTALL" -eq 1 ]]; then
    return 0
  fi
  if [[ "$DO_UPDATE" -eq 1 && "$ADMIN_PASSWORD_SUPPLIED" -eq 0 ]]; then
    ADMIN_BOOTSTRAP=0
    return 0
  fi
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(generate_password)"
    ADMIN_PASSWORD_GENERATED=1
  fi
  if [[ "${#ADMIN_PASSWORD}" -lt 6 ]]; then
    abort "Admin password must have at least 6 characters."
  fi
  [[ -n "$ADMIN_USER" ]] || abort "Admin username cannot be empty."
  [[ -n "$ADMIN_EMAIL" ]] || abort "Admin email cannot be empty."
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PACKAGE_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PACKAGE_MANAGER="dnf"
  elif command -v pacman >/dev/null 2>&1; then
    PACKAGE_MANAGER="pacman"
  else
    PACKAGE_MANAGER=""
  fi
}

package_list() {
  case "$PACKAGE_MANAGER" in
    apt) echo "python3 python3-venv python3-pip curl ca-certificates tar unzip git" ;;
    dnf) echo "python3 python3-pip curl ca-certificates tar unzip git" ;;
    pacman) echo "python python-pip curl ca-certificates tar unzip git" ;;
    *) echo "" ;;
  esac
}

install_command_for_packages() {
  local packages="$1"
  case "$PACKAGE_MANAGER" in
    apt) echo "sudo apt-get update && sudo apt-get install -y $packages" ;;
    dnf) echo "sudo dnf install -y $packages" ;;
    pacman) echo "sudo pacman -Sy --needed --noconfirm $packages" ;;
    *) echo "" ;;
  esac
}

check_system() {
  log "Checking Linux system and dependencies."
  [[ "$(uname -s)" == "Linux" ]] || abort "This installer is intended for Linux."
  detect_package_manager
  [[ -n "$PACKAGE_MANAGER" ]] || abort "Unsupported distribution: apt, dnf, or pacman is required."

  if command -v python3 >/dev/null 2>&1; then
    local py_version
    py_version="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
    log "Found Python $py_version."
    python3 - <<'PY' || log "Warning: Python 3.12 is recommended by the project documentation."
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY
  fi
}

install_dependencies() {
  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=("python3")
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing+=("curl")
  command -v tar >/dev/null 2>&1 || missing+=("tar")

  if [[ "${#missing[@]}" -eq 0 ]] && python3 -m venv --help >/dev/null 2>&1; then
    log "System dependencies look ready."
    return 0
  fi

  local packages
  packages="$(package_list)"
  [[ -n "$packages" ]] || abort "Cannot install dependencies automatically on this system."
  local manual_cmd
  manual_cmd="$(install_command_for_packages "$packages")"

  if confirm "Install missing system dependencies using $PACKAGE_MANAGER?"; then
    case "$PACKAGE_MANAGER" in
      apt)
        run_privileged apt-get update
        run_privileged apt-get install -y $packages
        ;;
      dnf) run_privileged dnf install -y $packages ;;
      pacman) run_privileged pacman -Sy --needed --noconfirm $packages ;;
    esac
  else
    abort "Install dependencies manually and rerun: $manual_cmd"
  fi
}

ui_msg() {
  local title="$1"
  local message="$2"
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "$title" --msgbox "$message" 12 72
  elif command -v dialog >/dev/null 2>&1; then
    dialog --title "$title" --msgbox "$message" 12 72
  else
    printf '\n%s\n%s\n\n' "$title" "$message"
  fi
}

ui_yesno() {
  local title="$1"
  local message="$2"
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "$title" --yesno "$message" 12 72
  elif command -v dialog >/dev/null 2>&1; then
    dialog --title "$title" --yesno "$message" 12 72
  else
    read -r -p "$message [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" || "$answer" == "YES" ]]
  fi
}

ui_input() {
  local title="$1"
  local message="$2"
  local default="$3"
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "$title" --inputbox "$message" 12 72 "$default" 3>&1 1>&2 2>&3
  elif command -v dialog >/dev/null 2>&1; then
    dialog --title "$title" --inputbox "$message" 12 72 "$default" 3>&1 1>&2 2>&3
  else
    read -r -p "$message [$default] " answer
    printf '%s\n' "${answer:-$default}"
  fi
}

ui_password() {
  local title="$1"
  local message="$2"
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "$title" --passwordbox "$message" 12 72 3>&1 1>&2 2>&3
  elif command -v dialog >/dev/null 2>&1; then
    dialog --title "$title" --passwordbox "$message" 12 72 3>&1 1>&2 2>&3
  else
    local answer
    read -r -s -p "$message " answer
    printf '\n' >&2
    printf '%s\n' "$answer"
  fi
}

ui_choose_scope() {
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "Installation mode" --menu "Choose installation scope" 15 72 2 \
      user "Current user" \
      system "System-wide (/opt, /etc, /usr/local/bin)" 3>&1 1>&2 2>&3
  elif command -v dialog >/dev/null 2>&1; then
    dialog --title "Installation mode" --menu "Choose installation scope" 15 72 2 \
      user "Current user" \
      system "System-wide (/opt, /etc, /usr/local/bin)" 3>&1 1>&2 2>&3
  else
    read -r -p "Install for current user or system-wide? [user/system] " answer
    [[ "$answer" == "system" ]] && printf 'system\n' || printf 'user\n'
  fi
}

installation_present() {
  [[ -f "$INSTALL_DIR/.algen-pam-install" ]] \
    || { [[ -f "$CONFIG_FILE" ]] && [[ -e "$BIN_PATH" || -f "$SERVICE_FILE" ]]; }
}

detect_installed_scope() {
  [[ -z "$INSTALL_SCOPE" && -z "$INSTALL_DIR" ]] || return 0
  if [[ -f "$HOME/.local/share/algen-pam/.algen-pam-install" ]] \
    || { [[ -f "$HOME/.config/algen-pam/.env" ]] && [[ -e "$HOME/.local/bin/algen-pam" ]]; }; then
    INSTALL_SCOPE="user"
  elif [[ -f "/opt/algen-pam/.algen-pam-install" ]] \
    || { [[ -f "/etc/algen-pam/.env" ]] && [[ -e "/usr/local/bin/algen-pam" ]]; }; then
    INSTALL_SCOPE="system"
  fi
}

choose_existing_install_action() {
  local action=""
  printf '\nExisting %s installation detected in %s.\n\n' "$APP_TITLE" "$INSTALL_DIR"
  cat <<'EOF'
Choose action (automatic update starts after 5 seconds):
  1) Update application (backup and keep config)
  2) Reinstall application (clean app files; keep config, data, and logs)
  3) Backup config only
  4) Remove app (keep config, data, and logs)
  5) Remove app and all files
  6) Abort
EOF
  if ! read -r -t 5 -p "Action [1] (auto update in 5s): " action; then
    printf '\n'
    action="1"
  fi
  action="${action:-1}"
  while [[ ! "$action" =~ ^[1-6]$ ]]; do
    read -r -p "Choose an action from 1 to 6: " action
  done

  case "$action" in
    1) INSTALL_ACTION="update"; DO_UPDATE=1 ;;
    2) INSTALL_ACTION="reinstall"; DO_UPDATE=1; REINSTALL_APP=1 ;;
    3) INSTALL_ACTION="backup" ;;
    4) INSTALL_ACTION="remove_keep" ;;
    5) INSTALL_ACTION="remove_all"; DO_UNINSTALL=1 ;;
    6) abort "No changes were made." ;;
  esac
  ASSUME_YES=1
}

ui_flow() {
  if [[ ! -t 0 ]]; then
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    abort "No interactive terminal detected. Use --silent --yes."
  fi

  ui_msg "Welcome" "This installer will install $APP_TITLE from $REPO_URL."
  check_system
  if [[ -z "$INSTALL_SCOPE" ]]; then
    INSTALL_SCOPE="$(ui_choose_scope)"
  fi
  resolve_paths
  INSTALL_DIR="$(ui_input "Install directory" "Choose installation directory" "$INSTALL_DIR")"
  resolve_paths
  if installation_present; then
    choose_existing_install_action
    return 0
  fi
  ADMIN_USER="$(ui_input "Admin account" "Admin username" "$ADMIN_USER")"
  ADMIN_EMAIL="$(ui_input "Admin account" "Admin email" "$ADMIN_EMAIL")"
  ADMIN_PASSWORD="$(ui_password "Admin account" "Admin password. Leave empty to generate one.")"
  if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD="$(generate_password)"
    ADMIN_PASSWORD_GENERATED=1
  else
    ADMIN_PASSWORD_SUPPLIED=1
    UPDATE_ADMIN_PASSWORD=1
  fi
  CREATE_SERVICE=0
  CREATE_DESKTOP=0
  if ui_yesno "systemd" "Create and enable a systemd service?"; then
    CREATE_SERVICE=1
  fi
  if ui_yesno "Desktop launcher" "Create a .desktop launcher for the web UI?"; then
    CREATE_DESKTOP=1
  fi
  resolve_paths
  load_configured_ports
  choose_ports
  local summary
  summary="Scope: $INSTALL_SCOPE
Install dir: $INSTALL_DIR
Config dir: $CONFIG_DIR
Log file: $LOG_FILE
HTTP port: $APP_PORT
SSH gateway port: $GATEWAY_PORT
Admin user: $ADMIN_USER <$ADMIN_EMAIL>
systemd service: $CREATE_SERVICE
Desktop launcher: $CREATE_DESKTOP"
  ui_msg "Summary" "$summary"
  ui_yesno "Confirm" "Start installation now?" || abort "Installation cancelled."
  ASSUME_YES=1
}

prepare_logging() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] log file: $LOG_FILE"
    return 0
  fi
  run_privileged mkdir -p "$LOG_DIR"
  run_privileged touch "$LOG_FILE"
  if is_system_install; then
    run_privileged chown "$INSTALL_OWNER" "$LOG_FILE"
  fi
  log "Logging to $LOG_FILE."
}

prepare_directories() {
  log "Preparing installation directories."
  run_privileged mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$(dirname "$BIN_PATH")"
  if [[ "$CREATE_DESKTOP" == "1" ]]; then
    run_privileged mkdir -p "$(dirname "$DESKTOP_FILE")"
  fi
  if [[ "$SYSTEMD_USER" -eq 1 && "$CREATE_SERVICE" == "1" ]]; then
    run mkdir -p "$(dirname "$SERVICE_FILE")"
  fi
  if is_system_install; then
    run_privileged chown -R "$INSTALL_OWNER" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
  fi
}

archive_url() {
  local ref_kind="heads"
  local ref_name="${BRANCH_NAME:-$DEFAULT_BRANCH}"
  if [[ -n "$TAG_NAME" ]]; then
    ref_kind="tags"
    ref_name="$TAG_NAME"
  fi
  local clean_repo="${REPO_URL%.git}"
  printf '%s/archive/refs/%s/%s.tar.gz\n' "$clean_repo" "$ref_kind" "$ref_name"
}

download_archive() {
  local destination="$1"
  local url
  url="$(archive_url)"
  local tmp_archive
  tmp_archive="$(mktemp)"
  log "Downloading source archive from $url."
  if command -v curl >/dev/null 2>&1; then
    run curl -fsSL "$url" -o "$tmp_archive"
  elif command -v wget >/dev/null 2>&1; then
    run wget -q "$url" -O "$tmp_archive"
  else
    abort "curl or wget is required to download source archives."
  fi
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  run tar -xzf "$tmp_archive" -C "$tmp_dir"
  local extracted
  extracted="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [[ -n "$extracted" ]] || abort "Downloaded archive did not contain a source directory."
  run mkdir -p "$destination"
  run cp -a "$extracted"/. "$destination"/
  run rm -f "$tmp_archive"
  run rm -rf "$tmp_dir"
}

fetch_source() {
  log "Fetching application source."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] fetch $REPO_URL into $INSTALL_DIR"
    return 0
  fi
  if command -v git >/dev/null 2>&1; then
    if [[ -d "$INSTALL_DIR/.git" ]]; then
      log "Updating existing git checkout in $INSTALL_DIR."
      run git -C "$INSTALL_DIR" fetch --tags --prune
      if [[ -n "$TAG_NAME" ]]; then
        run git -C "$INSTALL_DIR" checkout "$TAG_NAME"
      elif [[ -n "$BRANCH_NAME" ]]; then
        run git -C "$INSTALL_DIR" checkout "$BRANCH_NAME"
        run git -C "$INSTALL_DIR" pull --ff-only
      else
        run git -C "$INSTALL_DIR" pull --ff-only
      fi
    elif [[ -z "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1)" ]]; then
      local ref_args=()
      if [[ -n "$TAG_NAME" ]]; then
        ref_args=(--branch "$TAG_NAME")
      elif [[ -n "$BRANCH_NAME" ]]; then
        ref_args=(--branch "$BRANCH_NAME")
      fi
      run git clone --depth 1 "${ref_args[@]}" "$REPO_URL" "$INSTALL_DIR"
    else
      log "Install directory is not empty and is not a git checkout; refreshing files from a temporary clone."
      local tmp_dir
      tmp_dir="$(mktemp -d)"
      local ref_args=()
      if [[ -n "$TAG_NAME" ]]; then
        ref_args=(--branch "$TAG_NAME")
      elif [[ -n "$BRANCH_NAME" ]]; then
        ref_args=(--branch "$BRANCH_NAME")
      fi
      run git clone --depth 1 "${ref_args[@]}" "$REPO_URL" "$tmp_dir"
      run cp -a "$tmp_dir"/. "$INSTALL_DIR"/
      run rm -rf "$tmp_dir"
    fi
  else
    download_archive "$INSTALL_DIR"
  fi
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed 's/[&|\\]/\\&/g')"
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

configure_app() {
  log "Preparing configuration."
  local config_created=0
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] create or preserve $CONFIG_FILE"
    echo "[dry-run] link $INSTALL_DIR/.env -> $CONFIG_FILE"
    return 0
  fi

  if [[ ! -f "$CONFIG_FILE" ]]; then
    config_created=1
    if [[ -f "$INSTALL_DIR/.env.example" ]]; then
      cp "$INSTALL_DIR/.env.example" "$CONFIG_FILE"
    else
      touch "$CONFIG_FILE"
    fi
    set_env_value "$CONFIG_FILE" "DATABASE_URL" "sqlite:///$DATA_DIR/pam_lite.db"
    set_env_value "$CONFIG_FILE" "PAM_GATEWAY_HOST_KEY_PATH" "$DATA_DIR/gateway_host_key"
    if ! grep -q '^SECRET_KEY=change-me$' "$CONFIG_FILE"; then
      :
    elif command -v openssl >/dev/null 2>&1; then
      set_env_value "$CONFIG_FILE" "SECRET_KEY" "$(openssl rand -hex 32)"
    fi
  else
    log "Keeping existing config at $CONFIG_FILE."
  fi

  set_env_value "$CONFIG_FILE" "PAM_DEFAULT_ADMIN_USER" "$ADMIN_USER"
  set_env_value "$CONFIG_FILE" "PAM_DEFAULT_ADMIN_EMAIL" "$ADMIN_EMAIL"
  set_env_value "$CONFIG_FILE" "ALGEN_PAM_HOST" "$APP_HOST"
  set_env_value "$CONFIG_FILE" "ALGEN_PAM_PORT" "$APP_PORT"
  set_env_value "$CONFIG_FILE" "PAM_GATEWAY_PORT" "$GATEWAY_PORT"
  if [[ "$config_created" -eq 1 ]]; then
    set_env_value "$CONFIG_FILE" "PAM_OIDC_REDIRECT_URI" "http://localhost:$APP_PORT/auth/oidc/callback"
  fi
  if [[ "$config_created" -eq 1 || "$ADMIN_PASSWORD_SUPPLIED" -eq 1 ]]; then
    set_env_value "$CONFIG_FILE" "PAM_DEFAULT_ADMIN_PASSWORD" "$ADMIN_PASSWORD"
  fi

  rm -f "$INSTALL_DIR/.env"
  ln -s "$CONFIG_FILE" "$INSTALL_DIR/.env"
  touch "$INSTALL_DIR/.algen-pam-install"
}

build_app() {
  log "Creating Python virtual environment and installing application dependencies."
  [[ -f "$INSTALL_DIR/backend/requirements.txt" || "$DRY_RUN" -eq 1 ]] || abort "backend/requirements.txt not found in $INSTALL_DIR."
  run python3 -m venv "$INSTALL_DIR/backend/.venv"
  run "$INSTALL_DIR/backend/.venv/bin/python" -m pip install --upgrade pip
  run "$INSTALL_DIR/backend/.venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"
}

bootstrap_admin() {
  [[ "$ADMIN_BOOTSTRAP" -eq 1 ]] || return 0
  log "Creating or updating local admin account."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] bootstrap admin account $ADMIN_USER <$ADMIN_EMAIL>"
    return 0
  fi
  local update_args=()
  [[ "$UPDATE_ADMIN_PASSWORD" -eq 1 ]] && update_args=(--update-password)
  (
    cd "$INSTALL_DIR/backend"
    "$INSTALL_DIR/backend/.venv/bin/python" -m app.bootstrap_admin \
      --username "$ADMIN_USER" \
      --email "$ADMIN_EMAIL" \
      --password "$ADMIN_PASSWORD" \
      "${update_args[@]}"
  )
}

write_file_privileged() {
  local target="$1"
  local mode="$2"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] write $target"
    rm -f "$tmp"
    return 0
  fi
  if is_system_install && [[ "$target" != "$INSTALL_DIR"* && "$target" != "$CONFIG_DIR"* && "$target" != "$LOG_DIR"* ]]; then
    sudo_cmd install -m "$mode" "$tmp" "$target"
  else
    install -m "$mode" "$tmp" "$target"
  fi
  rm -f "$tmp"
}

create_launcher() {
  log "Creating command launcher at $BIN_PATH."
  write_file_privileged "$BIN_PATH" "0755" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "--version" ]]; then
  echo "$APP_NAME $APP_VERSION"
  exit 0
fi
cd "$INSTALL_DIR/backend"
exec "$INSTALL_DIR/backend/.venv/bin/uvicorn" app.main:app --host "\${ALGEN_PAM_HOST:-0.0.0.0}" --port "\${ALGEN_PAM_PORT:-$APP_PORT}" "\$@"
EOF
}

systemctl_cmd() {
  if [[ "$SYSTEMD_USER" -eq 1 ]]; then
    systemctl --user "$@"
  else
    sudo_cmd systemctl "$@"
  fi
}

service_exists() {
  [[ -f "$SERVICE_FILE" ]]
}

service_is_active() {
  if [[ "$SYSTEMD_USER" -eq 1 ]]; then
    systemctl --user is-active --quiet algen-pam.service 2>/dev/null
  else
    systemctl is-active --quiet algen-pam.service 2>/dev/null
  fi
}

stop_service_if_needed() {
  if service_is_active; then
    SERVICE_WAS_ACTIVE=1
    log "Stopping running systemd service."
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "[dry-run] systemctl stop algen-pam.service"
    else
      systemctl_cmd stop algen-pam.service || true
    fi
  fi
}

create_service() {
  [[ "$CREATE_SERVICE" == "1" ]] || return 0
  command -v systemctl >/dev/null 2>&1 || abort "systemctl not found; rerun with --no-service."
  log "Creating systemd service at $SERVICE_FILE."
  local user_line=""
  local wanted_by="default.target"
  if [[ "$SYSTEMD_USER" -eq 0 ]]; then
    user_line="User=$INSTALL_OWNER"
    wanted_by="multi-user.target"
  fi
  write_file_privileged "$SERVICE_FILE" "0644" <<EOF
[Unit]
Description=$APP_TITLE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
$user_line
WorkingDirectory=$INSTALL_DIR/backend
EnvironmentFile=$CONFIG_FILE
ExecStart=$INSTALL_DIR/backend/.venv/bin/uvicorn app.main:app --host $APP_HOST --port $APP_PORT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=$wanted_by
EOF
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] systemctl daemon-reload"
    echo "[dry-run] systemctl enable --now algen-pam.service"
  else
    systemctl_cmd daemon-reload
    systemctl_cmd enable --now algen-pam.service
  fi
}

create_desktop_launcher() {
  [[ "$CREATE_DESKTOP" == "1" ]] || return 0
  log "Creating desktop launcher at $DESKTOP_FILE."
  write_file_privileged "$DESKTOP_FILE" "0644" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_TITLE
Comment=Open the Linux PAM Lite web interface
Exec=xdg-open http://127.0.0.1:$APP_PORT/
Terminal=false
Categories=System;Security;
EOF
}

validate_installation() {
  log "Validating installation."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] validate launcher, version, service status, and HTTP health endpoint"
    return 0
  fi
  [[ -x "$BIN_PATH" ]] || abort "Launcher was not created at $BIN_PATH."
  "$BIN_PATH" --version >/dev/null || log "Version check is not supported."
  if [[ "$CREATE_SERVICE" == "1" ]]; then
    systemctl_cmd status algen-pam.service --no-pager || true
    wait_for_health || abort "Application service started but http://127.0.0.1:$APP_PORT/api/health did not respond. Check $LOG_FILE and the systemd journal."
  else
    validate_temporary_server
  fi
}

wait_for_health() {
  local attempt
  for attempt in {1..30}; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1; then
      log "Application health check passed on port $APP_PORT."
      return 0
    fi
    sleep 1
  done
  return 1
}

validate_temporary_server() {
  local validation_log="$LOG_DIR/validation.log"
  log "Starting a temporary application process for the health check."
  ALGEN_PAM_HOST="127.0.0.1" ALGEN_PAM_PORT="$APP_PORT" "$BIN_PATH" >"$validation_log" 2>&1 &
  TEMP_SERVER_PID=$!
  if wait_for_health; then
    kill "$TEMP_SERVER_PID" 2>/dev/null || true
    wait "$TEMP_SERVER_PID" 2>/dev/null || true
    TEMP_SERVER_PID=""
    log "Temporary validation process stopped."
    return 0
  fi
  kill "$TEMP_SERVER_PID" 2>/dev/null || true
  wait "$TEMP_SERVER_PID" 2>/dev/null || true
  TEMP_SERVER_PID=""
  abort "Application did not pass its health check. See $validation_log."
}

primary_ip_address() {
  local address=""
  if command -v hostname >/dev/null 2>&1; then
    address="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [[ -z "$address" ]] && command -v ip >/dev/null 2>&1; then
    address="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"
  fi
  printf '%s\n' "$address"
}

safe_remove_dir() {
  local dir="$1"
  [[ -n "$dir" && "$dir" != "/" && "$dir" != "$HOME" ]] || abort "Refusing to remove unsafe directory: $dir"
  if [[ ! -e "$dir" ]]; then
    return 0
  fi
  if [[ -f "$dir/.algen-pam-install" \
    || "$dir" == "/opt/algen-pam" \
    || "$dir" == "$HOME/.local/share/algen-pam" \
    || "$dir" == "/etc/algen-pam" \
    || "$dir" == "$HOME/.config/algen-pam" \
    || "$dir" == "/var/log/algen-pam" \
    || "$dir" == "$HOME/.local/state/algen-pam/logs" ]]; then
    run_privileged rm -rf "$dir"
  else
    abort "Refusing to remove $dir because it does not look like an Algen-PAM installation."
  fi
}

backup_config() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    log "No configuration file found at $CONFIG_FILE; backup skipped."
    return 0
  fi
  local backup_dir="$CONFIG_DIR/backups"
  local backup_file="$backup_dir/.env.$(date '+%Y%m%d-%H%M%S').bak"
  run_privileged mkdir -p "$backup_dir"
  run_privileged cp -p "$CONFIG_FILE" "$backup_file"
  log "Configuration backup created at $backup_file."
}

validate_cleanup_target() {
  [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" && "$INSTALL_DIR" != "$HOME" ]] \
    || abort "Refusing to clean unsafe installation directory: $INSTALL_DIR"
  [[ -f "$INSTALL_DIR/.algen-pam-install" \
    || "$INSTALL_DIR" == "/opt/algen-pam" \
    || "$INSTALL_DIR" == "$HOME/.local/share/algen-pam" ]] \
    || abort "Refusing to clean $INSTALL_DIR because it does not look like an Algen-PAM installation."
}

clean_application_files_keep_data() {
  validate_cleanup_target
  log "Removing application files while preserving $DATA_DIR."
  local entry
  while IFS= read -r -d '' entry; do
    run_privileged rm -rf "$entry"
  done < <(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 \
    ! -name "data" ! -name ".algen-pam-install" -print0)
}

remove_service_integration() {
  stop_service_if_needed
  if service_exists; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "[dry-run] systemctl disable algen-pam.service"
      echo "[dry-run] remove $SERVICE_FILE"
    else
      systemctl_cmd disable algen-pam.service || true
      run_privileged rm -f "$SERVICE_FILE"
      systemctl_cmd daemon-reload || true
    fi
  fi
  run_privileged rm -f "$BIN_PATH"
  run_privileged rm -f "$DESKTOP_FILE"
}

remove_application_keep_state() {
  prepare_logging
  log "Removing $APP_TITLE while keeping configuration, data, and logs."
  remove_service_integration
  clean_application_files_keep_data
  run_privileged rm -f "$INSTALL_DIR/.algen-pam-install"
  log "Application removed. Preserved: $CONFIG_DIR, $DATA_DIR, and $LOG_DIR."
}

uninstall_app() {
  prepare_logging
  log "Uninstalling $APP_TITLE."
  remove_service_integration
  safe_remove_dir "$INSTALL_DIR"
  if [[ "$KEEP_CONFIG" -eq 0 ]]; then
    safe_remove_dir "$CONFIG_DIR"
  fi
  if [[ "$KEEP_LOGS" -eq 0 ]]; then
    safe_remove_dir "$LOG_DIR"
  fi
  log "Uninstall complete."
}

install_app() {
  prepare_logging
  if [[ "$INSTALL_ACTION" == "update" ]]; then
    backup_config
  fi
  check_system
  install_dependencies
  if [[ "$DO_UPDATE" -eq 1 ]]; then
    stop_service_if_needed
  fi
  if [[ "$REINSTALL_APP" -eq 1 ]]; then
    clean_application_files_keep_data
  fi
  prepare_directories
  choose_ports
  fetch_source
  configure_app
  build_app
  bootstrap_admin
  create_launcher
  create_service
  create_desktop_launcher
  validate_installation
  if [[ "$DO_UPDATE" -eq 1 && "$SERVICE_WAS_ACTIVE" -eq 1 && "$CREATE_SERVICE" != "1" && "$DRY_RUN" -eq 0 ]]; then
    log "Restarting service that was active before update."
    systemctl_cmd start algen-pam.service || true
  fi
  log "Installation complete."
}

print_final_info() {
  local network_ip
  network_ip="$(primary_ip_address)"
  cat <<EOF

$APP_TITLE is ready.

Run:
  $BIN_PATH

Open:
  http://127.0.0.1:$APP_PORT/

Network access (listening on all interfaces):
  http://${network_ip:-SERVER_IP}:$APP_PORT/

SSH gateway port:
  $GATEWAY_PORT

Config:
  $CONFIG_FILE

Admin:
  $ADMIN_USER <$ADMIN_EMAIL>

Log:
  $LOG_FILE
EOF
  if [[ "$ADMIN_PASSWORD_GENERATED" -eq 1 ]]; then
    cat <<EOF

Generated admin password:
  $ADMIN_PASSWORD
EOF
  fi
  if [[ "$CREATE_SERVICE" == "1" ]]; then
    if [[ "$SYSTEMD_USER" -eq 1 ]]; then
      cat <<'EOF'

Service commands:
  systemctl --user status algen-pam
  systemctl --user stop algen-pam
  systemctl --user start algen-pam
EOF
    else
      cat <<'EOF'

Service commands:
  sudo systemctl status algen-pam
  sudo systemctl stop algen-pam
  sudo systemctl start algen-pam
EOF
    fi
  fi
}

main() {
  parse_args "$@"
  detect_installed_scope
  if [[ "$SILENT" -eq 0 && "$DO_UNINSTALL" -eq 0 && "$DO_UPDATE" -eq 0 ]]; then
    ui_flow
  fi
  resolve_paths

  if [[ "$SILENT" -eq 1 && "$DO_UNINSTALL" -eq 0 && "$DO_UPDATE" -eq 0 ]] \
    && installation_present; then
    echo "Existing installation detected in $INSTALL_DIR; selecting automatic update."
    INSTALL_ACTION="update"
    DO_UPDATE=1
  fi
  if [[ "$DO_UPDATE" -eq 1 && -z "$INSTALL_ACTION" ]]; then
    INSTALL_ACTION="update"
  fi

  if [[ "$CREATE_SERVICE" == "" ]]; then
    CREATE_SERVICE=0
  fi
  if [[ "$CREATE_DESKTOP" == "" ]]; then
    CREATE_DESKTOP=0
  fi

  if [[ "$INSTALL_ACTION" == "backup" ]]; then
    prepare_logging
    backup_config
    log "Configuration-only backup complete."
    return 0
  fi
  if [[ "$INSTALL_ACTION" == "remove_keep" ]]; then
    remove_application_keep_state
    return 0
  fi

  if [[ "$DO_UNINSTALL" -eq 0 ]]; then
    load_configured_ports
  fi
  ensure_admin_settings

  if [[ "$DO_UNINSTALL" -eq 1 ]]; then
    confirm "Remove $APP_TITLE from $INSTALL_DIR?" || abort "Uninstall cancelled."
    uninstall_app
    return 0
  fi

  if [[ "$DO_UPDATE" -eq 1 ]]; then
    confirm "Update $APP_TITLE in $INSTALL_DIR?" || abort "Update cancelled."
  fi

  install_app
  print_final_info
}

main "$@"

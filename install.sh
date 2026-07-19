#!/usr/bin/env bash
set -Eeuo pipefail

# Algen PAM installer.  All mutations happen only after the execution summary
# has been accepted.  Keep this file self-contained so it can be piped to bash.

# ---- constants and installer state -----------------------------------------
readonly APP_ID="algen-pam"
readonly APP_TITLE="Algen PAM / Linux PAM Lite"
readonly INSTALLER_VERSION="2.0.0"
readonly DEFAULT_REPO="https://github.com/chmajster/Algen-Privileged-Access-Management"
readonly DEFAULT_BRANCH="main"
readonly REQUIRED_PYTHON_MINOR=12

MODE=""                       # install|update|reinstall|backup|remove-app|uninstall
MODE_EXPLICIT=0
SCOPE=""
SCOPE_EXPLICIT=0
SILENT=0
YES=0
DRY_RUN=0
VERBOSE=0
SERVICE_CHOICE=""
DESKTOP_CHOICE=0
AUTO_PORT=0
INSTALL_DIR=""
REPO="$DEFAULT_REPO"
BRANCH="$DEFAULT_BRANCH"
BRANCH_EXPLICIT=0
TAG=""
APP_HOST="0.0.0.0"
APP_PORT="${ALGEN_PAM_PORT:-8080}"
GATEWAY_PORT="${PAM_GATEWAY_PORT:-2222}"
APP_PORT_EXPLICIT=0
GATEWAY_PORT_EXPLICIT=0
ADMIN_USER="${PAM_DEFAULT_ADMIN_USER:-}"
ADMIN_EMAIL="${PAM_DEFAULT_ADMIN_EMAIL:-}"
ADMIN_PASSWORD=""
ADMIN_PASSWORD_GENERATED=0
ADMIN_PASSWORD_SUPPLIED=0
LOCAL_AUTH_MODE="${PAM_LOCAL_AUTH_MODE:-os}"
KEEP_CONFIG=0
KEEP_DATA=0
KEEP_LOGS=0

CONFIG_DIR=""; CONFIG_FILE=""; DATA_DIR=""; LOG_DIR=""; LOG_FILE=""
BIN_PATH=""; SERVICE_FILE=""; DESKTOP_FILE=""; SYSTEMD_USER=0
TARGET_USER=""; TARGET_HOME=""; TARGET_GROUP=""
STAGE_ROOT=""; STAGED_APP=""; RELEASE_BACKUP=""; DIAGNOSTIC_PATH=""
STATE_BACKUP_DIR=""
TEMP_SERVER_PID=""; SERVICE_WAS_ACTIVE=0; SERVICE_WAS_ENABLED=0
MUTATIONS_STARTED=0

# ---- logging, errors, and cleanup ------------------------------------------
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }
emit() {
  local level="$1"; shift
  [[ "$level" != DEBUG || "$VERBOSE" -eq 1 ]] || return 0
  local line
  line="[$(timestamp)] [$level] $*"
  printf '%s\n' "$line" >&2
  if [[ -n "$LOG_FILE" && -f "$LOG_FILE" && "$DRY_RUN" -eq 0 ]]; then
    printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
info() { emit INFO "$@"; }
warn() { emit WARN "$@"; }
debug() { emit DEBUG "$@"; }
die() {
  emit ERROR "$*"
  [[ -z "$LOG_FILE" ]] || printf 'Log: %s\n' "$LOG_FILE" >&2
  [[ -z "$DIAGNOSTIC_PATH" ]] || printf 'Diagnostic files: %s\n' "$DIAGNOSTIC_PATH" >&2
  printf 'Fix the reported condition and run the same command again.\n' >&2
  exit 1
}
cleanup() {
  local status=$?
  [[ -z "$TEMP_SERVER_PID" ]] || { kill "$TEMP_SERVER_PID" 2>/dev/null || true; wait "$TEMP_SERVER_PID" 2>/dev/null || true; }
  unset ADMIN_PASSWORD
  if [[ -n "$STAGE_ROOT" && -d "$STAGE_ROOT" ]]; then
    if [[ "$status" -eq 0 || "$MUTATIONS_STARTED" -eq 0 ]]; then
      rm -rf -- "$STAGE_ROOT" 2>/dev/null || true
    else
      DIAGNOSTIC_PATH="$STAGE_ROOT"
      printf '[%s] [WARN] Staging retained for diagnostics: %s\n' "$(timestamp)" "$STAGE_ROOT" >&2
    fi
  fi
}
interrupted() { warn "Operation interrupted; cleanup is running."; exit 130; }
trap cleanup EXIT
trap interrupted INT TERM

usage() {
  cat <<'EOF'
Algen PAM safe installer

Usage: ./install.sh [mode] [options]

Modes (exactly one; install/update is inferred when omitted):
  --install              install a new instance
  --update               stage and atomically update an existing instance
  --reinstall            replace application files, preserving state
  --backup               back up configuration and data
  --remove-app           remove code and integration, preserve state
  --uninstall            remove the complete installation

Operation:  --silent --yes --dry-run --verbose --auto-port
Target:     --user --system --install-dir PATH
             --service --no-service --desktop --no-desktop
Network:    --port PORT --gateway-port PORT
Source:     --repo URL_OR_PATH --branch NAME --tag NAME
Admin:      --admin-user NAME --admin-email EMAIL
             --admin-password PASS --generate-admin-password
Removal:    --keep-config --keep-data --keep-logs
Other:      --help, -h

Compatibility examples:
  ./install.sh
  ./install.sh --silent --yes --user --no-service
  ./install.sh --silent --yes --system --service
  ./install.sh --update --system --yes
  ./install.sh --uninstall --user --yes
  ./install.sh --dry-run
EOF
}

# ---- argument parsing and validation ---------------------------------------
select_mode() {
  local requested="$1"
  if [[ -n "$MODE" && "$MODE" != "$requested" ]]; then
    die "Conflicting modes: '$MODE' and '$requested'. Select exactly one mode."
  fi
  MODE="$requested"; MODE_EXPLICIT=1
}
need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value."; }
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install) select_mode install ;;
      --update) select_mode update ;;
      --reinstall) select_mode reinstall ;;
      --backup) select_mode backup ;;
      --remove-app) select_mode remove-app ;;
      --uninstall) select_mode uninstall ;;
      --silent) SILENT=1 ;;
      --yes|-y) YES=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --verbose) VERBOSE=1 ;;
      --auto-port) AUTO_PORT=1 ;;
      --user) [[ -z "$SCOPE" || "$SCOPE" == user ]] || die "Use either --user or --system."; SCOPE=user; SCOPE_EXPLICIT=1 ;;
      --system) [[ -z "$SCOPE" || "$SCOPE" == system ]] || die "Use either --user or --system."; SCOPE=system; SCOPE_EXPLICIT=1 ;;
      --install-dir) need_value "$@"; shift; INSTALL_DIR="$1" ;;
      --service) [[ "$SERVICE_CHOICE" != 0 ]] || die "Use either --service or --no-service."; SERVICE_CHOICE=1 ;;
      --no-service) [[ "$SERVICE_CHOICE" != 1 ]] || die "Use either --service or --no-service."; SERVICE_CHOICE=0 ;;
      --desktop) DESKTOP_CHOICE=1 ;;
      --no-desktop) DESKTOP_CHOICE=0 ;;
      --port) need_value "$@"; shift; APP_PORT="$1"; APP_PORT_EXPLICIT=1 ;;
      --gateway-port) need_value "$@"; shift; GATEWAY_PORT="$1"; GATEWAY_PORT_EXPLICIT=1 ;;
      --repo) need_value "$@"; shift; REPO="$1" ;;
      --branch) need_value "$@"; shift; BRANCH="$1"; BRANCH_EXPLICIT=1 ;;
      --tag) need_value "$@"; shift; TAG="$1" ;;
      --admin-user) need_value "$@"; shift; ADMIN_USER="$1" ;;
      --admin-email) need_value "$@"; shift; ADMIN_EMAIL="$1" ;;
      --admin-password) need_value "$@"; shift; ADMIN_PASSWORD="$1"; ADMIN_PASSWORD_SUPPLIED=1 ;;
      --generate-admin-password) ADMIN_PASSWORD_GENERATED=1 ;;
      --keep-config) KEEP_CONFIG=1 ;;
      --keep-data) KEEP_DATA=1 ;;
      --keep-logs) KEEP_LOGS=1 ;;
      --help|-h) usage; exit 0 ;;
      *) die "Unknown argument: $1" ;;
    esac
    shift
  done
}
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
validate_path_text() { [[ "$1" != *$'\n'* && "$1" != *$'\r'* && "$1" != *$'\0'* ]] || die "Path contains a forbidden control character."; }
validate_arguments() {
  [[ "$(uname -s)" == Linux || "$DRY_RUN" -eq 1 ]] || die "This installer supports Linux only."
  valid_port "$APP_PORT" || die "--port must be an integer from 1 to 65535."
  valid_port "$GATEWAY_PORT" || die "--gateway-port must be an integer from 1 to 65535."
  [[ "$APP_PORT" != "$GATEWAY_PORT" ]] || die "HTTP and SSH gateway ports must differ."
  [[ -z "$TAG" || "$BRANCH_EXPLICIT" -eq 0 ]] || die "Use either --branch or --tag, not both."
  [[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ && "$BRANCH" != *..* ]] || die "Invalid branch name."
  [[ -z "$TAG" || "$TAG" =~ ^[A-Za-z0-9._+-]+$ ]] || die "Invalid tag name."
  [[ "$REPO" != *$'\n'* && "$REPO" =~ ^(https://|ssh://|git@|file://|/|\./|\.\./) ]] || die "--repo must be an HTTPS/SSH Git URL or a local path."
  [[ "$LOCAL_AUTH_MODE" == os || "$LOCAL_AUTH_MODE" == database ]] || die "PAM_LOCAL_AUTH_MODE must be 'os' or 'database'."
  [[ "$SILENT" -eq 0 || "$YES" -eq 1 || "$DRY_RUN" -eq 1 ]] || die "--silent requires --yes (except with --dry-run)."
  [[ -z "$INSTALL_DIR" ]] || validate_path_text "$INSTALL_DIR"
  if [[ -n "$ADMIN_USER" ]]; then [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || die "Invalid administrator username."; fi
  if [[ -n "$ADMIN_EMAIL" ]]; then [[ "$ADMIN_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "Invalid administrator email."; fi
  [[ "$ADMIN_PASSWORD" != *$'\n'* && "$ADMIN_PASSWORD" != *$'\r'* ]] || die "Administrator password cannot contain a newline."
}

# ---- user, privileges, paths, and installation detection ------------------
passwd_home() { getent passwd "$1" 2>/dev/null | awk -F: '{print $6; exit}'; }
resolve_identity() {
  if [[ -z "$SCOPE" ]]; then SCOPE=system; fi
  if [[ "$SCOPE" == user ]]; then
    if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
      die "Do not run a --user installation through sudo; rerun it as ${SUDO_USER}."
    fi
    [[ "$(id -u)" -ne 0 ]] || die "A --user installation as root is ambiguous; use --system or a non-root account."
    TARGET_USER="$(id -un)"; TARGET_HOME="${HOME:-$(passwd_home "$TARGET_USER")}"; TARGET_GROUP="$(id -gn "$TARGET_USER")"
    [[ "$TARGET_HOME" == /* && "$TARGET_HOME" != / ]] || die "HOME must be a safe absolute path for a user installation."
  else
    if [[ "$(id -u)" -eq 0 ]]; then
      TARGET_USER="${SUDO_USER:-algen-pam}"
    else
      TARGET_USER="$(id -un)"
    fi
    TARGET_HOME="$(passwd_home "$TARGET_USER" || true)"; TARGET_GROUP="$(id -gn "$TARGET_USER" 2>/dev/null || printf '%s' "$TARGET_USER")"
  fi
  [[ "$SCOPE" != user || -n "$TARGET_HOME" ]] || die "Cannot resolve home directory for $TARGET_USER."
}
resolve_paths() {
  if [[ "$SCOPE" == system ]]; then
    INSTALL_DIR="${INSTALL_DIR:-/opt/algen-pam}"
    CONFIG_DIR=/etc/algen-pam; LOG_DIR=/var/log/algen-pam; BIN_PATH=/usr/local/bin/algen-pam
    SERVICE_FILE=/etc/systemd/system/algen-pam.service; DESKTOP_FILE=/usr/local/share/applications/algen-pam.desktop; SYSTEMD_USER=0
  else
    INSTALL_DIR="${INSTALL_DIR:-$TARGET_HOME/.local/share/algen-pam}"
    CONFIG_DIR="$TARGET_HOME/.config/algen-pam"; LOG_DIR="$TARGET_HOME/.local/state/algen-pam/logs"; BIN_PATH="$TARGET_HOME/.local/bin/algen-pam"
    SERVICE_FILE="$TARGET_HOME/.config/systemd/user/algen-pam.service"; DESKTOP_FILE="$TARGET_HOME/.local/share/applications/algen-pam.desktop"; SYSTEMD_USER=1
  fi
  [[ "$INSTALL_DIR" == /* ]] || die "Installation path must be absolute after expansion: $INSTALL_DIR"
  [[ "$INSTALL_DIR" != / && "$INSTALL_DIR" != /etc && "$INSTALL_DIR" != /usr && "$INSTALL_DIR" != /var && "$INSTALL_DIR" != "$TARGET_HOME" ]] || die "Unsafe installation path: $INSTALL_DIR"
  DATA_DIR="$INSTALL_DIR/data"; CONFIG_FILE="$CONFIG_DIR/.env"; LOG_FILE="$LOG_DIR/install.log"
}
marker_valid() {
  local marker="$INSTALL_DIR/.algen-pam-install"
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  grep -qx 'app=algen-pam' "$marker" && grep -Fqx "install_dir=$INSTALL_DIR" "$marker"
}
installation_present() { marker_valid && [[ -d "$INSTALL_DIR/backend" ]]; }
detect_existing_scope() {
  [[ -n "$SCOPE" ]] && return 0
  if [[ -f /opt/algen-pam/.algen-pam-install ]]; then SCOPE=system
  elif [[ -n "${HOME:-}" && -f "$HOME/.local/share/algen-pam/.algen-pam-install" ]]; then SCOPE=user
  else SCOPE=system
  fi
}
determine_mode() {
  if [[ -z "$MODE" ]]; then
    if installation_present; then MODE=update
    elif marker_valid; then MODE=reinstall
    else MODE=install; fi
  fi
  case "$MODE" in
    install) marker_valid && die "An installation marker already exists; use --update or --reinstall." ;;
    update|backup|remove-app|uninstall) installation_present || { [[ "$DRY_RUN" -eq 1 ]] || die "Mode '$MODE' requires a valid installation marker in $INSTALL_DIR."; } ;;
    reinstall) marker_valid || { [[ "$DRY_RUN" -eq 1 ]] || die "Mode 'reinstall' requires a valid installation marker in $INSTALL_DIR."; } ;;
  esac
}
require_privileges() {
  [[ "$SCOPE" == user || "$(id -u)" -eq 0 || -x "$(command -v sudo 2>/dev/null || true)" ]] || die "System mode requires root or sudo."
}
as_root() {
  if [[ "$DRY_RUN" -eq 1 ]]; then printf '[dry-run] root:'; printf ' %q' "$@"; printf '\n'; return 0; fi
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo -- "$@"; fi
}
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; return 0; fi
  debug "Executing: $(printf '%q ' "$@")"; "$@"
}
target_cmd() { if [[ "$SCOPE" == system ]]; then as_root "$@"; else run "$@"; fi; }

# ---- system detection and dependencies ------------------------------------
python_ok() { command -v python3 >/dev/null 2>&1 && python3 -c "import sys; raise SystemExit(sys.version_info < (3,$REQUIRED_PYTHON_MINOR))"; }
venv_ok() { python_ok && { local d; d="$(mktemp -d)"; python3 -m venv "$d/v" >/dev/null 2>&1; local s=$?; rm -rf "$d"; return $s; }; }
detect_pm() {
  if command -v apt-get >/dev/null; then printf apt
  elif command -v dnf >/dev/null; then printf dnf
  elif command -v pacman >/dev/null; then printf pacman
  elif command -v zypper >/dev/null; then printf zypper
  else printf none; fi
}
missing_dependencies() {
  local missing=() cmd
  python_ok || missing+=(python3.12)
  venv_ok || missing+=(venv)
  for cmd in tar openssl; do command -v "$cmd" >/dev/null || missing+=("$cmd"); done
  { command -v curl >/dev/null || command -v wget >/dev/null; } || missing+=(curl)
  if [[ "$REPO" =~ ^(ssh://|git@) ]]; then command -v git >/dev/null || missing+=(git); fi
  [[ "$SERVICE_CHOICE" != 1 ]] || command -v systemctl >/dev/null || missing+=(systemctl)
  printf '%s\n' "${missing[@]}"
}
install_dependencies() {
  local -a missing=(); mapfile -t missing < <(missing_dependencies)
  [[ ${#missing[@]} -gt 0 && -n "${missing[0]}" ]] || return 0
  local pm; pm="$(detect_pm)"; [[ "$pm" != none ]] || die "Missing dependencies: ${missing[*]}; unsupported package manager."
  info "Installing missing system dependencies: ${missing[*]}"
  local -a packages=()
  case "$pm" in
    apt) packages=(python3.12 python3.12-venv python3-pip curl ca-certificates tar git openssl libpam0g); as_root apt-get update; as_root apt-get install -y "${packages[@]}" ;;
    dnf) packages=(python3.12 python3-pip curl ca-certificates tar git openssl pam); as_root dnf install -y "${packages[@]}" ;;
    pacman) packages=(python python-pip curl ca-certificates tar git openssl pam); as_root pacman -Sy --needed --noconfirm "${packages[@]}" ;;
    zypper) packages=(python312 python312-pip curl ca-certificates tar git openssl pam); as_root zypper --non-interactive install "${packages[@]}" ;;
  esac
  python_ok && venv_ok || die "Python 3.12 with venv is required and could not be prepared."
}

# ---- UI -------------------------------------------------------------------
have_tty() { [[ -t 0 || -r /dev/tty ]]; }
ui_menu() {
  local result=""
  if command -v whiptail >/dev/null && have_tty; then
    result=$(whiptail --title "Algen PAM" --menu "Existing installation detected" 18 72 6 \
      1 "Update application" 2 "Reinstall application" 3 "Back up configuration" \
      4 "Remove application, preserve data" 5 "Remove everything" 6 "Cancel" 3>&1 1>&2 2>&3) || return 1
  elif command -v dialog >/dev/null && have_tty; then
    result=$(dialog --stdout --title "Algen PAM" --menu "Existing installation detected" 18 72 6 \
      1 "Update application" 2 "Reinstall application" 3 "Back up configuration" \
      4 "Remove application, preserve data" 5 "Remove everything" 6 "Cancel") || return 1
  else
    have_tty || die "No interactive terminal. Use --silent --yes and an explicit mode."
    printf '%s\n' '1) Update application' '2) Reinstall application' '3) Back up configuration' \
      '4) Remove application, preserve data' '5) Remove everything' '6) Cancel' >/dev/tty
    read -r -p 'Choice [1-6]: ' result </dev/tty || return 1
  fi
  case "$result" in 1) MODE=update;; 2) MODE=reinstall;; 3) MODE=backup;; 4) MODE=remove-app;; 5) MODE=uninstall;; 6) return 1;; *) return 1;; esac
}
interactive_mode_selection() {
  [[ "$SILENT" -eq 0 && "$DRY_RUN" -eq 0 && "$MODE_EXPLICIT" -eq 0 && $(marker_valid; echo $?) -eq 0 ]] || return 0
  ui_menu || die "Operation cancelled by user."
}
interactive_install_wizard() {
  [[ "$SILENT" -eq 0 && "$DRY_RUN" -eq 0 && "$MODE" != update && "$MODE" != reinstall && "$MODE" != backup && "$MODE" != remove-app && "$MODE" != uninstall ]] || return 0
  marker_valid && return 0
  have_tty || die "No interactive terminal. Use --silent --yes with explicit options."
  local choice=""
  if [[ "$SCOPE_EXPLICIT" -eq 0 ]]; then
    if command -v whiptail >/dev/null; then
      choice=$(whiptail --title "Algen PAM" --menu "Choose installation scope" 14 68 2 1 "System-wide (/opt/algen-pam)" 2 "Current user" 3>&1 1>&2 2>&3) || die "Operation cancelled."
    elif command -v dialog >/dev/null; then
      choice=$(dialog --stdout --title "Algen PAM" --menu "Choose installation scope" 14 68 2 1 "System-wide (/opt/algen-pam)" 2 "Current user") || die "Operation cancelled."
    else
      printf '%s\n' '1) System-wide (/opt/algen-pam)' '2) Current user' >/dev/tty
      read -r -p 'Scope [1-2]: ' choice </dev/tty || die "Operation cancelled."
    fi
    case "$choice" in 1) SCOPE=system;; 2) SCOPE=user;; *) die "Invalid scope selection.";; esac
    resolve_identity; resolve_paths
  fi
  if [[ -z "$SERVICE_CHOICE" ]]; then
    if command -v whiptail >/dev/null; then
      if whiptail --title "Algen PAM" --yesno "Create a systemd service?" 9 60; then SERVICE_CHOICE=1
      else choice=$?; [[ "$choice" -eq 1 ]] && SERVICE_CHOICE=0 || die "Operation cancelled."; fi
    elif command -v dialog >/dev/null; then
      if dialog --title "Algen PAM" --yesno "Create a systemd service?" 9 60; then SERVICE_CHOICE=1
      else choice=$?; [[ "$choice" -eq 1 ]] && SERVICE_CHOICE=0 || die "Operation cancelled."; fi
    else
      read -r -p 'Create a systemd service? [y/N]: ' choice </dev/tty || die "Operation cancelled."
      [[ "$choice" =~ ^([yY]|[yY][eE][sS])$ ]] && SERVICE_CHOICE=1 || SERVICE_CHOICE=0
    fi
  fi
}
confirm_summary() {
  local ref_description="branch $BRANCH"
  [[ -z "$TAG" ]] || ref_description="tag $TAG"
  cat >&2 <<EOF

Operation summary
  mode:          $MODE
  scope:         $SCOPE
  install dir:   $INSTALL_DIR
  config:        $CONFIG_FILE
  data:          $DATA_DIR
  source:        $REPO ($ref_description)
  HTTP/gateway:  $APP_PORT / $GATEWAY_PORT
  service:       $SERVICE_CHOICE
EOF
  [[ "$YES" -eq 1 || "$DRY_RUN" -eq 1 ]] && return 0
  [[ "$SILENT" -eq 0 ]] || die "Silent mode cannot ask for confirmation; use --yes."
  have_tty || die "No interactive terminal available for confirmation."
  local answer; read -r -p "Proceed? [y/N]: " answer </dev/tty || die "Operation cancelled."
  [[ "$answer" =~ ^([yY]|[yY][eE][sS])$ ]] || die "Operation cancelled."
}

# ---- configuration ---------------------------------------------------------
env_file_value() { [[ -f "$1" ]] && sed -n "s/^$2=//p" "$1" | tail -n1 | sed 's/^"//; s/"$//'; }
configured_value() {
  if [[ -r "$CONFIG_FILE" ]]; then env_file_value "$CONFIG_FILE" "$1"
  elif [[ "$SCOPE" == system && -f "$CONFIG_FILE" ]]; then
    sudo sed -n "s/^$1=//p" "$CONFIG_FILE" | tail -n1 | sed 's/^"//; s/"$//'
  else return 1
  fi
}
load_existing_configuration() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  local value
  if [[ "$APP_PORT_EXPLICIT" -eq 0 ]]; then value="$(configured_value ALGEN_PAM_PORT || true)"; [[ -z "$value" ]] || APP_PORT="$value"; fi
  if [[ "$GATEWAY_PORT_EXPLICIT" -eq 0 ]]; then value="$(configured_value PAM_GATEWAY_PORT || true)"; [[ -z "$value" ]] || GATEWAY_PORT="$value"; fi
  [[ -n "$ADMIN_USER" ]] || ADMIN_USER="$(configured_value PAM_DEFAULT_ADMIN_USER || true)"
  [[ -n "$ADMIN_EMAIL" ]] || ADMIN_EMAIL="$(configured_value PAM_DEFAULT_ADMIN_EMAIL || true)"
}
set_env_value() {
  local file="$1" key="$2" value="$3" tmp escaped
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "Unsafe environment key: $key"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "Environment value for $key contains a newline."
  escaped=${value//\\/\\\\}; escaped=${escaped//\"/\\\"}; escaped=${escaped//\$/\\$}; escaped=${escaped//\`/\\\`}
  tmp="$(mktemp "$(dirname "$file")/.env.tmp.XXXXXX")"
  awk -v key="$key" -v replacement="$key=\"$escaped\"" '
    BEGIN { done=0 } $0 ~ "^" key "=" { if (!done) print replacement; done=1; next } { print }
    END { if (!done) print replacement }
  ' "$file" >"$tmp"
  chmod 0600 "$tmp"; mv -f "$tmp" "$file"
}
remove_env_value() {
  local file="$1" key="$2" tmp; [[ -f "$file" ]] || return 0
  tmp="$(mktemp "$(dirname "$file")/.env.tmp.XXXXXX")"; awk -v key="$key" '$0 !~ "^" key "="' "$file" >"$tmp"
  chmod 0600 "$tmp"; mv -f "$tmp" "$file"
}
generate_secret() { openssl rand -hex "${1:-32}"; }
prepare_config() {
  target_cmd mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$(dirname "$BIN_PATH")"
  target_cmd chmod 0700 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    target_cmd install -m 0600 "$STAGED_APP/.env.example" "$CONFIG_FILE"
  fi
  # Atomic editor must run as the owner of a user install. System installs are
  # edited in place only after directories have been created by root.
  local editor="$CONFIG_FILE"
  if [[ "$SCOPE" == system && "$(id -u)" -ne 0 ]]; then
    local local_copy="$STAGE_ROOT/config.env"; as_root cp "$CONFIG_FILE" "$local_copy"; as_root chown "$(id -u):$(id -g)" "$local_copy"; editor="$local_copy"
  fi
  local secret vault_secret
  secret="$(env_file_value "$editor" SECRET_KEY 2>/dev/null || true)"
  vault_secret="$(env_file_value "$editor" PAM_VAULT_MASTER_KEY 2>/dev/null || true)"
  [[ -n "$secret" && "$secret" != change-me ]] || secret="$(generate_secret 32)"
  [[ -n "$vault_secret" && "$vault_secret" != change-this-32-byte-key ]] || vault_secret="$(generate_secret 32)"
  set_env_value "$editor" DATABASE_URL "sqlite:///$DATA_DIR/pam_lite.db"
  set_env_value "$editor" SECRET_KEY "$secret"
  set_env_value "$editor" PAM_VAULT_MASTER_KEY "$vault_secret"
  set_env_value "$editor" PAM_GATEWAY_HOST_KEY_PATH "$DATA_DIR/gateway_host_key"
  set_env_value "$editor" PAM_SESSION_LOG_DIR "$LOG_DIR/sessions"
  set_env_value "$editor" PAM_LOCAL_AUTH_MODE "$LOCAL_AUTH_MODE"
  set_env_value "$editor" PAM_DEFAULT_ADMIN_USER "$ADMIN_USER"
  set_env_value "$editor" PAM_DEFAULT_ADMIN_EMAIL "$ADMIN_EMAIL"
  set_env_value "$editor" PAM_OS_ADMIN_USERS "$ADMIN_USER"
  set_env_value "$editor" ALGEN_PAM_HOST "$APP_HOST"
  set_env_value "$editor" ALGEN_PAM_PORT "$APP_PORT"
  set_env_value "$editor" PAM_GATEWAY_PORT "$GATEWAY_PORT"
  remove_env_value "$editor" PAM_DEFAULT_ADMIN_PASSWORD
  if [[ "$editor" != "$CONFIG_FILE" ]]; then as_root install -m 0600 "$editor" "$CONFIG_FILE"; fi
  target_cmd chmod 0600 "$CONFIG_FILE"
  if [[ "$SCOPE" == system ]]; then as_root chown "$TARGET_USER:$TARGET_GROUP" "$CONFIG_DIR" "$CONFIG_FILE"; fi
  mkdir -p "$STAGED_APP"; ln -sfn "$CONFIG_FILE" "$STAGED_APP/.env"
}

# ---- source acquisition and staged build ----------------------------------
validate_source_tree() {
  local d="$1"
  [[ -f "$d/backend/requirements.txt" && -f "$d/backend/app/main.py" && -f "$d/backend/app/bootstrap_admin.py" && -f "$d/frontend/index.html" && -f "$d/.env.example" ]] \
    || die "Source does not contain the expected Algen PAM project structure."
}
acquire_source() {
  STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/algen-pam.XXXXXX")"; STAGED_APP="$STAGE_ROOT/release"
  local local_repo="${REPO#file://}"
  if [[ -d "$local_repo" ]]; then
    mkdir -p "$STAGED_APP"
    tar -C "$local_repo" --exclude=.git --exclude=.env --exclude=data --exclude=backend/.venv --exclude='*/__pycache__' -cf - . | tar -C "$STAGED_APP" -xf -
  elif [[ "$REPO" == https://* ]]; then
    local kind=heads ref="$BRANCH" archive="$STAGE_ROOT/source.tar.gz" unpack="$STAGE_ROOT/unpack" url
    if [[ -n "$TAG" ]]; then kind=tags; ref="$TAG"; fi
    url="${REPO%.git}/archive/refs/$kind/$ref.tar.gz"
    if command -v curl >/dev/null; then run curl -fsSL --retry 3 "$url" -o "$archive"
    else run wget -q "$url" -O "$archive"; fi
    tar -tzf "$archive" >/dev/null || die "Downloaded source is not a valid gzip tar archive."
    tar -tzf "$archive" | awk 'BEGIN { bad=0 } /(^\/|(^|\/)\.\.($|\/))/ { bad=1 } END { exit bad }' \
      || die "Downloaded archive contains an unsafe path."
    mkdir -p "$unpack"; tar -xzf "$archive" -C "$unpack"
    local extracted; extracted="$(find "$unpack" -mindepth 1 -maxdepth 1 -type d -print -quit)"
    [[ -n "$extracted" ]] || die "Downloaded archive has no project directory."
    mv "$extracted" "$STAGED_APP"
  else
    command -v git >/dev/null || die "Git is required for SSH repository URLs."
    run git clone --filter=blob:none --no-checkout "$REPO" "$STAGED_APP"
    if [[ -n "$TAG" ]]; then
      run git -C "$STAGED_APP" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
      run git -C "$STAGED_APP" checkout --detach "refs/tags/$TAG"
    else
      run git -C "$STAGED_APP" fetch --depth 1 origin "refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
      run git -C "$STAGED_APP" checkout --detach "refs/remotes/origin/$BRANCH"
    fi
    rm -rf "$STAGED_APP/.git"
  fi
  validate_source_tree "$STAGED_APP"
}
build_staged_release() {
  info "Building and validating the staged release."
  run python3 -m venv --copies "$STAGED_APP/backend/.venv"
  run "$STAGED_APP/backend/.venv/bin/python" -m pip install --disable-pip-version-check -r "$STAGED_APP/backend/requirements.txt"
  (cd "$STAGED_APP/backend" && DATABASE_URL=sqlite:///:memory: PAM_LOCAL_AUTH_MODE=database "$STAGED_APP/backend/.venv/bin/python" -c 'import app.main; import app.bootstrap_admin') \
    || die "Staged backend import validation failed."
}

# ---- systemd and service state --------------------------------------------
systemctl_do() { if [[ "$SYSTEMD_USER" -eq 1 ]]; then run systemctl --user "$@"; else as_root systemctl "$@"; fi; }
service_is_active() { if [[ "$SYSTEMD_USER" -eq 1 ]]; then systemctl --user is-active --quiet algen-pam.service 2>/dev/null; else systemctl is-active --quiet algen-pam.service 2>/dev/null; fi; }
service_is_enabled() { if [[ "$SYSTEMD_USER" -eq 1 ]]; then systemctl --user is-enabled --quiet algen-pam.service 2>/dev/null; else systemctl is-enabled --quiet algen-pam.service 2>/dev/null; fi; }
capture_service_state() { service_is_active && SERVICE_WAS_ACTIVE=1 || true; service_is_enabled && SERVICE_WAS_ENABLED=1 || true; }
write_launcher() {
  local tmp="$STAGE_ROOT/launcher"
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    "[[ \"\${1:-}\" != --version ]] || { echo \"$APP_ID $INSTALLER_VERSION\"; exit 0; }" \
    "cd \"$INSTALL_DIR/backend\"" \
    "exec \"$INSTALL_DIR/backend/.venv/bin/uvicorn\" app.main:app --host \"\${ALGEN_PAM_HOST:-$APP_HOST}\" --port \"\${ALGEN_PAM_PORT:-$APP_PORT}\" \"\$@\"" >"$tmp"
  target_cmd install -m 0755 "$tmp" "$BIN_PATH"
}
write_service() {
  [[ "$SERVICE_CHOICE" -eq 1 ]] || return 0
  command -v systemctl >/dev/null || die "systemctl is unavailable; use --no-service."
  local tmp="$STAGE_ROOT/algen-pam.service" user_line="" wanted=default.target protect_home=read-only
  if [[ "$SYSTEMD_USER" -eq 0 ]]; then user_line="User=$TARGET_USER"; wanted=multi-user.target; protect_home=true; fi
  cat >"$tmp" <<EOF
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
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=$protect_home
ReadWritePaths=$DATA_DIR $LOG_DIR
UMask=0077

[Install]
WantedBy=$wanted
EOF
  target_cmd mkdir -p "$(dirname "$SERVICE_FILE")"; target_cmd install -m 0644 "$tmp" "$SERVICE_FILE"; systemctl_do daemon-reload
}
write_desktop() {
  [[ "$DESKTOP_CHOICE" -eq 1 ]] || return 0
  local tmp="$STAGE_ROOT/algen-pam.desktop"
  cat >"$tmp" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_TITLE
Exec=xdg-open http://127.0.0.1:$APP_PORT/
Terminal=false
Categories=System;Security;
EOF
  target_cmd mkdir -p "$(dirname "$DESKTOP_FILE")"
  target_cmd install -m 0644 "$tmp" "$DESKTOP_FILE"
}

# ---- port and runtime validation ------------------------------------------
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null; then ss -H -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END {exit !found}'
  elif command -v lsof >/dev/null; then lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | grep -q .
  else python3 - "$port" <<'PY'
import socket, sys
s=socket.socket()
try: s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError: raise SystemExit(0)
finally: s.close()
raise SystemExit(1)
PY
  fi
}
find_port() { local p="$1"; while (( p <= 65535 )); do port_in_use "$p" || { printf '%s' "$p"; return; }; ((p++)); done; return 1; }
validate_ports() {
  [[ "$MODE" == install ]] || return 0
  local variable current replacement
  for variable in APP_PORT GATEWAY_PORT; do current="${!variable}"; if port_in_use "$current"; then
    if [[ "$AUTO_PORT" -eq 1 ]]; then replacement="$(find_port "$((current+1))")" || die "No free port available."; printf -v "$variable" %s "$replacement"
    elif [[ "$SILENT" -eq 1 || "$YES" -eq 1 ]]; then die "Port $current is occupied. Supply another port or --auto-port."
    else die "Port $current is occupied; rerun with an explicit free port."
    fi
  fi
  done
}
wait_health() { local _; for _ in {1..30}; do curl -fsS --max-time 2 "http://127.0.0.1:$APP_PORT/api/health" | grep -q '"message":"ok"' && return 0; sleep 1; done; return 1; }
validate_runtime() {
  [[ "$SERVICE_CHOICE" -eq 1 ]] && return 0
  local v_log="$LOG_DIR/validation.log"
  (cd "$INSTALL_DIR/backend" && "$INSTALL_DIR/backend/.venv/bin/uvicorn" app.main:app --host 127.0.0.1 --port "$APP_PORT") >"$v_log" 2>&1 & TEMP_SERVER_PID=$!
  if ! wait_health; then
    warn "Health check failed; inspect $v_log."
    kill "$TEMP_SERVER_PID" 2>/dev/null || true; wait "$TEMP_SERVER_PID" 2>/dev/null || true; TEMP_SERVER_PID=""
    return 1
  fi
  kill "$TEMP_SERVER_PID" 2>/dev/null || true; wait "$TEMP_SERVER_PID" 2>/dev/null || true; TEMP_SERVER_PID=""
}

# ---- backup, deployment, rollback, uninstall ------------------------------
write_marker() {
  local tmp="$STAGE_ROOT/marker"
  printf 'app=%s\ninstaller_version=%s\nscope=%s\ninstall_dir=%s\ninstalled_at=%s\n' "$APP_ID" "$INSTALLER_VERSION" "$SCOPE" "$INSTALL_DIR" "$(date -u +%FT%TZ)" >"$tmp"
  target_cmd install -m 0600 "$tmp" "$INSTALL_DIR/.algen-pam-install"
}
backup_state() {
  local root
  root="$CONFIG_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"; target_cmd mkdir -p "$root"
  [[ ! -f "$CONFIG_FILE" ]] || target_cmd cp -p "$CONFIG_FILE" "$root/env"
  [[ ! -d "$DATA_DIR" ]] || target_cmd tar -C "$DATA_DIR" -czf "$root/data.tar.gz" .
  target_cmd chmod -R go-rwx "$root"; info "Backup created: $root"
  STATE_BACKUP_DIR="$root"
}
safe_target() {
  [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != / && ! -L "$INSTALL_DIR" ]] || die "Unsafe or symbolic installation target: $INSTALL_DIR"
  marker_valid || die "Refusing deletion: installation marker is absent or inconsistent."
  local resolved; resolved="$(readlink -f "$INSTALL_DIR")"; [[ "$resolved" == "$INSTALL_DIR" ]] || die "Installation path resolves outside its declared location."
  if find "$INSTALL_DIR" -type l -print0 | while IFS= read -r -d '' link; do
    local destination; destination="$(readlink -f "$link")"
    [[ "$destination" == "$INSTALL_DIR"/* || ( "$link" == "$INSTALL_DIR/.env" && "$destination" == "$CONFIG_FILE" ) ]] || exit 1
  done; then :; else die "Installation contains a symlink escaping the installation directory."; fi
}
create_system_user_if_needed() {
  [[ "$SCOPE" == system && "$TARGET_USER" == algen-pam ]] || return 0
  id algen-pam >/dev/null 2>&1 || as_root useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin algen-pam
  TARGET_GROUP="$(id -gn algen-pam)"
}
deploy_release() {
  local parent; parent="$(dirname "$INSTALL_DIR")"; target_cmd mkdir -p "$parent"
  RELEASE_BACKUP="$parent/.algen-pam.previous.$(date +%s)"
  if marker_valid; then safe_target; target_cmd mv "$INSTALL_DIR" "$RELEASE_BACKUP"; fi
  if ! target_cmd mv "$STAGED_APP" "$INSTALL_DIR"; then
    [[ ! -d "$RELEASE_BACKUP" ]] || target_cmd mv "$RELEASE_BACKUP" "$INSTALL_DIR"
    die "Release switch failed and the previous release was restored."
  fi
  if [[ -d "$RELEASE_BACKUP/data" ]]; then target_cmd rm -rf "$INSTALL_DIR/data"; target_cmd mv "$RELEASE_BACKUP/data" "$INSTALL_DIR/data"; else target_cmd mkdir -p "$DATA_DIR"; fi
  target_cmd ln -sfn "$CONFIG_FILE" "$INSTALL_DIR/.env"
  write_marker; target_cmd chmod 0700 "$DATA_DIR"
  if [[ "$SCOPE" == system ]]; then
    as_root chown "$TARGET_USER:$TARGET_GROUP" "$DATA_DIR" "$LOG_DIR"
    as_root find "$DATA_DIR" "$LOG_DIR" -xdev -type f -exec chown "$TARGET_USER:$TARGET_GROUP" '{}' +
  fi
}
rollback_release() {
  warn "Validation failed; rolling back the application release."
  [[ "$SERVICE_CHOICE" -eq 0 ]] || systemctl_do stop algen-pam.service 2>/dev/null || true
  local failed
  failed="$INSTALL_DIR.failed.$(date +%s)"
  [[ ! -d "$INSTALL_DIR" ]] || target_cmd mv "$INSTALL_DIR" "$failed"
  if [[ ! -d "$RELEASE_BACKUP" ]]; then
    DIAGNOSTIC_PATH="$failed"
    warn "No previous release existed; the failed fresh release was retained for diagnostics."
    return 0
  fi
  target_cmd mv "$RELEASE_BACKUP" "$INSTALL_DIR"
  if [[ -d "$failed/data" ]]; then target_cmd rm -rf "$INSTALL_DIR/data"; target_cmd mv "$failed/data" "$INSTALL_DIR/data"; fi
  if [[ -f "$STATE_BACKUP_DIR/env" ]]; then target_cmd install -m 0600 "$STATE_BACKUP_DIR/env" "$CONFIG_FILE"; fi
  if [[ -f "$STATE_BACKUP_DIR/data.tar.gz" ]]; then
    target_cmd rm -rf "$INSTALL_DIR/data"; target_cmd mkdir -p "$INSTALL_DIR/data"
    target_cmd tar -C "$INSTALL_DIR/data" -xzf "$STATE_BACKUP_DIR/data.tar.gz"
  fi
  DIAGNOSTIC_PATH="$failed"
  [[ "$SERVICE_WAS_ACTIVE" -eq 0 ]] || systemctl_do start algen-pam.service
}
bootstrap_admin() {
  [[ "$MODE" == install || "$MODE" == reinstall || "$ADMIN_PASSWORD_SUPPLIED" -eq 1 || "$ADMIN_PASSWORD_GENERATED" -eq 1 ]] || return 0
  local -a update_arg=(); [[ "$ADMIN_PASSWORD_SUPPLIED" -eq 1 && "$MODE" != install ]] && update_arg=(--update-password)
  if [[ "$SCOPE" == system && "$(id -u)" -eq 0 && "$TARGET_USER" != root ]]; then
    (cd "$INSTALL_DIR/backend" && runuser -u "$TARGET_USER" -- "$INSTALL_DIR/backend/.venv/bin/python" -m app.bootstrap_admin --username "$ADMIN_USER" --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" "${update_arg[@]}")
  elif [[ "$SCOPE" == system && "$(id -u)" -ne 0 && "$TARGET_USER" != "$(id -un)" ]]; then
    (cd "$INSTALL_DIR/backend" && sudo -u "$TARGET_USER" -- "$INSTALL_DIR/backend/.venv/bin/python" -m app.bootstrap_admin --username "$ADMIN_USER" --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" "${update_arg[@]}")
  else
    (cd "$INSTALL_DIR/backend" && "$INSTALL_DIR/backend/.venv/bin/python" -m app.bootstrap_admin --username "$ADMIN_USER" --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" "${update_arg[@]}")
  fi
  remove_env_value "$CONFIG_FILE" PAM_DEFAULT_ADMIN_PASSWORD
}
remove_integrations() {
  service_is_active && systemctl_do stop algen-pam.service || true
  if [[ -f "$SERVICE_FILE" ]]; then systemctl_do disable algen-pam.service 2>/dev/null || true; target_cmd rm -f "$SERVICE_FILE"; systemctl_do daemon-reload || true; fi
  target_cmd rm -f "$BIN_PATH" "$DESKTOP_FILE"
}
remove_app_only() { safe_target; remove_integrations; target_cmd find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name data ! -name .algen-pam-install -exec rm -rf -- '{}' +; info "Application removed; data, configuration, and logs preserved."; }
full_uninstall() {
  safe_target; remove_integrations
  # Keep the final log writable until the final message has been emitted.
  if [[ "$KEEP_DATA" -eq 1 ]]; then target_cmd mkdir -p "$CONFIG_DIR"; target_cmd mv "$DATA_DIR" "$CONFIG_DIR/data-preserved-$(date +%s)"; KEEP_CONFIG=1; fi
  target_cmd rm -rf -- "$INSTALL_DIR"
  [[ "$KEEP_CONFIG" -eq 1 ]] || target_cmd rm -rf -- "$CONFIG_DIR"
  [[ "$KEEP_LOGS" -eq 1 ]] || target_cmd rm -rf -- "$LOG_DIR"
  LOG_FILE=""; info "Uninstall completed."
}

# ---- main operation flow ---------------------------------------------------
prepare_admin_defaults() {
  [[ -n "$ADMIN_USER" ]] || ADMIN_USER="$TARGET_USER"
  [[ -n "$ADMIN_EMAIL" ]] || ADMIN_EMAIL="$ADMIN_USER@localhost.localdomain"
  [[ "$LOCAL_AUTH_MODE" != os || "$DRY_RUN" -eq 1 || ( "$SCOPE" == system && "$ADMIN_USER" == algen-pam ) ]] \
    || id "$ADMIN_USER" >/dev/null 2>&1 || die "OS administrator account '$ADMIN_USER' does not exist."
}
prepare_admin_password() {
  [[ "$MODE" == install || "$MODE" == reinstall || "$ADMIN_PASSWORD_SUPPLIED" -eq 1 || "$ADMIN_PASSWORD_GENERATED" -eq 1 ]] || return 0
  if [[ -z "$ADMIN_PASSWORD" && "$DRY_RUN" -eq 1 ]]; then ADMIN_PASSWORD=dry-run-placeholder
  elif [[ -z "$ADMIN_PASSWORD" ]]; then ADMIN_PASSWORD="$(generate_secret 18)"; ADMIN_PASSWORD_GENERATED=1; fi
  [[ ${#ADMIN_PASSWORD} -ge 12 ]] || die "Administrator password must contain at least 12 characters."
}
prepare_logging() { target_cmd mkdir -p "$LOG_DIR"; target_cmd touch "$LOG_FILE"; target_cmd chmod 0600 "$LOG_FILE"; }
execute_install_or_update() {
  install_dependencies
  acquire_source
  build_staged_release
  create_system_user_if_needed
  capture_service_state
  if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then systemctl_do stop algen-pam.service; fi
  [[ "$MODE" == update || "$MODE" == reinstall ]] && backup_state
  if ! prepare_config; then
    [[ "$SERVICE_WAS_ACTIVE" -eq 0 ]] || systemctl_do start algen-pam.service || true
    die "Configuration preparation failed before release switch."
  fi
  deploy_release
  if ! write_launcher || ! write_service || ! write_desktop || ! bootstrap_admin; then
    rollback_release
    die "Release integration or administrator bootstrap failed; rollback completed."
  fi
  if [[ "$SERVICE_CHOICE" -eq 1 ]]; then
    if [[ "$MODE" == install ]]; then systemctl_do enable --now algen-pam.service || { rollback_release; die "Service start failed; rollback completed."; }
    elif [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then systemctl_do start algen-pam.service || { rollback_release; die "Service restart failed; rollback completed."; }
    fi
  fi
  debug "Previous service state: active=$SERVICE_WAS_ACTIVE enabled=$SERVICE_WAS_ENABLED"
  local valid=0
  if [[ "$SERVICE_CHOICE" -eq 1 && ( "$SERVICE_WAS_ACTIVE" -eq 1 || "$MODE" == install ) ]]; then
    service_is_active && wait_health && valid=1
  else
    if port_in_use "$APP_PORT"; then warn "Cannot run validation: port $APP_PORT is occupied by another process."
    elif validate_runtime; then valid=1
    fi
  fi
  if [[ "$valid" -ne 1 ]]; then rollback_release; die "New release failed validation; rollback completed."; fi
  [[ -z "$RELEASE_BACKUP" || ! -d "$RELEASE_BACKUP" ]] || target_cmd rm -rf -- "$RELEASE_BACKUP"
}
main() {
  parse_args "$@"                         # 1
  validate_arguments                       # 2
  detect_existing_scope                    # 3
  resolve_identity
  resolve_paths
  interactive_mode_selection
  interactive_install_wizard
  interactive_mode_selection
  determine_mode                           # 4
  [[ -n "$SERVICE_CHOICE" ]] || { if [[ -f "$SERVICE_FILE" ]]; then SERVICE_CHOICE=1; else SERVICE_CHOICE=0; fi; }
  load_existing_configuration              # 5/6
  validate_arguments
  require_privileges                       # 7
  prepare_admin_defaults                    # 8
  prepare_admin_password
  validate_ports
  confirm_summary                          # 9
  [[ "$DRY_RUN" -eq 0 ]] || { info "Dry run complete; no changes were made."; return 0; }
  MUTATIONS_STARTED=1
  prepare_logging
  case "$MODE" in                          # 10
    install|update|reinstall) execute_install_or_update ;;
    backup) backup_state ;;
    remove-app) remove_app_only ;;
    uninstall) full_uninstall ;;
  esac
                                           # 11: operation-specific validation completed
  info "Operation '$MODE' completed successfully."
  if [[ "$ADMIN_PASSWORD_GENERATED" -eq 1 && "$MODE" != uninstall ]]; then
    printf '\nGenerated administrator password (shown once):\n  %s\n' "$ADMIN_PASSWORD"
  fi
  unset ADMIN_PASSWORD
  [[ "$MODE" == install || "$MODE" == update || "$MODE" == reinstall ]] && printf '\nOpen: http://127.0.0.1:%s/\nConfig: %s\n' "$APP_PORT" "$CONFIG_FILE"
}

main "$@"

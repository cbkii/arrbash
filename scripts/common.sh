# shellcheck shell=bash

: "${STACK:=arr}"
: "${STACK_UPPER:=${STACK^^}}"
: "${BLUE:=}"
: "${CYAN:=}"
: "${YELLOW:=}"
: "${RESET:=}"
: "${BOLD:=}"
: "${ARR_COLOR_OUTPUT:=1}"
: "${ARR_COMPOSE_VERSION:=}"
: "${SECRET_FILE_MODE:=600}"
: "${NONSECRET_FILE_MODE:=600}"
: "${DATA_DIR_MODE:=700}"
: "${LOCK_FILE_MODE:=640}"

declare -a ARR_TEMP_PATHS=()

arr_cleanup_temp_assets() {
  local path=""

  if [[ -z "${ARR_TEMP_PATHS[*]:-}" ]]; then
    return 0
  fi

  for path in "${ARR_TEMP_PATHS[@]}"; do
    [[ -n "$path" ]] || continue
    rm -rf -- "$path" 2>/dev/null || true
  done

  ARR_TEMP_PATHS=()
}

arr_global_cleanup() {
  arr_cleanup_temp_assets

  if [[ -n "${ARR_LOCKFILE:-}" ]]; then
    rm -f -- "$ARR_LOCKFILE" 2>/dev/null || true
  fi
}

arr_register_cleanup() {
  if [[ -n "${ARR_CLEANUP_TRAP_SET:-}" ]]; then
    return 0
  fi

  if [[ "${ARR_MAIN_TRAP_INSTALLED:-0}" == "1" ]]; then
    ARR_CLEANUP_TRAP_SET=1
    return 0
  fi

  trap 'arr_global_cleanup' EXIT INT TERM HUP QUIT
  ARR_CLEANUP_TRAP_SET=1
}

arr_register_temp_path() {
  local path="$1"

  if [[ -z "$path" ]]; then
    return 0
  fi

  arr_register_cleanup
  ARR_TEMP_PATHS+=("$path")
}

arr_unregister_temp_path() {
  local target="$1"

  if [[ -z "$target" || -z "${ARR_TEMP_PATHS[*]:-}" ]]; then
    return 0
  fi

  local -a remaining=()
  local path=""
  local removed=0

  for path in "${ARR_TEMP_PATHS[@]}"; do
    if ((removed == 0)) && [[ "$path" == "$target" ]]; then
      removed=1
      continue
    fi
    remaining+=("$path")
  done

  if ((removed == 1)); then
    ARR_TEMP_PATHS=("${remaining[@]}")
  fi
}

arr_cleanup_temp_path() {
  local path="$1"

  if [[ -z "$path" ]]; then
    return 0
  fi

  arr_unregister_temp_path "$path"
  rm -rf -- "$path" 2>/dev/null || true
}

if [[ -z "${ARR_YAML_EMIT_LIB_SOURCED:-}" ]]; then
  _arr_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  YAML_EMIT_LIB="${YAML_EMIT_LIB:-${_arr_common_dir}/yaml-emit.sh}"
  if [[ -f "${YAML_EMIT_LIB}" ]]; then
    # shellcheck source=scripts/yaml-emit.sh
    . "${YAML_EMIT_LIB}"
  else
    printf '[arr] missing emission helper library: %s\n' "${YAML_EMIT_LIB}" >&2
    exit 1
  fi
  unset _arr_common_dir
fi

if [[ -z "${ARR_DATA_ROOT:-}" ]]; then
  if [[ -n "${HOME:-}" ]]; then
    ARR_DATA_ROOT="${HOME%/}/srv"
  else
    ARR_DATA_ROOT="/srv/${STACK}"
  fi
fi

ARR_DATA_ROOT="${ARR_DATA_ROOT%/}"

# shellcheck disable=SC2034  # exported for other modules
STACK_LABEL="[${STACK}]"

# Derives runtime color output preference respecting NO_COLOR/force overrides
arr_resolve_color_output() {
  if [[ -n "${NO_COLOR:-}" ]]; then
    ARR_COLOR_OUTPUT=0
    return
  fi

  case "${FORCE_COLOR:-}" in
    '' | 0 | false | FALSE | no | NO) ;;
    *)
      ARR_COLOR_OUTPUT=1
      return
      ;;
  esac

  case "${ARR_COLOR_OUTPUT:-1}" in
    0 | false | FALSE | no | NO | off | OFF)
      ARR_COLOR_OUTPUT=0
      ;;
    *)
      ARR_COLOR_OUTPUT=1
      ;;
  esac
}

arr_resolve_color_output

# Determines if a shell variable is readonly to avoid clobbering host overrides
arr_var_is_readonly() {
  local varname="$1"
  local declaration=""

  if ! declaration=$(declare -p -- "$varname" 2>/dev/null); then
    return 1
  fi

  [[ ${declaration} == declare\ -*r* ]]
}

# Checks command availability without emitting output (used for optional deps)
have_command() {
  command -v "$1" >/dev/null 2>&1
}

# Read space-separated fields safely regardless of caller IFS.
# Usage: arr_read_fields "a b c" var1 var2 var3
arr_read_fields() {
  local __src="$1"
  shift
  local __oldifs="$IFS"
  local __status
  IFS=' '
  if read -r "$@" <<<"$__src"; then
    __status=0
  else
    __status=$?
  fi
  IFS="$__oldifs"
  # shellcheck disable=SC2248  # __status is a numeric return code
  return $__status
}

# Ensures port is numeric and within 1-65535
validate_port() {
  local port="$1"
  local display="${port:-<empty>}"

  if [[ -z "$port" ]]; then
    warn "Invalid port: ${display} (expected integer between 1 and 65535)"
    return 1
  fi

  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    warn "Invalid port: ${display} (expected integer between 1 and 65535)"
    return 1
  fi

  if ((port < 1 || port > 65535)); then
    warn "Invalid port: ${display} (expected integer between 1 and 65535)"
    return 1
  fi

  return 0
}

# Normalises a port value, falling back to a default and warning when invalid
arr_resolve_port() {
  local __resultvar="$1"
  local raw="${2-}"
  local default="${3-}"
  local warn_message="${4-}"
  local log_handler="${5-}"
  local value="$raw"

  if [[ -z "$value" ]]; then
    value="$default"
  fi

  if ! validate_port "$value"; then
    value="$default"
    if [[ -n "$warn_message" ]]; then
      if [[ -n "$log_handler" ]] && declare -F "$log_handler" >/dev/null 2>&1; then
        "$log_handler" "$warn_message"
      else
        warn "$warn_message"
      fi
    fi
  fi

  printf -v "$__resultvar" '%s' "$value"
}

# Coerces a positive integer, defaulting and warning when invalid or <= 0
arr_resolve_positive_int() {
  local __resultvar="$1"
  local raw="${2-}"
  local default="${3-}"
  local warn_message="${4-}"
  local log_handler="${5-}"
  local value="$raw"

  if [[ -z "$value" ]]; then
    value="$default"
  fi

  local invalid=0
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    invalid=1
  elif ((value <= 0)); then
    invalid=1
  fi

  if ((invalid)); then
    value="$default"
    if [[ -n "$warn_message" ]]; then
      if [[ -n "$log_handler" ]] && declare -F "$log_handler" >/dev/null 2>&1; then
        "$log_handler" "$warn_message"
      else
        warn "$warn_message"
      fi
    fi
  fi

  printf -v "$__resultvar" '%s' "$value"
}

# Detects docker compose command once per shell and memoizes result for callers
# shellcheck disable=SC2120  # Verbosity flag is intentionally optional for callers
arr_resolve_compose_cmd() {
  local verbose="${1:-0}"

  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    if [[ "$verbose" == "1" ]]; then
      local version_display="${ARR_COMPOSE_VERSION:-}"
      msg "Using cached Docker Compose command: ${DOCKER_COMPOSE_CMD[*]}${version_display:+ (version ${version_display})}"
    fi
    return 0
  fi

  local -a candidate=()
  local version=""
  local major=""
  local version_output=""

  if docker compose version >/dev/null 2>&1; then
    candidate=(docker compose)
    if version_output="$(docker compose version --short 2>/dev/null)"; then
      version="${version_output#v}"
      major="${version%%.*}"
      if [[ -n "$major" && "$major" =~ ^[0-9]+$ ]]; then
        : # major version is valid, do nothing
      else
        version=""
      fi
    else
      version=""
    fi
  fi

  if ((${#candidate[@]} == 0)) && have_command docker-compose; then
    if version_output="$(docker-compose version --short 2>/dev/null)"; then
      version="${version_output#v}"
      major="${version%%.*}"
      if [[ "$major" =~ ^[0-9]+$ ]] && ((major >= 2)); then
        candidate=(docker-compose)
      else
        version=""
      fi
    else
      version=""
    fi
  fi

  if ((${#candidate[@]} == 0)); then
    die "Docker Compose v2+ is required but not found"
  fi

  DOCKER_COMPOSE_CMD=("${candidate[@]}")
  ARR_COMPOSE_VERSION="$version"

  if [[ "$verbose" == "1" ]]; then
    msg "Resolved Docker Compose command: ${DOCKER_COMPOSE_CMD[*]}${version:+ (version ${version})}"
  fi
}

# Resolves the canonical ARR_DATA_ROOT, defaulting to ~/srv when unset
arr_data_root() {
  local resolved="${ARR_DATA_ROOT:-}"

  if [[ -z "$resolved" ]]; then
    if [[ -n "${HOME:-}" ]]; then
      resolved="${HOME%/}/srv"
    else
      resolved="/srv/${STACK:-arr}"
    fi
  fi

  printf '%s' "${resolved%/}"
}

# Resolves the stack working directory under ARR_DATA_ROOT
arr_stack_dir() {
  local resolved="${ARR_STACK_DIR:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_data_root)/${STACK:-arr}"
  fi

  printf '%s' "${resolved%/}"
}

# Resolves the configuration/secrets directory
arr_conf_dir() {
  local resolved="${ARRCONF_DIR:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_stack_dir)configs"
  fi

  printf '%s' "${resolved%/}"
}

# Resolves the generated .env file path
arr_env_file() {
  local resolved="${ARR_ENV_FILE:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_stack_dir)/.env"
  fi

  printf '%s' "$resolved"
}

# Resolves the canonical location of userr.conf
arr_userconf_path() {
  local resolved="${ARR_USERCONF_PATH:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_conf_dir)/userr.conf"
  fi

  printf '%s' "$resolved"
}

# Provides canonical dockarr root resolution with consistent fallbacks
arr_docker_data_root() {
  local resolved="${ARR_DOCKER_DIR:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_stack_dir)/dockarr"
  fi

  printf '%s' "${resolved%/}"
}

# Resolves the Gluetun data directory under the dockarr root
arr_gluetun_dir() {
  printf '%s/gluetun' "$(arr_docker_data_root)"
}

# Resolves the VPN auto-reconnect working directory under Gluetun assets
arr_gluetun_auto_reconnect_dir() {
  printf '%s/auto-reconnect' "$(arr_gluetun_dir)"
}

# Resolves the stack log directory, defaulting under ARR_STACK_DIR when unset
arr_log_dir() {
  local resolved="${ARR_LOG_DIR:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_stack_dir)/logs"
  fi

  printf '%s' "${resolved%/}"
}

# Resolves the installer log location
arr_install_log_path() {
  local resolved="${ARR_INSTALL_LOG:-}"

  if [[ -z "$resolved" ]]; then
    resolved="$(arr_log_dir)/${STACK:-arr}-install.log"
  fi

  printf '%s' "$resolved"
}

# Escapes text for single-quoted shells; optional flatten mode serializes newlines
arr_shell_escape_single_quotes() {
  local input="${1-}"
  local mode="${2-}"
  local escaped
  escaped="$(printf '%s' "$input" | sed "s/'/'\\\\''/g")"

  if [ "$mode" = "flat" ] || [ "${ARR_ESCAPE_FLATTEN:-0}" = "1" ]; then
    # Flatten: real newline -> literal \n (two characters). Only opt-in.
    printf '%s' "$escaped" | tr '\n' '\\n'
  else
    printf '%s' "$escaped"
  fi
}

# Escapes text for double-quoted shells; optional flatten mode serializes newlines
arr_shell_escape_double_quotes() {
  local input="${1-}"
  local mode="${2-}"
  local escaped
  escaped="$(printf '%s' "$input" | sed -e 's/[\\$`\"]/\\&/g')"

  if [ "$mode" = "flat" ] || [ "${ARR_ESCAPE_FLATTEN:-0}" = "1" ]; then
    printf '%s' "$escaped" | tr '\n' '\\n'
  else
    printf '%s' "$escaped"
  fi
}

# Returns a process command line (space delimited) for diagnostics; best-effort only
read_proc_cmdline() {
  local pid="$1"

  if [[ -z "$pid" || ! -r "/proc/${pid}/cmdline" ]]; then
    return 1
  fi

  tr '\0' ' ' <"/proc/${pid}/cmdline" | sed 's/[[:space:]]\+$//'
}

# Returns a process comm name for telemetry helpers; fails silently if unreadable
read_proc_comm() {
  local pid="$1"

  if [[ -z "$pid" || ! -r "/proc/${pid}/comm" ]]; then
    return 1
  fi

  tr -d '\n' <"/proc/${pid}/comm"
}

# Attempts graceful termination before SIGKILL while guarding against PID 1 accidents
safe_kill() {
  local pid="$1"
  local label="${2:-process}"
  local timeout="${3:-10}"

  if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
    warn "safe_kill called with invalid pid '${pid}' for ${label}"
    return 1
  fi

  if ((pid == 1)); then
    warn "Refusing to kill PID 1 (${label})"
    return 1
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  if kill -TERM "$pid" 2>/dev/null; then
    local deadline=$((SECONDS + timeout))
    while kill -0 "$pid" 2>/dev/null; do
      if ((SECONDS >= deadline)); then
        break
      fi
      sleep 0.2
    done
  fi

  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi

  if kill -0 "$pid" 2>/dev/null; then
    warn "Failed to terminate ${label} (pid ${pid})"
    return 1
  fi

  return 0
}

# Appends structured log lines to current install log sinks without failing the caller
arr_json_log() {
  local json_line="$1"

  if [[ -z "$json_line" ]]; then
    return 0
  fi

  local target="${LOG_FILE:-}"
  if [[ -n "$target" ]]; then
    printf '%s\n' "$json_line" >>"$target" 2>/dev/null || true
    return 0
  fi

  local log_dir
  log_dir="$(arr_log_dir)"
  if [[ -n "$log_dir" ]]; then
    ensure_dir "$log_dir"
    printf '%s\n' "$json_line" >>"${log_dir}/latest.log" 2>/dev/null || true
  fi
}

# Lists any commands absent from PATH, preserving order for user-facing prompts
missing_commands() {
  local -a missing=()
  local cmd

  for cmd in "$@"; do
    if ! have_command "$cmd"; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} == 0)); then
    return 0
  fi

  printf '%s\n' "${missing[@]}"
}

# Warns when optional commands are missing so installers can proceed with awareness
check_dependencies() {
  local missing
  local rc=0

  if ! missing="$(missing_commands "$@")"; then
    rc=$?
    warn "Unable to evaluate optional dependencies (missing_commands exited with ${rc})"
    return "$rc"
  fi

  if [[ -z "$missing" ]]; then
    return 0
  fi

  local display
  display="${missing//$'\n'/, }"
  warn "Missing recommended command(s): ${display}"
  return 1
}

# Aborts immediately if required commands are unavailable
require_dependencies() {
  local missing
  if ! missing="$(missing_commands "$@")"; then
    local rc=$?
    die "Failed to evaluate required dependencies (missing_commands exited with ${rc})"
  fi

  if [[ -z "$missing" ]]; then
    return 0
  fi

  local display
  display="${missing//$'\n'/, }"
  die "Missing required command(s): ${display}"
}

# Ensures a directory exists, optionally sudo-ing and fixing ownership for PUID/PGID
ensure_dir() {
  local dir="$1"
  if mkdir -p "$dir" 2>/dev/null; then
    return 0
  fi

  local rc=$?
  if [[ "${ARR_ALLOW_SUDO_DIRS:-0}" == "1" ]]; then
    if [[ $EUID -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        if sudo mkdir -p "$dir" 2>/dev/null || sudo mkdir -p "$dir"; then
          if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
            sudo chown -R "${PUID}:${PGID}" "$dir" 2>/dev/null || true
          fi
          return 0
        fi
      fi
    elif [[ $EUID -eq 0 ]]; then
      # shellcheck disable=SC2248  # rc is an integer exit code from mkdir
      return $rc
    fi
  fi
  # shellcheck disable=SC2248  # rc is an integer exit code from mkdir
  return $rc
}

# Applies mode to directory with sudo fallback, warning when permissions drift
ensure_dir_mode() {
  local dir="$1"
  local mode="$2"

  ensure_dir "$dir"

  if [[ -z "$mode" ]]; then
    return 0
  fi

  if chmod "$mode" "$dir" 2>/dev/null; then
    return 0
  fi

  if [[ "${ARR_ALLOW_SUDO_DIRS:-0}" == "1" ]]; then
    if [[ $EUID -ne 0 ]]; then
      if command -v sudo >/dev/null 2>&1; then
        if sudo chmod "$mode" "$dir" 2>/dev/null; then
          if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
            sudo chown "${PUID}:${PGID}" "$dir" 2>/dev/null || true
          fi
          return 0
        fi
      fi
    fi
  fi
  warn "Could not apply mode ${mode} to ${dir}"
}

# Fetches numeric permission mode; returns non-zero if target missing
arr_stat_mode() {
  local target="$1"

  if [[ ! -e "$target" ]]; then
    return 1
  fi

  stat -c '%a' "$target" 2>/dev/null || return 1
}

# Detects unsafe group-write permissions so installer can warn collaborators
arr_is_group_writable() {
  local target="$1"

  local mode
  if ! mode="$(arr_stat_mode "$target")"; then
    return 1
  fi

  if [[ -z "$mode" ]]; then
    return 1
  fi

  if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
    return 1
  fi

  local numeric=$((8#$mode))

  # 020 = group write bit
  if (((numeric & 020) != 0)); then
    return 0
  fi

  return 1
}

# De-duplicates collaboration warnings before appending to summary buffer
arr_append_collab_warning() {
  local entry="$1"

  if [[ -z "$entry" ]]; then
    return 0
  fi

  local current="${COLLAB_PERMISSION_WARNINGS:-}"

  if [[ -n "$current" ]]; then
    local padded=$'\n'"${current}"$'\n'
    local needle=$'\n'"${entry}"$'\n'
    if [[ "$padded" == *"${needle}"* ]]; then
      return 0
    fi
    COLLAB_PERMISSION_WARNINGS+=$'\n'"${entry}"
  else
    COLLAB_PERMISSION_WARNINGS="${entry}"
  fi
}

# Emits a collaboration warning only once even if triggered repeatedly
arr_warn_collab_once() {
  local message="$1"

  if [[ -z "$message" ]]; then
    return 0
  fi

  local previous="${COLLAB_PERMISSION_WARNINGS:-}"

  arr_append_collab_warning "$message"

  if [[ "${COLLAB_PERMISSION_WARNINGS:-}" != "$previous" ]]; then
    warn "$message"
  fi
}

# Detects whether any argument targets a path requiring forced sudo handling
arr_command_has_sensitive_arg() {
  local arg=""

  for arg in "$@"; do
    if arr_should_force_permission_sudo "$arg"; then
      return 0
    fi
  done

  return 1
}

# Returns the first sensitive argument from a command invocation, if any
arr_first_sensitive_arg() {
  local arg=""

  for arg in "$@"; do
    if arr_should_force_permission_sudo "$arg"; then
      printf '%s' "$arg"
      return 0
    fi
  done

  return 1
}

# Identifies permission-denied style failures from stderr payloads
arr_sensitive_error_is_permission() {
  local stderr_payload="${1:-}"

  if [[ -z "$stderr_payload" ]]; then
    return 1
  fi

  if printf '%s' "$stderr_payload" | LC_ALL=C grep -qi 'permission denied'; then
    return 0
  fi

  return 1
}

# Runs commands touching sensitive paths with sudo fallback on permission errors
arr_run_sensitive_command() {
  if [[ $# -eq 0 ]]; then
    return 0
  fi

  if ! arr_command_has_sensitive_arg "$@"; then
    "$@"
    return $?
  fi

  local need_sudo=0
  if [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    need_sudo=1
  fi

  local tmp_out tmp_err status stderr_payload sensitive_arg

  tmp_out="$(mktemp 2>/dev/null)" || die "Failed to allocate stdout capture for sensitive command"
  arr_register_temp_path "$tmp_out"
  tmp_err="$(mktemp 2>/dev/null)" || {
    arr_cleanup_temp_path "$tmp_out"
    die "Failed to allocate stderr capture for sensitive command"
  }
  arr_register_temp_path "$tmp_err"

  if "$@" >"$tmp_out" 2>"$tmp_err"; then
    cat "$tmp_out"
    cat "$tmp_err" >&2
    arr_cleanup_temp_path "$tmp_out"
    arr_cleanup_temp_path "$tmp_err"
    return 0
  fi

  status=$?
  stderr_payload="$(cat "$tmp_err" 2>/dev/null)"

  if ((need_sudo == 1)) && arr_sensitive_error_is_permission "$stderr_payload"; then
    # shellcheck disable=SC2024  # Redirecting to agent-owned temp files is safe with sudo
    if sudo "$@" >"$tmp_out" 2>"$tmp_err"; then
      cat "$tmp_out"
      cat "$tmp_err" >&2
      arr_cleanup_temp_path "$tmp_out"
      arr_cleanup_temp_path "$tmp_err"
      return 0
    fi
    status=$?
    stderr_payload="$(cat "$tmp_err" 2>/dev/null)"
  fi

  cat "$tmp_out"
  cat "$tmp_err" >&2
  arr_cleanup_temp_path "$tmp_out"
  arr_cleanup_temp_path "$tmp_err"

  if arr_sensitive_error_is_permission "$stderr_payload"; then
    sensitive_arg="$(arr_first_sensitive_arg "$@" || true)"
    if [[ -n "$sensitive_arg" ]]; then
      die "Permission denied while running $1 on ${sensitive_arg}"
    fi
    die "Permission denied while running $1"
  fi

  return "$status"
}

# Appends a line to files requiring sudo escalation when necessary
arr_sensitive_append_line() {
  local file="$1"
  local line="$2"

  if [[ -z "$file" ]]; then
    return 1
  fi

  if arr_should_force_permission_sudo "$file" && [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    if ! printf '%s\n' "$line" | sudo tee -a "$file" >/dev/null; then
      die "Failed to append to ${file}"
    fi
  else
    if ! printf '%s\n' "$line" >>"$file"; then
      if arr_should_force_permission_sudo "$file"; then
        die "Failed to append to ${file}"
      fi
      return 1
    fi
  fi

  return 0
}

# Reads sensitive files with sudo fallback when direct access is denied
arr_read_sensitive_file() {
  local file="$1"

  if [[ -z "$file" || ! -e "$file" ]]; then
    return 1
  fi

  if ! arr_should_force_permission_sudo "$file"; then
    cat "$file"
    return $?
  fi

  if cat "$file" 2>/dev/null; then
    return 0
  fi

  if [[ -e "$file" && ! -r "$file" ]] && [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    if sudo cat "$file"; then
      return 0
    fi
  fi

  if [[ -e "$file" && ! -r "$file" ]]; then
    die "Permission denied while reading ${file}"
  fi

  return 1
}

# Detects permission-sensitive targets that must succeed even when sudo is required
arr_should_force_permission_sudo() {
  local target="${1-}"
  if [[ -z "$target" ]]; then
    return 1
  fi

  local lowered="${target,,}"

  if [[ "$lowered" == *"qbittorrent.conf" ]]; then
    return 0
  fi

  if [[ "$lowered" == *.env || "$lowered" == *".env."* ]]; then
    return 0
  fi

  if [[ "$lowered" == *.yml || "$lowered" == *".yml."* ]]; then
    return 0
  fi

  if [[ "$lowered" == *.yaml || "$lowered" == *".yaml."* ]]; then
    return 0
  fi

  return 1
}

# Applies file mode if target exists, tolerating chmod failures
ensure_file_mode() {
  local file="$1"
  local mode="$2"

  if [[ ! -e "$file" || -z "$mode" ]]; then
    return 0
  fi

  if chmod "$mode" "$file" 2>/dev/null; then
    return 0
  fi

  local allow_sudo=0
  if arr_should_force_permission_sudo "$file"; then
    allow_sudo=1
  fi
  if [[ "${ARR_ALLOW_SUDO_DIRS:-0}" == "1" ]]; then
    allow_sudo=1
  fi

  if ((allow_sudo == 1)) && [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    if sudo chmod "$mode" "$file" 2>/dev/null; then
      if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
        sudo chown "${PUID}:${PGID}" "$file" 2>/dev/null || true
      fi
      return 0
    fi
  fi

  if arr_should_force_permission_sudo "$file"; then
    die "Failed to apply mode ${mode} to ${file}"
  fi

  warn "Could not apply mode ${mode} to ${file}"
}

# Convenience wrapper enforcing secret file permissions consistently
ensure_secret_file_mode() {
  ensure_file_mode "$1" "$SECRET_FILE_MODE"
}

# Applies standard non-secret permissions via ensure_file_mode
ensure_nonsecret_file_mode() {
  ensure_file_mode "$1" "$NONSECRET_FILE_MODE"
}

# Ensures data directories inherit hardened default mode
ensure_data_dir_mode() {
  ensure_dir_mode "$1" "$DATA_DIR_MODE"
}

# Creates a temp file with optional template/mode, returning its path for atomic writes
arr_mktemp_file() {
  local template="${1-}"
  local mode="${2:-600}"
  local tmp=""

  if [[ -n "$template" ]]; then
    tmp="$(mktemp "$template" 2>/dev/null)" || return 1
  else
    tmp="$(mktemp 2>/dev/null)" || return 1
  fi

  if [[ -n "$mode" ]]; then
    chmod "$mode" "$tmp" 2>/dev/null || warn "Could not set mode ${mode} on temporary file ${tmp}"
  fi

  : >"$tmp"

  arr_register_temp_path "$tmp"

  printf '%s\n' "$tmp"
}

# Creates a temp directory with hardened mode for transient assets
arr_mktemp_dir() {
  local template="${1-}"
  local mode="${2:-700}"
  local tmp=""

  if [[ -n "$template" ]]; then
    tmp="$(mktemp -d "$template" 2>/dev/null)" || return 1
  else
    tmp="$(mktemp -d 2>/dev/null)" || return 1
  fi

  if [[ -n "$mode" ]]; then
    chmod "$mode" "$tmp" 2>/dev/null || warn "Could not set mode ${mode} on temporary directory ${tmp}"
  fi

  arr_register_temp_path "$tmp"

  printf '%s\n' "$tmp"
}

# Re-execs script with elevated privileges via sudo/pkexec/su, preserving argv when possible
arr_escalate_privileges() {
  if [[ "${ARR_ESCALATED:-0}" == "1" ]]; then
    return 0
  fi

  _euid="${EUID:-$(id -u)}"
  if [ "${_euid}" -eq 0 ]; then
    return 0
  fi

  _script_path="${0:-}"
  if [ -n "${_script_path}" ] && [ "${_script_path#./}" = "${_script_path}" ] && [ "${_script_path#/}" = "${_script_path}" ]; then
    if command -v realpath >/dev/null 2>&1; then
      _script_path="$(realpath "${_script_path}" 2>/dev/null || printf '%s' "${_script_path}")"
    else
      _script_path="$(pwd)/${_script_path}"
    fi
  fi

  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true >/dev/null 2>&1; then
      export ARR_ESCALATED=1
      # shellcheck disable=SC2093
      exec sudo -E "${_script_path}" "$@"
      unset ARR_ESCALATED
      return 0
    else
      printf '[%s] escalating privileges with sudo; you may be prompted for your password…\n' "$(basename "${_script_path}")" >&2
      export ARR_ESCALATED=1
      # shellcheck disable=SC2093
      exec sudo -E "${_script_path}" "$@"
      unset ARR_ESCALATED
      return 0
    fi
  fi

  if command -v pkexec >/dev/null 2>&1; then
    printf '[%s] escalating privileges with pkexec; you may be prompted for authentication…\n' "$(basename "${_script_path}")" >&2
    if command -v bash >/dev/null 2>&1; then
      export ARR_ESCALATED=1
      # shellcheck disable=SC2093
      exec pkexec /bin/bash -c 'exec "$@"' bash "${_script_path}" "$@"
      unset ARR_ESCALATED
    else
      export ARR_ESCALATED=1
      # shellcheck disable=SC2093
      exec pkexec /bin/sh -c 'exec "$@"' sh "${_script_path}" "$@"
      unset ARR_ESCALATED
    fi
    return 0
  fi

  if command -v su >/dev/null 2>&1; then
    printf '[%s] escalating privileges with su; you may be prompted for the root password…\n' "$(basename "${_script_path}")" >&2

    _cmd=""
    local _cmd_source=""
    if [ -n "${_script_path}" ]; then
      _cmd_source="${_script_path}"
    else
      _cmd_source="${0:-}"
    fi
    _cmd="$(arr_shell_escape_single_quotes "${_cmd_source}")"
    _cmd="'${_cmd}'"

    for _arg in "$@"; do
      _escaped="$(arr_shell_escape_single_quotes "${_arg}")"
      _cmd="${_cmd} '${_escaped}'"
    done

    export ARR_ESCALATED=1
    # shellcheck disable=SC2093
    exec su - root -c "exec ${_cmd}"
    unset ARR_ESCALATED
    return 0
  fi

  printf '[%s] ERROR: root privileges are required. Install sudo, pkexec (polkit) or su, or run this script as root.\n' "$(basename "${_script_path}")" >&2
  return 2
}

# Checks if tcp/udp port has listeners using ss, returning 2 when ss unavailable
ss_port_bound() {
  local proto="$1"
  local port="$2"

  if ! have_command ss; then
    return 2
  fi

  local flag
  case "$proto" in
    udp)
      flag="u"
      ;;
    tcp)
      flag="t"
      ;;
    *)
      return 2
      ;;
  esac

  if ss -H -ln${flag} "sport = :${port}" 2>/dev/null | awk 'NR>0 {exit 0} END {exit 1}'; then
    return 0
  fi

  return 1
}

# Checks port occupancy using lsof as a fallback when ss is unavailable
lsof_port_bound() {
  local proto="$1"
  local port="$2"

  if ! have_command lsof; then
    return 2
  fi

  local spec
  case "$proto" in
    udp)
      spec=(-iUDP:"${port}")
      ;;
    tcp)
      spec=(-iTCP:"${port}" -sTCP:LISTEN)
      ;;
    *)
      return 2
      ;;
  esac

  if lsof -nP "${spec[@]}" 2>/dev/null | awk 'NR>0 {exit 0} END {exit 1}'; then
    return 0
  fi

  return 1
}

# Answers whether any supported tool detects the port as bound
port_bound_any() {
  local proto="$1"
  local port="$2"

  if ss_port_bound "$proto" "$port"; then
    return 0
  fi

  if lsof_port_bound "$proto" "$port"; then
    return 0
  fi

  return 1
}

# Normalizes bind targets to comparable forms (handles IPv6-v4 mapped addresses)
normalize_bind_address() {
  local address="${1:-}"

  address="${address%%%*}"
  address="${address#[}"
  address="${address%]}"

  if [[ "$address" == ::ffff:* ]]; then
    address="${address##::ffff:}"
  fi

  if [[ -z "$address" ]]; then
    address="*"
  fi

  printf '%s\n' "$address"
}

# Determines if desired bind address conflicts with an existing listener binding
address_conflicts() {
  local desired_raw="$1"
  local actual_raw="$2"

  local desired
  local actual
  desired="$(normalize_bind_address "$desired_raw")"
  actual="$(normalize_bind_address "$actual_raw")"

  if [[ "$desired" == "0.0.0.0" || "$desired" == "*" ]]; then
    return 0
  fi

  case "$actual" in
    "0.0.0.0" | "::" | "*")
      return 0
      ;;
  esac

  if [[ "$desired" == "$actual" ]]; then
    return 0
  fi

  return 1
}

# Wrapper for docker compose respecting ARR_STACK_DIR and cached command resolution
compose() {
  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    die "Docker Compose command not detected; run preflight first"
  fi

  local project_dir="${ARR_STACK_DIR:-}"

  if [[ -n "$project_dir" ]]; then
    if [[ ! -d "$project_dir" ]]; then
      die "Stack directory not found: ${project_dir}"
    fi

    (
      cd "$project_dir" || die "Failed to change to ${project_dir}"
      "${DOCKER_COMPOSE_CMD[@]}" "$@"
    )
  else
    "${DOCKER_COMPOSE_CMD[@]}" "$@"
  fi
}

arr_run_state_dir() {
  local base="${ARR_STACK_DIR:-}"

  if [[ -z "$base" ]]; then
    return 1
  fi

  printf '%s/.%s\n' "$base" "$STACK"
}

arr_run_failure_flag_path() {
  local run_dir

  if ! run_dir="$(arr_run_state_dir 2>/dev/null)"; then
    return 1
  fi

  printf '%s/run.failed\n' "$run_dir"
}

arr_clear_run_failure() {
  local flag

  if ! flag="$(arr_run_failure_flag_path 2>/dev/null)"; then
    return 0
  fi

  rm -f "$flag" 2>/dev/null || true
}

arr_write_run_failure() {
  local message="$1"
  local code="${2:-}"
  local flag

  if ! flag="$(arr_run_failure_flag_path 2>/dev/null)"; then
    return 1
  fi

  ensure_dir_mode "$(dirname "$flag")" "$DATA_DIR_MODE"

  {
    if [[ -n "$code" ]]; then
      printf 'code=%s\n' "$code"
    fi
    printf 'message=%s\n' "$message"
  } >"$flag"

  ensure_nonsecret_file_mode "$flag"
}

arr_run_failure_flag_exists() {
  local flag

  if ! flag="$(arr_run_failure_flag_path 2>/dev/null)"; then
    return 1
  fi

  [[ -f "$flag" ]]
}

arr_read_run_failure_reason() {
  local flag

  if ! flag="$(arr_run_failure_flag_path 2>/dev/null)"; then
    return 1
  fi

  [[ -f "$flag" ]] || return 1

  local message=""
  local message_rc=0
  if ! message="$(grep -m1 '^message=' "$flag" 2>/dev/null | cut -d= -f2-)"; then
    message_rc=$?
  fi

  if ((message_rc > 1)); then
    return 1
  fi

  if ((message_rc == 0)) && [[ -n "$message" ]]; then
    printf '%s\n' "$message"
    return 0
  fi

  cat "$flag"
}

arr_read_run_failure_code() {
  local flag

  if ! flag="$(arr_run_failure_flag_path 2>/dev/null)"; then
    return 1
  fi

  [[ -f "$flag" ]] || return 1

  local code=""
  local code_rc=0
  if ! code="$(grep -m1 '^code=' "$flag" 2>/dev/null | cut -d= -f2-)"; then
    code_rc=$?
  fi

  if ((code_rc > 1)); then
    return 1
  fi

  [[ -z "$code" ]] && return 1
  printf '%s\n' "$code"
}

# Resolves whether colorized output should be emitted right now
msg_color_supported() {
  arr_resolve_color_output

  if [[ "${ARR_COLOR_OUTPUT}" == 0 ]]; then
    return 1
  fi

  return 0
}

# Provides consistent timestamp used across log_* helpers
arr_timestamp() {
  date '+%H:%M:%S'
}

# Emits timestamped informational log to stdout
log_info() {
  printf '[%s] %s\n' "$(arr_timestamp)" "$*"
}

# Emits timestamped warning log to stderr
log_warn() {
  printf '[%s] WARNING: %s\n' "$(arr_timestamp)" "$*" >&2
}

# Emits timestamped error log to stderr
log_error() {
  printf '[%s] ERROR: %s\n' "$(arr_timestamp)" "$*" >&2
}

# User-facing info message without additional styling
msg() {
  if msg_color_supported; then
    printf '%b%s%b\n' "$BLUE" "$*" "$RESET"
  else
    printf '%s\n' "$*"
  fi
}

# User-facing step banner with bold styling
step() {
  if msg_color_supported; then
    printf '%b[STEP] ⁂ ⟫ %s%b\n' "${BLUE}${BOLD}" "$*" "$RESET"
  else
    printf '[STEP] %s\n' "$*"
  fi
}

# User-facing warning message with optional color
warn() {
  if msg_color_supported; then
    printf '%b[‽]  %s%b\n' "$YELLOW" "$*" "$RESET" >&2
  else
    printf '[WARN]  %s\n' "$*" >&2
  fi
}

# Logs error then exits non-zero to halt the caller
die() {
  log_error "$@"
  exit 1
}

# Verifies that every temporary mv is followed by an ensure_*_file_mode guard
verify_tempfile_permission_guards() {
  local repo_root="${1:-}"

  if [[ -z "$repo_root" ]]; then
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  fi

  if ! have_command rg; then
    warn "ripgrep not found; skipping permission guard verification."
    return 0
  fi

  (
    cd "$repo_root" || exit 2

    local violations=0
    local rel_path=""
    local line=""
    local snippet=""

    while IFS=: read -r rel_path line _; do
      [[ -f "$rel_path" ]] || continue
      snippet="$(sed -n "$((line + 1)),$((line + 8))p" "$rel_path")"
      if [[ "$snippet" != *ensure_*_file_mode* ]]; then
        warn "Missing ensure_*_file_mode after mv \"\$tmp\" in ${rel_path}:${line}"
        violations=1
      fi
    done < <(rg --line-number 'mv "\$tmp"' --glob '*.sh' || true)

    exit "$violations"
  )

  local status=$?
  if [[ "$status" -eq 2 ]]; then
    die "Unable to enter ${repo_root} to verify permission guards"
  fi

  return "$status"
}

# Sets up logging streams and symlinks before installer output begins
init_logging() {
  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir_mode "$log_dir" "$DATA_DIR_MODE"

  local timestamp
  if [[ -n "${ARR_LOG_TIMESTAMP:-}" ]]; then
    timestamp="${ARR_LOG_TIMESTAMP}"
  else
    timestamp="$(date +%Y%m%d-%H%M%S)"
    export ARR_LOG_TIMESTAMP="$timestamp"
  fi
  LOG_FILE="${log_dir}/${STACK}-${timestamp}.log"

  : >"$LOG_FILE"
  ensure_nonsecret_file_mode "$LOG_FILE"

  local latest_link="${log_dir}/latest.log"
  ln -sf "$LOG_FILE" "$latest_link"

  local install_log="${ARR_INSTALL_LOG:-${log_dir}/${STACK}-install.log}"
  local install_hint=""
  if [[ -n "$install_log" ]]; then
    local install_dir
    install_dir="$(dirname "$install_log")"
    ensure_dir_mode "$install_dir" "$DATA_DIR_MODE"
    if [[ "$install_log" != "$LOG_FILE" ]]; then
      ln -sf "$LOG_FILE" "$install_log"
      install_hint="Latest install log symlink: ${install_log}"
    else
      install_hint="Install log: ${install_log}"
    fi
  fi

  exec > >(tee -a "$LOG_FILE")
  exec 2>&1

  msg "Installation started at $(date)"
  msg "Log file: $LOG_FILE"
  if [[ -n "$install_hint" ]]; then
    msg "$install_hint"
  fi
}

# Serializes installer runs via lockfile to avoid concurrent writes
acquire_lock() {
  local lock_dir="${ARR_STACK_DIR:-/tmp}"
  local timeout=30
  local elapsed=0

  if [ ! -d "$lock_dir" ]; then
    if ! mkdir -p "$lock_dir" 2>/dev/null; then
      lock_dir="/tmp"
    fi
  fi

  local lockfile="${lock_dir}/.${STACK}.lock"

  local force_unlock="${ARR_FORCE_UNLOCK:-0}"
  if [[ "${force_unlock}" == "1" && -e "${lockfile}" ]]; then
    local previous_owner=""
    if previous_owner="$(cat "${lockfile}" 2>/dev/null)"; then
      previous_owner="${previous_owner//[$'\n\r\t ']}"
    fi
    if [[ -n "${previous_owner}" ]]; then
      warn "Force-unlocking existing installer lock held by PID ${previous_owner} (${lockfile})."
    else
      warn "Force-unlocking existing installer lock at ${lockfile}."
    fi
    if ! rm -f -- "${lockfile}" 2>/dev/null; then
      die "Failed to remove existing installer lock at ${lockfile}."
    fi
  fi

  while ! (
    set -C
    printf '%s' "$$" >"$lockfile"
  ) 2>/dev/null; do
    if [ "$elapsed" -ge "$timeout" ]; then
      die "Could not acquire lock after ${timeout}s. Another instance may be running."
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  chmod "$LOCK_FILE_MODE" "$lockfile" 2>/dev/null || true

  ARR_LOCKFILE="$lockfile"
  arr_register_cleanup
}

# Safely writes content to target by staging through a temp file with correct mode
atomic_write() {
  local target="$1"
  local content="$2"
  local mode="${3:-600}"
  local tmp

  tmp="$(arr_mktemp_file "${target}.XXXXXX.tmp" '')" || die "Failed to create temp file for ${target}"

  if ! printf '%s\n' "$content" >"$tmp" 2>/dev/null; then
    arr_cleanup_temp_path "$tmp"
    die "Failed to write to temporary file for ${target}"
  fi

  local allow_sudo=0
  if arr_should_force_permission_sudo "$target"; then
    allow_sudo=1
  fi
  if [[ "${ARR_ALLOW_SUDO_DIRS:-0}" == "1" ]]; then
    allow_sudo=1
  fi

  local can_use_sudo=0
  if ((allow_sudo == 1)) && [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    can_use_sudo=1
  fi

  if ! chmod "$mode" "$tmp" 2>/dev/null; then
    if ((can_use_sudo == 1)); then
      if ! sudo chmod "$mode" "$tmp" 2>/dev/null; then
        arr_cleanup_temp_path "$tmp"
        die "Failed to set permissions on ${target}"
      fi
    else
      arr_cleanup_temp_path "$tmp"
      die "Failed to set permissions on ${target}"
    fi
  fi

  local moved=0
  if mv -f "$tmp" "$target" 2>/dev/null; then
    moved=1
  elif ((can_use_sudo == 1)) && sudo mv -f "$tmp" "$target" 2>/dev/null; then
    moved=1
  fi

  if ((moved == 0)); then
    arr_cleanup_temp_path "$tmp"
    die "Failed to atomically write ${target}"
  fi

  arr_unregister_temp_path "$tmp"

  if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
    if chown "${PUID}:${PGID}" "$target" 2>/dev/null; then
      :
    elif ((can_use_sudo == 1)) && sudo chown "${PUID}:${PGID}" "$target" 2>/dev/null; then
      :
    elif arr_should_force_permission_sudo "$target"; then
      die "Failed to set ownership on ${target}"
    else
      warn "Could not set ownership on ${target}"
    fi
  fi

  ensure_file_mode "$target" "$mode"
}

# Trims leading/trailing whitespace without touching inner spacing
trim_string() {
  local value="${1-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# Normalizes an environment variable name by uppercasing and collapsing
# separators so variants like "arr-docker__dir" map to "ARR_DOCKER_DIR".
arr_compose_normalize_env_name() {
  local name="${1-}"
  name="${name^^}"
  name="${name//[^A-Z0-9_]/_}"
  while [[ "$name" == *"__"* ]]; do
    name="${name//__/_}"
  done
  name="${name#_}"
  name="${name%_}"
  while [[ "$name" == *"__"* ]]; do
    name="${name//__/_}"
  done
  printf '%s' "$name"
}

# Removes underscores after normalization so fuzzy matching can compare
# compacted variants (e.g., RADARR_DIR → RADARRDIR).
arr_compose_compact_env_name() {
  local name
  name="$(arr_compose_normalize_env_name "$1")"
  name="${name//_/}"
  printf '%s' "$name"
}

# Determines whether two compacted names differ by a single character
# insertion/deletion (treats RADARDIR vs RADARRDIR as a match).
arr_compose_is_single_insertion() {
  local shorter="$1"
  local longer="$2"
  local len_shorter="${#shorter}"
  local len_longer="${#longer}"

  if ((len_longer - len_shorter != 1)); then
    return 1
  fi

  local i=0
  local j=0
  local skipped=0

  while ((i < len_shorter && j < len_longer)); do
    if [[ "${shorter:i:1}" == "${longer:j:1}" ]]; then
      ((i++))
      ((j++))
      continue
    fi

    if ((skipped != 0)); then
      return 1
    fi

    skipped=1
    ((j++))
  done

  return 0
}

# Collects canonical environment keys from defaults, the generated .env, and
# the current exported environment so compose validation has a stable catalog
# even before .env is regenerated.
arr_compose_collect_canonical_env_names() {
  local env_file="${1:-}"
  declare -A seen=()
  local key=""

  if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
    while IFS= read -r key; do
      [[ -z "$key" ]] && continue
      if [[ -z "${seen[$key]:-}" ]]; then
        printf '%s\n' "$key"
        seen["$key"]=1
      fi
    done < <(arr_collect_all_expected_env_keys 2>/dev/null || true)
  fi

  if [[ -n "$env_file" && -f "$env_file" ]]; then
    while IFS= read -r key_line || [[ -n "$key_line" ]]; do
      [[ -z "${key_line//[[:space:]]/}" ]] && continue
      [[ "$key_line" =~ ^[[:space:]]*# ]] && continue
      if [[ "$key_line" == *'='* ]]; then
        key="${key_line%%=*}"
        key="$(trim_string "$key")"
        if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -z "${seen[$key]:-}" ]]; then
          printf '%s\n' "$key"
          seen["$key"]=1
        fi
      fi
    done <"$env_file"
  fi

  while IFS='=' read -r key _ || [[ -n "$key" ]]; do
    [[ -z "$key" ]] && continue
    if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -z "${seen[$key]:-}" ]]; then
      printf '%s\n' "$key"
      seen["$key"]=1
    fi
  done < <(env)
}

arr_function_exists() {
  declare -f "$1" >/dev/null 2>&1
}

arr_normalize_bool() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      printf '1\n'
      ;;
    *)
      printf '0\n'
      ;;
  esac
}

arr_validate_ipv4_safe() {
  local ip="${1:-}"
  if arr_function_exists validate_ipv4; then
    validate_ipv4 "$ip"
    return
  fi
  [[ "$ip" =~ ^(([0-9]{1,3})\.){3}[0-9]{1,3}$ ]]
}

arr_ipv4_is_private_pattern() {
  local ip="${1:-}"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

arr_is_private_ipv4_safe() {
  local ip="${1:-}"
  if arr_function_exists is_private_ipv4; then
    is_private_ipv4 "$ip"
    return
  fi
  arr_validate_ipv4_safe "$ip" && arr_ipv4_is_private_pattern "$ip"
}

arr_hostname_private_candidates() {
  if ! command -v hostname >/dev/null 2>&1; then
    return 1
  fi
  hostname -I 2>/dev/null | tr ' ' '\n' | awk 'NF'
}

arr_derive_dns_host_entry() {
  local ip="${LAN_IP:-}"

  if [[ -n "$ip" && "$ip" != "0.0.0.0" ]] && arr_validate_ipv4_safe "$ip" && arr_is_private_ipv4_safe "$ip"; then
    printf '%s\n' "$ip"
    return 0
  fi

  local candidate
  local -a host_candidates=()
  if command -v hostname >/dev/null 2>&1; then
    mapfile -t host_candidates < <(arr_hostname_private_candidates 2>/dev/null || true)
  fi

  for candidate in "${host_candidates[@]}"; do
    [[ -z "$candidate" ]] && continue
    if arr_validate_ipv4_safe "$candidate" && arr_is_private_ipv4_safe "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  printf '%s\n' "127.0.0.1"
}

arr_derive_gluetun_firewall_outbound_subnets() {
  local ip="${LAN_IP:-}"
  local -a candidates=("192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")
  local cidr=""

  if [[ -n "$ip" ]] && arr_function_exists lan_ipv4_subnet_cidr; then
    local cidr_rc=0
    if cidr="$(lan_ipv4_subnet_cidr "$ip" 2>/dev/null)"; then
      if [[ -n "$cidr" ]]; then
        candidates=("$cidr" "${candidates[@]}")
      fi
    else
      cidr_rc=$?
      if ((cidr_rc != 0)); then
        : # Ignore failure; fallback candidates cover the defaults.
      fi
    fi
  fi

  printf '%s\n' "${candidates[@]}" | LC_ALL=C sort -u | paste -sd, -
}

arr_derive_gluetun_firewall_input_ports() {
  local split_mode="${SPLIT_VPN:-0}"
  local expose_direct="${EXPOSE_DIRECT_PORTS:-0}"
  local -a ports=()
  local port=""

  if [[ "$split_mode" != "1" && "${ENABLE_CADDY:-0}" == "1" ]]; then
    for port in "${CADDY_HTTP_PORT:-}" "${CADDY_HTTPS_PORT:-}"; do
      [[ -n "$port" ]] && ports+=("$port")
    done
  fi

  if [[ "$split_mode" == "1" ]]; then
    port="${QBT_PORT:-}"
    [[ -n "$port" ]] && ports+=("$port")
  elif [[ "$expose_direct" == "1" ]]; then
    for port in \
      "${QBT_PORT:-}" "${SONARR_PORT:-}" "${RADARR_PORT:-}" \
      "${PROWLARR_PORT:-}" "${BAZARR_PORT:-}" "${FLARR_PORT:-}"; do
      [[ -n "$port" ]] && ports+=("$port")
    done
    if [[ "${SABNZBD_ENABLED:-0}" == "1" && "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
      port="${SABNZBD_PORT:-}"
      [[ -n "$port" ]] && ports+=("$port")
    fi
  fi

  if ((${#ports[@]} == 0)); then
    printf '\n'
    return 0
  fi

  local -A seen=()
  local -a deduped=()
  for port in "${ports[@]}"; do
    if [[ -n "$port" && -z "${seen[$port]:-}" && "$port" =~ ^[0-9]+$ ]]; then
      seen["$port"]=1
      deduped+=("$port")
    fi
  done

  if ((${#deduped[@]} == 0)); then
    printf '\n'
    return 0
  fi

  IFS=, printf '%s\n' "${deduped[*]}"
}

arr_derive_openvpn_user() {
  if [[ ${OPENVPN_USER+x} ]]; then
    printf '%s\n' "${OPENVPN_USER}"
    return 0
  fi

  if [[ -n "${OPENVPN_USER_VALUE:-}" ]]; then
    printf '%s\n' "${OPENVPN_USER_VALUE}"
    return 0
  fi

  if [[ -n "${PROTON_USER_VALUE:-}" ]]; then
    printf '%s\n' "${PROTON_USER_VALUE%+pmp}+pmp"
    return 0
  fi

  printf '\n'
}

arr_derive_openvpn_password() {
  if [[ ${OPENVPN_PASSWORD+x} ]]; then
    printf '%s\n' "${OPENVPN_PASSWORD}"
    return 0
  fi

  if [[ -n "${PROTON_PASS_VALUE:-}" ]]; then
    printf '%s\n' "${PROTON_PASS_VALUE}"
    return 0
  fi

  printf '\n'
}

arr_derive_compose_profiles_csv() {
  local -a profiles=(ipdirect)

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    profiles+=(proxy)
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    profiles+=(localdns)
  fi

  if ((${#profiles[@]} == 0)); then
    printf '\n'
    return 0
  fi

  local -A seen=()
  local -a deduped=()
  local profile
  for profile in "${profiles[@]}"; do
    if [[ -n "$profile" && -z "${seen[$profile]:-}" ]]; then
      seen["$profile"]=1
      deduped+=("$profile")
    fi
  done

  IFS=, printf '%s\n' "${deduped[*]}"
}

arr_assign_upstream_dns_env() {
  local -a servers=("$@")

  if ((${#servers[@]} == 0)); then
    if declare -p ARR_UPSTREAM_DNS_CHAIN >/dev/null 2>&1; then
      servers=("${ARR_UPSTREAM_DNS_CHAIN[@]}")
    fi
  fi

  if ((${#servers[@]} == 0)); then
    servers=("1.1.1.1" "1.0.0.1")
  fi

  local csv_input
  csv_input="$(IFS=,; printf '%s' "${servers[*]}")"
  local csv_normalized
  csv_normalized="$(normalize_csv "$csv_input")"
  local -a normalized=()
  IFS=',' read -r -a normalized <<<"$csv_normalized"

  UPSTREAM_DNS_SERVERS="$csv_normalized"
  UPSTREAM_DNS_1="${normalized[0]:-}"
  UPSTREAM_DNS_2="${normalized[1]:-}"
  export UPSTREAM_DNS_SERVERS UPSTREAM_DNS_1 UPSTREAM_DNS_2
}

# Deduplicates and normalizes comma-separated lists while stripping whitespace
normalize_csv() {
  local csv="${1-}"
  csv="${csv//$'\r'/}"
  csv="${csv//$'\n'/,}"
  csv="${csv//$'\t'/,}"

  local -A seen=()
  local -a ordered=()
  local entry
  local IFS=','
  read -ra entries <<<"$csv"

  for entry in "${entries[@]}"; do
    entry="$(trim_string "$entry")"
    [[ -z "$entry" ]] && continue
    if [[ -z "${seen[$entry]+x}" ]]; then
      seen[$entry]=1
      ordered+=("$entry")
    fi
  done

  local joined=""
  for entry in "${ordered[@]}"; do
    if [[ -z "$joined" ]]; then
      joined="$entry"
    else
      joined+=",$entry"
    fi
  done

  printf '%s' "$joined"
}

# Builds ordered upstream DNS list from env overrides or defaults
collect_upstream_dns_servers() {
  local csv=""

  if [[ -n "${UPSTREAM_DNS_1:-}" ]]; then
    csv+="${UPSTREAM_DNS_1}"
  fi

  if [[ -n "${UPSTREAM_DNS_SERVERS:-}" ]]; then
    csv+="${csv:+,}${UPSTREAM_DNS_SERVERS}"
  fi

  if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
    csv+="${csv:+,}${UPSTREAM_DNS_2}"
  fi

  if [[ -z "$csv" ]]; then
    if declare -p ARR_UPSTREAM_DNS_CHAIN >/dev/null 2>&1; then
      local entry
      for entry in "${ARR_UPSTREAM_DNS_CHAIN[@]}"; do
        csv+="${csv:+,}${entry}"
      done
    fi
  fi

  if [[ -z "$csv" ]]; then
    csv="1.1.1.1,1.0.0.1"
  fi

  csv="$(normalize_csv "$csv")"

  local -a servers=()
  IFS=',' read -r -a servers <<<"$csv"

  local server
  for server in "${servers[@]}"; do
    [[ -z "$server" ]] && continue
    printf '%s\n' "$server"
  done
}

# Tests whether a DNS resolver answers queries using whichever CLI is available
probe_dns_resolver() {
  local server="$1"
  local domain="${2:-cloudflare.com}"
  local timeout="${3:-2}"

  if command -v dig >/dev/null 2>&1; then
    if dig +time="${timeout}" +tries=1 @"${server}" "${domain}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v drill >/dev/null 2>&1; then
    if drill -Q "${domain}" @"${server}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v kdig >/dev/null 2>&1; then
    if kdig @"${server}" "${domain}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  if command -v nslookup >/dev/null 2>&1; then
    if nslookup "${domain}" "${server}" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi

  return 2
}

# Flags nested ${...${...}} constructs that docker compose cannot interpolate
arr_scan_nested_placeholders() {
  local file="$1"

  if [[ -z "$file" || ! -f "$file" ]]; then
    return 1
  fi

  local line=""
  local line_no=0
  local depth=0
  local max_depth=0
  local char=""
  local i=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    depth=0
    max_depth=0

    for ((i = 0; i < ${#line}; i++)); do
      char="${line:i:1}"

      if [[ "$char" == '$' && $((i + 1)) -lt ${#line} && "${line:i+1:1}" == '{' ]]; then
        depth=$((depth + 1))
        ((depth > max_depth)) && max_depth=$depth
        ((i++))
        continue
      fi

      if [[ "$char" == '}' && depth -gt 0 ]]; then
        depth=$((depth - 1))
      fi
    done

    if ((max_depth > 1)); then
      printf '%d\t%s\n' "$line_no" "$line"
    fi
  done <"$file"
}

arr_evaluate_nested_placeholder() {
  local expr="$1"

  if [[ -z "$expr" ]]; then
    return 1
  fi

  if [[ "$expr" == *$'$(' || "$expr" == *$'\x60' ]]; then
    return 1
  fi

  if [[ ! "$expr" =~ ^\$\{[A-Za-z0-9_!:?+\-\{\}\$]*\}$ ]]; then
    return 1
  fi

  local sanitized="${expr//"/\\"}"
  local resolved=""

  # Intentionally using eval to resolve trusted/generated placeholders; guarded by rejecting
  # $(...) and backticks, regex validation, and quote escaping. Consider allowlisting specific
  # parameter operators or forbidding characters like ':' or '-' for extra hardening.
  if ! resolved="$(eval "printf '%s' \"${sanitized}\"")"; then
    return 1
  fi

  printf '%s' "$resolved"
}

arr_replace_nested_placeholders_in_line() {
  local line="$1"
  local working="$line"
  local replaced=0
  local placeholder=""
  local resolved=""
  local max_iterations=50
  local iterations=0
  local i=0

  while [[ "$working" == *"\${"* ]]; do
    ((iterations++))
    if ((iterations > max_iterations)); then
      warn "  Reached maximum nested placeholder resolution iterations; stopping"
      break
    fi

    local prefix="${working%%\$\{*}"
    local remainder="${working:${#prefix}}"
    local brace_count=0
    local found=0

    # The remainder starts with '${', so we start with a brace_count of 1
    # and scan from the 3rd character.
    brace_count=1
    for ((i = 2; i < ${#remainder}; i++)); do
      local ch="${remainder:i:1}"
      if [[ "$ch" == "{" ]]; then
        ((brace_count++))
      elif [[ "$ch" == "}" ]]; then
        ((brace_count--))
        if ((brace_count == 0)); then
          placeholder="${remainder:0:i+1}"
          found=1
          break
        fi
      fi
    done

    if ((found == 0)); then
      warn "  Unable to locate closing brace for nested placeholder starting at: ${remainder}"
      break
    fi

    if ! resolved="$(arr_evaluate_nested_placeholder "$placeholder")"; then
      warn "  Unable to resolve nested placeholder ${placeholder} automatically"
      break
    fi
    # Prevent infinite loop when no progress can be made
    if [[ "$resolved" == "$placeholder" ]]; then
      warn "  Nested placeholder ${placeholder} did not resolve to a different value; stopping to avoid infinite loop"
      break
    fi

    local rest="${remainder:${#placeholder}}"
    working="${prefix}${resolved}${rest}"
    replaced=1
  done

  printf '%s' "$working"

  if ((replaced == 0)); then
    return 1
  fi
}

arr_hardcode_nested_placeholders() {
  local file="$1"
  local nested_blob="$2"

  if [[ -z "$file" || -z "$nested_blob" ]]; then
    return 1
  fi

  local tmp=""
  tmp="$(arr_mktemp_file "${file}.XXXXXX.hardcode" '')" || return 1

  local -A targets=()
  local -a ordered_lines=()
  local line_no=""
  local content=""

  while IFS=$'\t' read -r line_no content; do
    [[ -z "$line_no" ]] && continue
    if [[ -z "${targets[$line_no]+x}" ]]; then
      ordered_lines+=("$line_no")
    fi
    targets[$line_no]="$content"
  done <<<"$nested_blob"

  local current_line=0
  local line=""
  local resolved_line=""
  local unresolved=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    current_line=$((current_line + 1))

    if [[ -n "${targets[$current_line]:-}" ]]; then
      if resolved_line="$(arr_replace_nested_placeholders_in_line "$line")"; then
        printf '%s\n' "$resolved_line" >>"$tmp"
      else
        printf '%s\n' "$line" >>"$tmp"
        unresolved=1
      fi
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$file"

  if ! mv "$tmp" "$file"; then
    warn "Failed to update ${file} while hardcoding nested placeholders"
    return 1
  fi

  if ((unresolved)); then
    warn "Unable to resolve all nested placeholders automatically"
    return 1
  fi

  local summary=""
  summary="$(printf 'L%s ' "${ordered_lines[@]}")"
  summary="${summary%% }"
  if [[ -n "$summary" ]]; then
    msg "Hardcoded nested placeholders on lines: ${summary}"
  fi

  return 0
}

verify_single_level_env_placeholders() {
  local file="$1"

  if [[ -z "$file" || ! -f "$file" ]]; then
    die "verify_single_level_env_placeholders requires an existing file"
  fi

  local nested=""
  if ! nested="$(arr_scan_nested_placeholders "$file")"; then
    die "Failed to inspect ${file} for nested placeholders"
  fi

  if [[ -z "$nested" ]]; then
    return 0
  fi

  warn "Detected unsupported nested environment placeholders while rendering ${file}"
  warn "  Offending lines:"

  local line_no=""
  local content=""
  while IFS=$'\t' read -r line_no content; do
    warn "    L${line_no}: ${content}"
  done <<<"$nested"

  local auto_fix=0
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    auto_fix=1
    msg "ASSUME_YES=1; automatically hardcoding nested placeholders."
  else
    printf 'Replace nested environment placeholders with hardcoded values? [y/N]: '
    local response=""
    if ! read -r response; then
      warn "Could not read response; nested placeholders remain."
      return 1
    fi
    case "${response,,}" in
      y | yes)
        auto_fix=1
        ;;
      *)
        warn "Nested placeholders remain; aborting compose generation."
        return 1
        ;;
    esac
  fi

  if ((auto_fix == 0)); then
    return 1
  fi

  if ! arr_hardcode_nested_placeholders "$file" "$nested"; then
    warn "Nested placeholders could not be hardcoded automatically."
    return 1
  fi

  local post_fix=""
  post_fix="$(arr_scan_nested_placeholders "$file")"
  if [[ -n "$post_fix" ]]; then
    warn "Nested placeholders persist after attempted hardcoding; manual intervention required."
    return 1
  fi

  return 0
}

# Ensure every ${VAR} in compose file maps to a known key; catch while we know which module introduced the $VAR.
arr_verify_compose_placeholders() {
  local compose_file="$1"
  local env_file="$2"
  if [[ -z "$compose_file" || ! -f "$compose_file" ]]; then
    die "arr_verify_compose_placeholders requires an existing compose file"
  fi
  declare -A _arr_known_env=()
  local _arr_key=""
  while IFS= read -r _arr_key; do
    [[ -z "$_arr_key" ]] && continue
    _arr_known_env["$_arr_key"]=1
  done < <(arr_compose_collect_canonical_env_names "$env_file")
  local _arr_unexpected=0
  local _arr_placeholder="" _arr_name="" _arr_sep=""
  local _arr_matches=""
  # Match ${VAR}, ${VAR-...}, ${VAR:-...}, ${VAR=...}, ${VAR:=...}, ${VAR?...}, ${VAR:+...}
  local _arr_matches_rc=0
  local _arr_raw_matches=""
  local -a _arr_missing=()

  if ! _arr_raw_matches="$(LC_ALL=C grep -oE '\$\{[A-Za-z_][A-Za-z0-9_]*([:\-=\?+][^}]*)?\}' "$compose_file" 2>/dev/null)"; then
    _arr_matches_rc=$?
  else
    if [[ -n "$_arr_raw_matches" ]]; then
      _arr_matches="$(printf '%s\n' "$_arr_raw_matches" | sort -u)"
    else
      _arr_matches=""
    fi
  fi

  if ((_arr_matches_rc > 1)); then
    die "Failed to inspect ${compose_file} for environment placeholders (grep exited with ${_arr_matches_rc})"
  fi

  if ((_arr_matches_rc != 0)) || [[ -z "$_arr_matches" ]]; then
    return 0
  fi

  _arr_name="${_arr_name%%"$_arr_sep"*}"
  while IFS= read -r _arr_placeholder; do
    _arr_name="${_arr_placeholder:2:${#_arr_placeholder}-3}"
    # Strip any parameter operator and default/message segment
    for _arr_sep in ':-' '-' ':=' ':?' ':+'; do
      if [[ "$_arr_name" == *"$_arr_sep"* ]]; then
        _arr_name="${_arr_name%%"$_arr_sep"*}"
      fi
    done
    if [[ -z "$_arr_name" ]]; then
      continue
    fi
    if [[ -n "${_arr_known_env[${_arr_name}]:-}" ]]; then
      continue
    fi
    if [[ ${!_arr_name+x} ]]; then
      continue
    fi
    printf "[placeholders] Unexpected placeholder \${%s} in %s\n" "$_arr_name" "$compose_file" >&2
    local _arr_display=""
    printf -v _arr_display "\${%s}" "$_arr_name"
    _arr_missing+=("${_arr_display}")
    _arr_unexpected=1
  done <<<"$_arr_matches"
  if ((_arr_unexpected)); then
    warn "compose env placeholders unresolved after auto-repair:"
    local _arr_missing_entry=""
    for _arr_missing_entry in "${_arr_missing[@]}"; do
      warn "  ${_arr_missing_entry}"
    done
  fi
  return "$_arr_unexpected"
}

# Applies sed edits via temp file for portability across BSD/GNU variants
portable_sed() {
  local expr="$1"
  local file="$2"
  local tmp

  tmp="$(arr_mktemp_file "${file}.XXXXXX.tmp")" || die "Failed to create temp file for sed"

  local perms=""
  if [ -e "$file" ]; then
    perms="$(arr_run_sensitive_command stat -c '%a' "$file" || true)"
    perms="${perms//$'\n'/}"
  fi

  if arr_run_sensitive_command sh -c 'sed -e "$1" "$2" >"$3"' sh "$expr" "$file" "$tmp"; then
    if [ -f "$file" ] && cmp -s "$file" "$tmp" 2>/dev/null; then
      arr_cleanup_temp_path "$tmp"
      return 0
    fi

    if arr_run_sensitive_command mv -f "$tmp" "$file"; then
      arr_unregister_temp_path "$tmp"
    else
      arr_cleanup_temp_path "$tmp"
      die "Failed to update ${file}"
    fi

    [[ -n "$perms" ]] && ensure_file_mode "$file" "$perms"
  else
    arr_cleanup_temp_path "$tmp"
    die "sed operation failed on ${file}"
  fi
}

# Escapes replacement strings for safe use in sed substitution bodies
escape_sed_replacement() {
  local s="${1-}"
  local delim="${2:-/}"

  # Always escape backslashes, newlines and '&' which have special meaning in replacements.
  s="${s//\\/\\\\}"
  s="${s//$'\n'/\\n}"
  s="${s//&/\\&}"
  
  case "$delim" in
    '/') s="${s//\//\\/}" ;;
    '|') s="${s//|/\\|}" ;;
    '#') s="${s//#/\\#}" ;;
    *) : ;;  # Add more delimiters as needed.
  esac

  printf '%s' "$s"
}

# Reverses docker compose escaping to recover raw env values (handles $$ expansion)
unescape_env_value_from_compose() {
  local value="${1-}"
  local sentinel=$'\001__ARR_DOLLAR__\002'

  value="${value//$'\r'/}" # Normalize line endings

  if ((${#value} >= 2)); then
    local first_char="${value:0:1}"
    local last_char="${value: -1}"
    if [[ "$first_char" == '"' && "$last_char" == '"' ]]; then
      value="${value:1:${#value}-2}"
      value="${value//\$\$/${sentinel}}"
      value="$(printf '%b' "$value")"
      value="${value//${sentinel}/\$}"
      printf '%s' "$value"
      return
    fi
  fi

  value="${value//\$\$/${sentinel}}"
  value="${value//${sentinel}/\$}"
  printf '%s' "$value"
}

# Reads a KEY=VALUE pair from an env file and returns the decoded value
get_env_kv() {
  local key="${1:-}"
  local file="${2:-}"

  if [[ -z "$key" || -z "$file" || ! -f "$file" ]]; then
    return 1
  fi

  local line
  line="$(arr_run_sensitive_command grep -m1 "^${key}=" "$file" || true)"
  if [[ -z "$line" ]]; then
    return 1
  fi

  local value
  value="${line#*=}"
  value="$(unescape_env_value_from_compose "$value")"
  printf '%s\n' "$value"
}

# Persists installer-discovered env vars back into .env without introducing duplicates
persist_env_var() {
  local key="$1"
  local value="$2"

  if [ -z "$key" ]; then
    return
  fi

  if [[ "$value" == *$'\n'* ]]; then
    die "Environment value for ${key} contains newline characters"
  fi

  if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    warn "Skipping invalid environment variable name: ${key}"
    return
  fi

  if [[ ! -f "${ARR_ENV_FILE}" ]]; then
    return
  fi

  local line
  line="${key}=${value}"

  if arr_run_sensitive_command grep -q "^${key}=" "${ARR_ENV_FILE}"; then
    local escaped
    escaped="$(escape_sed_replacement "$line" '|')"
    portable_sed "s|^${key}=.*$|${escaped}|" "${ARR_ENV_FILE}"
  else
    arr_sensitive_append_line "${ARR_ENV_FILE}" "$line"
  fi

  ensure_file_mode "${ARR_ENV_FILE}" "$SECRET_FILE_MODE"
}

# Masks secrets for logs while leaving limited prefix/suffix context visible
obfuscate_sensitive() {
  local value="${1-}"
  local visible_prefix="${2:-2}"
  local visible_suffix="${3:-${visible_prefix}}"

  if [ -z "$value" ]; then
    printf '(not set)'
    return
  fi

  if ((visible_prefix < 0)); then
    visible_prefix=0
  fi
  if ((visible_suffix < 0)); then
    visible_suffix=0
  fi

  local length=${#value}
  if ((length <= visible_prefix + visible_suffix)); then
    printf '%*s' "$length" '' | tr ' ' '*'
    return
  fi

  local prefix=""
  local suffix=""
  ((visible_prefix > 0)) && prefix="${value:0:visible_prefix}"
  ((visible_suffix > 0)) && suffix="${value: -visible_suffix}"

  local hidden_len=$((length - visible_prefix - visible_suffix))
  local mask
  mask="$(printf '%*s' "$hidden_len" '' | tr ' ' '*')"

  printf '%s%s%s' "$prefix" "$mask" "$suffix"
}

# Generates a random alphanumeric password using best available entropy source
gen_safe_password() {
  local len="${1:-20}"

  if ((len <= 0)); then
    len=20
  fi

  if command -v openssl >/dev/null 2>&1; then
    LC_ALL=C openssl rand -base64 $((len * 2)) | tr -dc 'A-Za-z0-9' | head -c "$len" || true
    printf '\n'
    return
  fi

  if [ -r /dev/urandom ]; then
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len" || true
    printf '\n'
    return
  fi

  printf '%s' "$(date +%s%N)$$" | sha256sum | tr -dc 'A-Za-z0-9' | head -c "$len" || true
  printf '\n'
}

# Sanitizes usernames to a safe subset, defaulting to "user" when empty
sanitize_user() {
  local input="${1:-user}"
  local sanitized
  sanitized="$(printf '%s' "$input" | tr -cd 'A-Za-z0-9._-' || true)"
  if [ -z "$sanitized" ]; then
    sanitized="user"
  fi
  printf '%s' "$sanitized"
}

# Validates bcrypt hash formatting and cost bounds before accepting user input
valid_bcrypt() {
  local hash_candidate="${1:-}"

  if [[ "$hash_candidate" =~ ^\$2[aby]\$([0-3][0-9])\$[./A-Za-z0-9]{53}$ ]]; then
    local cost="${BASH_REMATCH[1]}"
    if ((10#$cost >= 4 && 10#$cost <= 31)); then
      return 0
    fi
  fi

  return 1
}

# Checks if a compose-escaped value decodes to a valid bcrypt hash
is_bcrypt_hash() {
  local escaped_candidate="${1:-}"

  escaped_candidate="$(unescape_env_value_from_compose "$escaped_candidate")"

  valid_bcrypt "$escaped_candidate"
}

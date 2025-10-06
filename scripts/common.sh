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

# Checks command availability without emitting output (used for optional deps)
have_command() {
  command -v "$1" >/dev/null 2>&1
}

# Ensures port is numeric and within 1-65535
validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
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

  if docker compose version >/dev/null 2>&1; then
    candidate=(docker compose)
    version="$(docker compose version --short 2>/dev/null || true)"
    version="${version#v}"
    major="${version%%.*}"
    if [[ -n "$major" && "$major" =~ ^[0-9]+$ ]]; then
      : # major version is valid, do nothing
    else
      version=""
    fi
  fi

  if ((${#candidate[@]} == 0)) && have_command docker-compose; then
    version="$(docker-compose version --short 2>/dev/null || true)"
    version="${version#v}"
    major="${version%%.*}"
    if [[ "$major" =~ ^[0-9]+$ ]] && ((major >= 2)); then
      candidate=(docker-compose)
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

# Provides canonical docker-data root resolution with consistent fallbacks
arr_docker_data_root() {
  local base="${ARR_DOCKER_DIR:-}"

  if [[ -n "$base" ]]; then
    printf '%s' "${base%/}"
    return
  fi

  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    printf '%s' "${ARR_STACK_DIR%/}/docker-data"
    return
  fi

  local base_root="${ARR_DATA_ROOT:-}"
  if [[ -n "$base_root" ]]; then
    printf '%s/docker-data' "${base_root%/}"
    return
  fi

  local home_dir="${HOME:-}"
  if [[ -n "$home_dir" ]]; then
    printf '%s/srv/docker-data' "${home_dir%/}"
    return
  fi

  printf '%s' "/srv/${STACK}/docker-data"
}

# Resolves the Gluetun data directory under the docker-data root
arr_gluetun_dir() {
  printf '%s/gluetun' "$(arr_docker_data_root)"
}

# Resolves the VPN auto-reconnect working directory under Gluetun assets
arr_gluetun_auto_reconnect_dir() {
  printf '%s/auto-reconnect' "$(arr_gluetun_dir)"
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

  local log_dir="${ARR_LOG_DIR:-${ARR_STACK_DIR:-}/logs}"
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
  missing="$(missing_commands "$@" || true)"

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
  missing="$(missing_commands "$@" || true)"

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
      return $rc
    fi
  fi
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
  mode="$(arr_stat_mode "$target" || true)"

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

# Applies file mode if target exists, tolerating chmod failures
ensure_file_mode() {
  local file="$1"
  local mode="$2"

  if [[ ! -e "$file" ]]; then
    return 0
  fi

  chmod "$mode" "$file" 2>/dev/null || warn "Could not apply mode ${mode} to ${file}"
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

  local message
  message="$(grep -m1 '^message=' "$flag" 2>/dev/null | cut -d= -f2- || true)"

  if [[ -n "$message" ]]; then
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

  local code
  code="$(grep -m1 '^code=' "$flag" 2>/dev/null | cut -d= -f2- || true)"
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

# User-facing info message with optional color
msg() {
  if msg_color_supported; then
    printf '%b%s%b\n' "$CYAN" "$*" "$RESET"
  else
    printf '%s\n' "$*"
  fi
}

# User-facing step banner with bold/bright styling
step() {
  if msg_color_supported; then
    printf '%b🧱📣 %s%b\n' "${BOLD}${BLUE}" "$*" "$RESET"
  else
    printf '🧱📣 %s\n' "$*"
  fi
}

# User-facing warning message with optional color
warn() {
  if msg_color_supported; then
    printf '%b⚠️ %s%b\n' "$YELLOW" "$*" "$RESET" >&2
  else
    printf '⚠️ %s\n' "$*" >&2
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
  local log_dir="${ARR_LOG_DIR:-${ARR_STACK_DIR}/logs}"
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
  trap 'rm -f -- "$ARR_LOCKFILE"' EXIT INT TERM HUP QUIT
}

# Safely writes content to target by staging through a temp file with correct mode
atomic_write() {
  local target="$1"
  local content="$2"
  local mode="${3:-600}"
  local tmp

  tmp="$(arr_mktemp_file "${target}.XXXXXX.tmp" '')" || die "Failed to create temp file for ${target}"

  if ! printf '%s\n' "$content" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to write to temporary file for ${target}"
  fi

  if ! chmod "$mode" "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to set permissions on ${target}"
  fi

  if ! mv -f "$tmp" "$target" 2>/dev/null; then
    rm -f "$tmp"
    die "Failed to atomically write ${target}"
  fi
}

# Escapes ENV values for docker compose compatibility (newline/carriage/dollar aware)
escape_env_value_for_compose() {
  local value="${1-}"

  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi

  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//\$/\$\$}"

  printf '%s' "$value"
}

# Emits KEY=VALUE lines after compose-safe escaping; errors on newline-containing values
write_env_kv() {
  local key="$1"
  local value="${2-}"

  if [[ -z "$key" ]]; then
    die "write_env_kv requires a key"
  fi

  local escaped
  escaped="$(escape_env_value_for_compose "$value")"

  if [[ "$escaped" == *$'\n'* ]]; then
    die "Environment value for ${key} contains newline characters"
  fi

  printf '%s=%s\n' "$key" "$escaped"
}

# Trims leading/trailing whitespace without touching inner spacing
trim_string() {
  local value="${1-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
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
verify_single_level_env_placeholders() {
  local file="$1"

  if [[ -z "$file" || ! -f "$file" ]]; then
    die "verify_single_level_env_placeholders requires an existing file"
  fi

  local nested=""

  nested="$(awk '/\$\{[^}]*\$\{/{printf "%d:%s\n", NR, $0}' "$file" || true)"

  if [[ -z "$nested" ]]; then
    return 0
  fi

  warn "Detected unsupported nested environment placeholders while rendering ${file}"
  warn "  Nested variable expansions:"
  printf '%s\n' "$nested" >&2

  return 1
}

# Applies sed edits via temp file for portability across BSD/GNU variants
portable_sed() {
  local expr="$1"
  local file="$2"
  local tmp

  tmp="$(arr_mktemp_file "${file}.XXXXXX.tmp")" || die "Failed to create temp file for sed"

  local perms=""
  if [ -e "$file" ]; then
    perms="$(stat -c '%a' "$file" 2>/dev/null || echo '')"
  fi

  if sed -e "$expr" "$file" >"$tmp" 2>/dev/null; then
    if [ -f "$file" ] && cmp -s "$file" "$tmp" 2>/dev/null; then
      rm -f "$tmp"
      return 0
    fi

    if ! mv -f "$tmp" "$file" 2>/dev/null; then
      rm -f "$tmp"
      die "Failed to update ${file}"
    fi

    if [ -n "$perms" ]; then
      chmod "$perms" "$file" 2>/dev/null || true
    fi
  else
    rm -f "$tmp"
    die "sed operation failed on ${file}"
  fi
}

# Escapes replacement strings for safe use in sed substitution bodies
escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&/]/\\&/g'
}

# Reverses docker compose escaping to recover raw env values (handles $$ expansion)
unescape_env_value_from_compose() {
  local value="${1-}"
  local sentinel=$'\001__ARR_DOLLAR__\002'

  value="${value//$'\r'/}" # Normalize line endings

  if [[ "$value" =~ ^".*"$ ]]; then
    value="${value:1:${#value}-2}"
    value="${value//\$\$/${sentinel}}"
    value="$(printf '%b' "$value")"
    value="${value//${sentinel}/\$}"
    printf '%s' "$value"
    return
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
  line="$(grep -m1 "^${key}=" "$file" 2>/dev/null || true)"
  if [[ -z "$line" ]]; then
    return 1
  fi

  local value
  value="${line#*=}"
  value="$(unescape_env_value_from_compose "$value")"
  printf '%s\n' "$value"
}

# Updates a qBittorrent INI key atomically, creating the file if missing
set_qbt_conf_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  local tmp
  if ! tmp="$(arr_mktemp_file "${file}.XXXX" "$SECRET_FILE_MODE")"; then
    return 1
  fi

  if [ -f "$file" ]; then
    awk -v k="$key" -v v="$value" '
      BEGIN { found=0 }
      $0 ~ "^"k"=" { print k"="v; found=1; next }
      { print }
      END { if (!found) print k"="v }
    ' "$file" >"$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >"$tmp"
  fi

  if mv "$tmp" "$file"; then
    ensure_secret_file_mode "$file"
  else
    rm -f "$tmp"
    return 1
  fi
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

  if [ -f "${ARR_ENV_FILE}" ]; then
    local compose_safe
    compose_safe="$(escape_env_value_for_compose "$value")"
    if grep -q "^${key}=" "${ARR_ENV_FILE}"; then
      local escaped
      escaped="$(escape_sed_replacement "$compose_safe")"
      portable_sed "s/^${key}=.*/${key}=${escaped}/" "${ARR_ENV_FILE}"
    else
      write_env_kv "$key" "$value" >>"${ARR_ENV_FILE}"
    fi
  fi
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
  local candidate="${1-}"

  if [[ "$candidate" =~ ^\$2[aby]\$([0-3][0-9])\$[./A-Za-z0-9]{53}$ ]]; then
    local cost="${BASH_REMATCH[1]}"
    if ((10#$cost >= 4 && 10#$cost <= 31)); then
      return 0
    fi
  fi

  return 1
}

# Checks if a compose-escaped value decodes to a valid bcrypt hash
is_bcrypt_hash() {
  local candidate="${1-}"

  candidate="$(unescape_env_value_from_compose "$candidate")"

  valid_bcrypt "$candidate"
}

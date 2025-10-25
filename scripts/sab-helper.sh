#!/usr/bin/env bash
# SABnzbd helper – query and manage the ARR Stack SABnzbd instance

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}"
if ! STACK_DIR="$(cd "${STACK_DIR}" 2>/dev/null && pwd)"; then
  echo "Stack directory not found: ${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}" >&2
  exit 1
fi

resolve_helper_path() {
  local candidate="$1"
  if [[ -f "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

COMMON_HELPER="${STACK_DIR}/scripts/common.sh"
if [[ ! -f "$COMMON_HELPER" ]]; then
  if [[ -n "${REPO_ROOT:-}" ]] && resolve_helper_path "${REPO_ROOT}/scripts/common.sh" >/dev/null; then
    COMMON_HELPER="${REPO_ROOT}/scripts/common.sh"
  elif resolve_helper_path "${STACK_DIR_DEFAULT}/scripts/common.sh" >/dev/null; then
    COMMON_HELPER="${STACK_DIR_DEFAULT}/scripts/common.sh"
  else
    echo "sab-helper: common helpers missing (looked for ${STACK_DIR}/scripts/common.sh)" >&2
    exit 1
  fi
fi

# shellcheck source=scripts/common.sh
. "$COMMON_HELPER"

if [[ -f "${STACK_DIR}/arrconf/userr.conf.defaults.sh" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "${STACK_DIR}/arrconf/userr.conf.defaults.sh"
fi

CONFIG_HELPER="${STACK_DIR}/scripts/config.sh"
if [[ ! -f "$CONFIG_HELPER" ]]; then
  if [[ -n "${REPO_ROOT:-}" ]] && resolve_helper_path "${REPO_ROOT}/scripts/config.sh" >/dev/null; then
    CONFIG_HELPER="${REPO_ROOT}/scripts/config.sh"
  elif resolve_helper_path "${STACK_DIR_DEFAULT}/scripts/config.sh" >/dev/null; then
    CONFIG_HELPER="${STACK_DIR_DEFAULT}/scripts/config.sh"
  else
    CONFIG_HELPER=""
  fi
fi

if [[ -n "$CONFIG_HELPER" ]]; then
  # shellcheck source=scripts/config.sh
  . "$CONFIG_HELPER"
fi

ENV_FILE="$(arr_env_file)"

load_env() {
  [[ -f "$ENV_FILE" ]] || return 0

  local line key raw value
  while IFS= read -r line || [[ -n $line ]]; do
    line="${line//$'\r'/}"
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^[[:space:]]*export[[:space:]]+(.+)$ ]] && line="${BASH_REMATCH[1]}"
    [[ $line =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue

    key="${BASH_REMATCH[1]}"
    raw="${BASH_REMATCH[2]}"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    value="$(unescape_env_value_from_compose "$raw")"

    if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      printf -v "$key" '%s' "$value"
      # shellcheck disable=SC2163  # export is intentional for dynamic key names
      export "$key"
    else
      log_warn "Invalid environment variable name '$key' in $ENV_FILE, skipping."
    fi
  done <"$ENV_FILE"
}

sab_enabled() {
  [[ "${SABNZBD_ENABLED:-0}" == "1" ]]
}

sab_check_env() {
  if ! sab_enabled; then
    log_warn "SABNZBD_ENABLED=0"
    return 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    log_error "curl is required"
    return 1
  fi

  if [[ -z "${SABNZBD_API_KEY:-}" ]]; then
    log_warn "SABNZBD_API_KEY is empty; API calls may fail"
  fi

  local timeout
  arr_resolve_positive_int timeout "${SABNZBD_TIMEOUT:-}" 15 "" log_warn
  SABNZBD_TIMEOUT="$timeout"

  local sab_port
  arr_resolve_port sab_port "${SABNZBD_PORT:-}" "${SABNZBD_INT_PORT:-8080}" "" log_warn
  SABNZBD_PORT="$sab_port"

  local sab_host="${SABNZBD_HOST:-${LOCALHOST_IP:-localhost}}"
  if [[ -z "$sab_host" ]]; then
    sab_host="${LOCALHOST_IP:-localhost}"
  fi
  SABNZBD_HOST="$sab_host"

  local sab_helper_scheme="${SABNZBD_HELPER_SCHEME:-http}"
  if [[ -z "$sab_helper_scheme" ]]; then
    sab_helper_scheme="http"
  fi
  SABNZBD_HELPER_SCHEME="$sab_helper_scheme"

  SAB_HELPER_ENV_READY=1
  return 0
}

sab_base_url() {
  sab_check_env || return 1
  local scheme="${SABNZBD_HELPER_SCHEME:-http}"
  local host="${SABNZBD_HOST:-${LOCALHOST_IP:-localhost}}"
  local port="${SABNZBD_PORT:-${SABNZBD_INT_PORT:-8080}}"
  printf '%s://%s:%s' "$scheme" "$host" "$port" | sed 's#[[:space:]]##g' | sed 's#/*$##'
}

sab_api() {
  local query="${1:-}"

  sab_check_env || return 1

  local timeout="${SABNZBD_TIMEOUT:-15}"
  local base=""
  if ! base="$(sab_base_url)"; then
    return 1
  fi
  local args="${query}"

  if [[ "$args" != *"apikey="* ]]; then
    if [[ -z "${SABNZBD_API_KEY:-}" ]]; then
      log_warn "API key required for this operation"
      return 1
    fi
    if [[ -n "$args" ]]; then
      args="apikey=${SABNZBD_API_KEY}&${args}"
    else
      args="apikey=${SABNZBD_API_KEY}"
    fi
  fi

  if [[ -n "$args" ]]; then
    args="?${args}"
  fi

  local response
  if ! response=$(curl -fsSL --connect-timeout "$timeout" "${base}/api${args}" 2>/dev/null); then
    log_error "API request failed (${base})"
    return 1
  fi

  printf '%s\n' "$response"
}

sab_version() {
  if [[ "${SAB_HELPER_ENV_READY:-0}" != "1" ]]; then
    sab_check_env || return 1
  fi

  local timeout="${SABNZBD_TIMEOUT:-15}"
  local base=""
  if ! base="$(sab_base_url)"; then
    return 1
  fi
  local output=""

  if ! output=$(curl -fsSL --connect-timeout "$timeout" "${base}/api" --get --data-urlencode 'mode=version' --data-urlencode 'output=json' 2>/dev/null); then
    return 1
  fi

  local version=""
  if command -v jq >/dev/null 2>&1; then
    version="$(jq -r '.version // empty' <<<"$output" 2>/dev/null || printf '')"
  else
    version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$output" | head -n1)"
  fi
  if [[ -z "$version" ]]; then
    printf '(unknown)\n'
    return 1
  fi
  printf '%s\n' "$version"
}

sab_queue_raw() {
  sab_api 'mode=queue&output=json'
}

sab_history_raw() {
  sab_api 'mode=history&output=json'
}

sab_status_summary() {
  sab_check_env || return 1

  local version
  version="$(sab_version 2>/dev/null || printf '(unknown)')"
  log_info "Version: ${version}"

  local queue_json
  if ! queue_json="$(sab_queue_raw 2>/dev/null)"; then
    log_warn "Unable to fetch queue"
    return 1
  fi

  if command -v jq >/dev/null 2>&1; then
    local status slots speed eta
    status="$(jq -r '.queue.status // "unknown"' <<<"$queue_json" 2>/dev/null || printf 'unknown')"
    slots="$(jq -r '.queue.slots | length' <<<"$queue_json" 2>/dev/null || printf '0')"
    speed="$(jq -r '.queue.speed // "0"' <<<"$queue_json" 2>/dev/null || printf '0')"
    log_info "Queue: status=${status}, active_items=${slots}, speed=${speed}"
    eta="$(jq -r '.queue.slots[0].timeleft // empty' <<<"$queue_json" 2>/dev/null || printf '')"
    if [[ -n "$eta" && "$eta" != "None" ]]; then
      log_info "Next completion in ${eta}"
    fi
  else
    log_warn "jq required for SAB parsing; install jq for detailed output"
  fi
}

sab_add_nzb_file() {
  local file="${1:-}"
  sab_check_env || return 1

  if [[ -z "$file" ]]; then
    log_error "add-file requires a path"
    return 1
  fi
  if [[ ! -f "$file" ]]; then
    log_error "NZB file not found: $file"
    return 1
  fi
  if [[ -z "${SABNZBD_API_KEY:-}" ]]; then
    log_error "SABNZBD_API_KEY must be set to upload NZBs"
    return 1
  fi

  local base=""
  if ! base="$(sab_base_url)"; then
    return 1
  fi
  local response
  if ! response=$(curl -fsSL --connect-timeout "${SABNZBD_TIMEOUT}" \
    -F "apikey=${SABNZBD_API_KEY}" \
    -F "output=json" \
    -F "mode=addfile" \
    -F "cat=${SABNZBD_CATEGORY:-}" \
    -F "name=@${file}" \
    "${base}/api" 2>/dev/null); then
    log_error "Failed to upload ${file}"
    return 1
  fi
  printf '%s\n' "$response"
}

sab_add_nzb_url() {
  local url="${1:-}"
  sab_check_env || return 1

  if [[ -z "$url" ]]; then
    log_error "add-url requires a URL"
    return 1
  fi
  if [[ -z "${SABNZBD_API_KEY:-}" ]]; then
    log_error "SABNZBD_API_KEY must be set to submit URLs"
    return 1
  fi

  local base=""
  if ! base="$(sab_base_url)"; then
    return 1
  fi
  local response
  if ! response=$(curl -fsSL --connect-timeout "${SABNZBD_TIMEOUT}" --get \
    --data-urlencode "apikey=${SABNZBD_API_KEY}" \
    --data-urlencode "mode=addurl" \
    --data-urlencode "name=${url}" \
    --data-urlencode "cat=${SABNZBD_CATEGORY:-}" \
    --data-urlencode "output=json" \
    "${base}/api" 2>/dev/null); then
    log_error "Failed to submit URL"
    return 1
  fi
  printf '%s\n' "$response"
}

sab_pause() {
  sab_api 'mode=pause' >/dev/null && log_info "Queue paused"
}

sab_resume() {
  sab_api 'mode=resume' >/dev/null && log_info "Queue resumed"
}

sab_delete_job() {
  local nzo_id="${1:-}"
  if [[ -z "$nzo_id" ]]; then
    log_error "delete requires an NZO ID"
    return 1
  fi
  sab_api "mode=queue&name=delete&value=${nzo_id}" >/dev/null && log_info "Deleted job ${nzo_id}"
}

sab_postprocess() {
  local -a args=("$@")
  local timestamp
  timestamp="$(arr_now_iso8601 2>/dev/null || arr_date_local '+%Y-%m-%d %H:%M:%S %Z')"

  log_info "sab.postprocess invoked at ${timestamp}"

  local idx value
  for idx in {0..7}; do
    value="${args[idx]:-}"
    log_info "sab.postprocess arg$((idx + 1))=${value}"
  done

  if ((${#args[@]} > 8)); then
    local -a extra=("${args[@]:8}")
    log_info "sab.postprocess extra_args=${extra[*]}"
  fi

  return 0
}

usage() {
  cat <<'USAGE'
usage: sab-helper.sh {version|queue|history|status|add-file <path>|add-url <url>|pause|resume|delete <nzo_id>|postprocess [args...]}
USAGE
}

main() {
  load_env

  local cmd="${1:-}"
  # shellcheck disable=SC2221,SC2222  # -* pattern intentionally includes double-dash variants
  case "$cmd" in
    version)
      sab_version
      ;;
    queue)
      sab_queue_raw
      ;;
    history)
      sab_history_raw
      ;;
    status)
      sab_status_summary
      ;;
    add-file)
      shift || true
      sab_add_nzb_file "${1:-}"
      ;;
    add-url)
      shift || true
      sab_add_nzb_url "${1:-}"
      ;;
    pause)
      sab_pause
      ;;
    resume)
      sab_resume
      ;;
    delete)
      shift || true
      sab_delete_job "${1:-}"
      ;;
    postprocess)
      shift || true
      sab_postprocess "$@"
      ;;
    -* | --*)
      usage
      return 1
      ;;
    "")
      usage
      return 1
      ;;
    *)
      usage
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

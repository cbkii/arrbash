#!/usr/bin/env bash
# shellcheck shell=bash
# Library: Helpers for interacting with the Gluetun control API.
# Provides minimal wrappers to check tunnel status and ProtonVPN forwarded ports.
# shellcheck disable=SC1091,SC2250

if [[ -n "${_ARR_GLUETUN_API_SOURCED:-}" ]]; then
  return 0
fi
_ARR_GLUETUN_API_SOURCED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=../stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

if ! declare -f die >/dev/null 2>&1; then
  die() {
    printf '%s\n' "$*" >&2
    exit 1
  }
fi

: "${GLUETUN_CONTROL_URL:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"
: "${GLUETUN_API_TIMEOUT:=8}"
: "${GLUETUN_API_RETRY_COUNT:=3}"
: "${GLUETUN_API_RETRY_DELAY:=2}"

_gluetun_api_requires() {
  if ! command -v curl >/dev/null 2>&1; then
    die "curl is required to query the Gluetun control API"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    die "jq is required to parse Gluetun control API responses"
  fi
}

_gluetun_api_request() {
  _gluetun_api_requires

  local path="$1"
  local url="${GLUETUN_CONTROL_URL%/}${path}"
  local -a args=("curl" "-fsS" "--connect-timeout" "${GLUETUN_API_TIMEOUT}" "--max-time" "${GLUETUN_API_TIMEOUT}" "${url}")

  if [[ -n "${GLUETUN_API_KEY}" ]]; then
    args+=(-H "X-API-Key: ${GLUETUN_API_KEY}")
  fi

  local attempt=1
  local max_attempts="${GLUETUN_API_RETRY_COUNT}"
  local retry_delay="${GLUETUN_API_RETRY_DELAY}"

  while ((attempt <= max_attempts)); do
    if "${args[@]}" 2>/dev/null; then
      return 0
    fi
    
    if ((attempt < max_attempts)); then
      if declare -f arr_retry >/dev/null 2>&1; then
        arr_retry "Gluetun API request to ${path} failed (attempt ${attempt}/${max_attempts}), retrying in ${retry_delay}s..."
      elif declare -f warn >/dev/null 2>&1; then
        warn "[RETRY] Gluetun API request to ${path} failed (attempt ${attempt}/${max_attempts}), retrying in ${retry_delay}s..."
      fi
      sleep "${retry_delay}"
    fi
    ((attempt++))
  done

  if declare -f arr_error >/dev/null 2>&1; then
    arr_error "Gluetun API request to ${path} failed after ${max_attempts} attempts"
    arr_action "Check if Gluetun container is running and GLUETUN_CONTROL_URL is correct"
  elif declare -f warn >/dev/null 2>&1; then
    warn "[ERROR] Gluetun API request to ${path} failed after ${max_attempts} attempts"
  fi
  return 1
}

_gluetun_api_get_json() {
  local path="$1"
  if ! _gluetun_api_request "$path"; then
    return 1
  fi
}

# Returns the OpenVPN status string ("running", "connected", etc.).
gluetun_api_status() {
  local body
  if ! body="$(_gluetun_api_get_json "/v1/openvpn/status" 2>/dev/null)"; then
    printf 'unknown'
    return 1
  fi

  local status
  status="$(printf '%s' "$body" | jq -r '.status // empty' 2>/dev/null || true)"
  if [[ -z "$status" ]]; then
    printf 'unknown'
    return 1
  fi

  printf '%s' "$status"
}

# Returns the forwarded port as an integer (0 if not available).
gluetun_api_forwarded_port() {
  local body
  if ! body="$(_gluetun_api_get_json "/v1/openvpn/portforwarded" 2>/dev/null)"; then
    printf '0'
    return 1
  fi

  local port
  port="$(printf '%s' "$body" | jq -r '.port // .data.port // 0' 2>/dev/null || printf '0')"
  if [[ "$port" =~ ^[0-9]+$ ]]; then
    printf '%s' "$port"
    return 0
  fi

  printf '0'
  return 1
}

# Wait until Gluetun reports status=running and a forwarded port is present.
# Usage: gluetun_wait_until_ready <timeout_seconds>
# Returns 0 when ready, 1 on timeout.
gluetun_wait_until_ready() {
  local timeout="${1:-120}"
  local start
  start="$(date +%s)"

  while true; do
    local status
    status="$(gluetun_api_status 2>/dev/null || printf 'unknown')"
    local port
    port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')"

    if [[ "$status" == "running" && "$port" =~ ^[1-9][0-9]*$ ]]; then
      return 0
    fi

    local now
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      return 1
    fi
    sleep 3
  done
}

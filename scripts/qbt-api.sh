#!/usr/bin/env bash
# shellcheck shell=bash
# Library: Helper functions for interacting with qBittorrent's Web API.
# shellcheck disable=SC1091

if [[ -n "${_ARR_QBT_API_SOURCED:-}" ]]; then
  return 0
fi
_ARR_QBT_API_SOURCED=1

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

: "${QBT_HOST:=127.0.0.1}"
: "${QBT_PORT:=${QBT_INT_PORT:-8080}}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${QBT_API_TIMEOUT:=10}"
: "${QBT_API_RETRY_COUNT:=3}"
: "${QBT_API_RETRY_DELAY:=2}"

_qbt_api_requires() {
  if ! command -v curl >/dev/null 2>&1; then
    die "curl is required to talk to qBittorrent"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    die "jq is required to parse qBittorrent responses"
  fi
}

_qbt_api_base_url() {
  printf 'http://%s:%s' "$QBT_HOST" "$QBT_PORT"
}

_qbt_api_cookie_file=""

_qbt_api_cleanup_cookie() {
  if [[ -n "${_qbt_api_cookie_file}" && -f "${_qbt_api_cookie_file}" ]]; then
    rm -f -- "${_qbt_api_cookie_file}" 2>/dev/null || true
  fi
  _qbt_api_cookie_file=""
}

_qbt_api_ensure_cookie() {
  _qbt_api_requires

  if [[ -n "${_qbt_api_cookie_file}" && -f "${_qbt_api_cookie_file}" ]]; then
    return 0
  fi

  local template="${TMPDIR:-/tmp}/qbt-api-cookie.XXXXXX"
  if declare -f arr_prepare_mktemp_template >/dev/null 2>&1; then
    template="$(arr_prepare_mktemp_template "$template")"
  fi
  _qbt_api_cookie_file="$(mktemp "$template" 2>/dev/null || true)"
  if [[ -z "${_qbt_api_cookie_file}" ]]; then
    die "Failed to create temporary cookie file for qBittorrent"
  fi

  local url
  url="$(_qbt_api_base_url)/api/v2/auth/login"

  local attempt=1
  local max_attempts="${QBT_API_RETRY_COUNT}"
  local retry_delay="${QBT_API_RETRY_DELAY}"

  while ((attempt <= max_attempts)); do
    if curl -fsS \
      --connect-timeout "${QBT_API_TIMEOUT}" \
      --max-time "${QBT_API_TIMEOUT}" \
      -c "${_qbt_api_cookie_file}" \
      --data-urlencode "username=${QBT_USER}" \
      --data-urlencode "password=${QBT_PASS}" \
      "${url}" >/dev/null 2>/dev/null; then

      if grep -q "SID" "${_qbt_api_cookie_file}" 2>/dev/null; then
        return 0
      fi
    fi

    if ((attempt < max_attempts)); then
      if declare -f arr_retry >/dev/null 2>&1; then
        arr_retry "qBittorrent authentication failed (attempt ${attempt}/${max_attempts}), retrying in ${retry_delay}s..."
      elif declare -f warn >/dev/null 2>&1; then
        warn "[RETRY] qBittorrent authentication failed (attempt ${attempt}/${max_attempts}), retrying in ${retry_delay}s..."
      fi
      sleep "${retry_delay}"
    fi
    ((attempt++))
  done

  if declare -f arr_error >/dev/null 2>&1; then
    arr_error "qBittorrent authentication failed after ${max_attempts} attempts"
    arr_action "Check QBT_USER and QBT_PASS credentials, and verify qBittorrent container is running"
  elif declare -f warn >/dev/null 2>&1; then
    warn "[ERROR] qBittorrent authentication failed after ${max_attempts} attempts"
  fi
  _qbt_api_cleanup_cookie
  return 1
}

qbt_api_login() {
  _qbt_api_ensure_cookie
}

_qbt_api_curl_json() {
  local path="$1"
  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local url
  url="$(_qbt_api_base_url)${path}"

  local response
  local http_code
  local attempt=1
  local max_attempts=2

  while ((attempt <= max_attempts)); do
    response=$(curl -fsS -w "\n%{http_code}" \
      --connect-timeout "${QBT_API_TIMEOUT}" \
      --max-time "${QBT_API_TIMEOUT}" \
      -b "${_qbt_api_cookie_file}" \
      "${url}" 2>/dev/null)

    http_code=$(printf '%s' "$response" | tail -n1)
    response=$(printf '%s' "$response" | sed '$d')

    if [[ "$http_code" == "200" || "$http_code" == "2"* ]]; then
      printf '%s' "$response"
      return 0
    fi

    # Session expired or auth error - try to re-authenticate
    if [[ "$http_code" == "401" || "$http_code" == "403" ]] && ((attempt < max_attempts)); then
      if declare -f arr_info >/dev/null 2>&1; then
        arr_info "qBittorrent session expired, re-authenticating..."
      elif declare -f warn >/dev/null 2>&1; then
        warn "[INFO] qBittorrent session expired, re-authenticating..."
      fi
      _qbt_api_cleanup_cookie
      if ! _qbt_api_ensure_cookie; then
        return 1
      fi
    else
      break
    fi
    ((attempt++))
  done

  return 1
}

qbt_api_healthcheck() {
  if _qbt_api_curl_json "/api/v2/app/version" >/dev/null; then
    return 0
  fi
  return 1
}

qbt_pause_all() {
  if ! _qbt_api_ensure_cookie; then
    return 1
  fi
  local url
  url="$(_qbt_api_base_url)/api/v2/torrents/pause"
  curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data "hashes=all" \
    "${url}" >/dev/null
}

qbt_resume_all() {
  if ! _qbt_api_ensure_cookie; then
    return 1
  fi
  local url
  url="$(_qbt_api_base_url)/api/v2/torrents/resume"
  curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data "hashes=all" \
    "${url}" >/dev/null
}

qbt_current_listen_port() {
  local body
  if ! body="$(_qbt_api_curl_json "/api/v2/app/preferences" 2>/dev/null)"; then
    printf '0'
    return 1
  fi

  local port
  port="$(printf '%s' "$body" | jq -r '.listen_port // 0' 2>/dev/null || printf '0')"
  if [[ "$port" =~ ^[0-9]+$ ]]; then
    printf '%s' "$port"
    return 0
  fi

  printf '0'
  return 1
}

qbt_set_listen_port() {
  local port="$1"
  local verify="${2:-true}"

  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  # Validate port is in valid range
  if ((port < 1024 || port > 65535)); then
    if declare -f warn >/dev/null 2>&1; then
      warn "Invalid port number: ${port} (must be 1024-65535)"
    fi
    return 1
  fi

  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  if ! payload="$(jq -cn --argjson port "$port" '{listen_port: $port, random_port: false}' 2>/dev/null)"; then
    printf 'Failed to generate qBittorrent port update JSON\n' >&2
    return 1
  fi
  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  if ! curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null; then
    return 1
  fi

  # Verify the port was actually set if requested
  if [[ "$verify" == "true" ]]; then
    # Retry logic with exponential backoff for port verification
    local delay="${QBT_VERIFICATION_DELAY:-1}"
    local max_attempts=3
    local attempt=1
    local actual_port
    while ((attempt <= max_attempts)); do
      sleep "$delay"
      actual_port="$(qbt_current_listen_port 2>/dev/null || printf '0')"
      if [[ "$actual_port" == "$port" ]]; then
        break
      fi
      ((attempt++))
      delay=$((delay * 2))
    done
    if [[ "$actual_port" != "$port" ]]; then
      if declare -f warn >/dev/null 2>&1; then
        warn "Port verification failed after $max_attempts attempts: requested ${port}, got ${actual_port}"
      fi
      return 1
    fi
  fi

  return 0
}

# Sets the qBittorrent WebUI password via the API.
# Must be called while logged in (after successful authentication).
# Returns 0 on success, 1 on failure.
qbt_set_password() {
  local new_password="$1"

  if [[ -z "$new_password" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Cannot set empty password"
    fi
    return 1
  fi

  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  if ! payload="$(jq -cn --arg pass "$new_password" '{web_ui_password: $pass}' 2>/dev/null)"; then
    printf 'Failed to generate qBittorrent password update JSON\n' >&2
    return 1
  fi

  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  if ! curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Failed to set qBittorrent password via API"
    fi
    return 1
  fi

  # Clear the cookie to force re-authentication with new password
  _qbt_api_cleanup_cookie

  return 0
}

# Sets the qBittorrent WebUI username via the API.
# Must be called while logged in (after successful authentication).
# Returns 0 on success, 1 on failure.
qbt_set_username() {
  local new_username="$1"

  if [[ -z "$new_username" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Cannot set empty username"
    fi
    return 1
  fi

  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  if ! payload="$(jq -cn --arg user "$new_username" '{web_ui_username: $user}' 2>/dev/null)"; then
    printf 'Failed to generate qBittorrent username update JSON\n' >&2
    return 1
  fi

  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  if ! curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Failed to set qBittorrent username via API"
    fi
    return 1
  fi

  # Clear the cookie to force re-authentication with new username
  _qbt_api_cleanup_cookie

  return 0
}

# Sets both qBittorrent WebUI username and password via the API.
# Must be called while logged in (after successful authentication).
# Returns 0 on success, 1 on failure.
qbt_set_credentials() {
  local new_username="$1"
  local new_password="$2"

  if [[ -z "$new_username" && -z "$new_password" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Cannot set empty credentials"
    fi
    return 1
  fi

  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  if [[ -n "$new_username" && -n "$new_password" ]]; then
    if ! payload="$(jq -cn --arg user "$new_username" --arg pass "$new_password" '{web_ui_username: $user, web_ui_password: $pass}' 2>/dev/null)"; then
      printf 'Failed to generate qBittorrent credentials update JSON\n' >&2
      return 1
    fi
  elif [[ -n "$new_username" ]]; then
    if ! payload="$(jq -cn --arg user "$new_username" '{web_ui_username: $user}' 2>/dev/null)"; then
      printf 'Failed to generate qBittorrent username update JSON\n' >&2
      return 1
    fi
  else
    if ! payload="$(jq -cn --arg pass "$new_password" '{web_ui_password: $pass}' 2>/dev/null)"; then
      printf 'Failed to generate qBittorrent password update JSON\n' >&2
      return 1
    fi
  fi

  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  if ! curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null; then
    if declare -f warn >/dev/null 2>&1; then
      warn "Failed to set qBittorrent credentials via API"
    fi
    return 1
  fi

  # Clear the cookie to force re-authentication with new credentials
  _qbt_api_cleanup_cookie

  return 0
}

# Gets the current list of additional trackers from qBittorrent preferences
# Returns the tracker list (newline-separated) on stdout, empty string if no trackers configured
# Returns 0 on success, 1 on failure (authentication or API error)
qbt_get_additional_trackers() {
  local body
  if ! body="$(_qbt_api_curl_json "/api/v2/app/preferences" 2>/dev/null)"; then
    return 1
  fi

  local trackers
  trackers="$(printf '%s' "$body" | jq -r '.add_trackers // ""' 2>/dev/null || printf '')"
  printf '%s' "$trackers"
  return 0
}

# Sets the additional trackers list in qBittorrent preferences
# Takes a newline-separated list of tracker URLs
# Returns 0 on success, 1 on failure (authentication or API error)
qbt_set_additional_trackers() {
  local trackers="$1"

  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  if ! payload="$(jq -cn --arg trackers "$trackers" '{add_trackers: $trackers}' 2>/dev/null)"; then
    if declare -f arr_error >/dev/null 2>&1; then
      arr_error "Failed to generate qBittorrent tracker update JSON"
    fi
    return 1
  fi

  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  if ! curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null; then
    return 1
  fi

  return 0
}

# Allow callers to clean up cookie files on exit.
qbt_api_cleanup() {
  _qbt_api_cleanup_cookie
}

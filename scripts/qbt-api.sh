#!/usr/bin/env bash
# shellcheck shell=bash
# Library: Helper functions for interacting with qBittorrent's Web API.

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
: "${QBT_PORT:=8080}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${QBT_API_TIMEOUT:=10}"

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

  if ! curl -fsS \
      --connect-timeout "${QBT_API_TIMEOUT}" \
      --max-time "${QBT_API_TIMEOUT}" \
      -c "${_qbt_api_cookie_file}" \
      --data-urlencode "username=${QBT_USER}" \
      --data-urlencode "password=${QBT_PASS}" \
      "${url}" >/dev/null; then
    _qbt_api_cleanup_cookie
    return 1
  fi

  if ! grep -q "SID" "${_qbt_api_cookie_file}" 2>/dev/null; then
    _qbt_api_cleanup_cookie
    return 1
  fi

  return 0
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

  curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    "${url}"
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
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if ! _qbt_api_ensure_cookie; then
    return 1
  fi

  local payload
  payload=$(jq -cn --argjson port "$port" '{listen_port: $port, random_port: false}' 2>/dev/null || printf '{}')
  local url
  url="$(_qbt_api_base_url)/api/v2/app/setPreferences"

  curl -fsS \
    --connect-timeout "${QBT_API_TIMEOUT}" \
    --max-time "${QBT_API_TIMEOUT}" \
    -b "${_qbt_api_cookie_file}" \
    --data-urlencode "json=${payload}" \
    "${url}" >/dev/null
}

# Allow callers to clean up cookie files on exit.
qbt_api_cleanup() {
  _qbt_api_cleanup_cookie
}

trap '_qbt_api_cleanup_cookie' EXIT

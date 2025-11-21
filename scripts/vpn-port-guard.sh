#!/usr/bin/env bash
# shellcheck shell=bash
# vpn-port-guard: minimal controller to align qBittorrent with Gluetun's forwarded port

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck disable=SC1091
if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

log() {
  printf '[vpn-port-guard] %s\n' "$*"
}

log_debug() {
  if bool_true "${VPN_PORT_GUARD_DEBUG}"; then
    printf '[vpn-port-guard] DEBUG: %s\n' "$*"
  fi
}

bool_true() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | on | ON) return 0 ;;
    *) return 1 ;;
  esac
}

# Environment defaults with backward compatibility
# Parse GLUETUN_CONTROL_URL if provided, otherwise use individual components
if [[ -n "${GLUETUN_CONTROL_URL:-}" ]]; then
  # Validate URL format before extraction
  if [[ ! "${GLUETUN_CONTROL_URL}" =~ ^https?:// ]]; then
    log "Warning: GLUETUN_CONTROL_URL does not start with http:// or https://, using as-is: ${GLUETUN_CONTROL_URL}"
  fi
  
  # Extract host and port from URL (e.g., http://127.0.0.1:8000)
  if [[ -z "${GLUETUN_API_HOST:-}" ]]; then
    GLUETUN_API_HOST="$(printf '%s' "${GLUETUN_CONTROL_URL}" | sed -E 's|^https?://([^:/]+).*|\1|')"
  fi
  if [[ -z "${GLUETUN_CONTROL_PORT:-}" ]]; then
    # Extract port only if URL contains :port pattern, otherwise leave unset to use default
    _extracted_port="$(printf '%s' "${GLUETUN_CONTROL_URL}" | sed -nE 's|^https?://[^:]+:([0-9]+).*|\1|p')"
    if [[ -n "$_extracted_port" ]]; then
      GLUETUN_CONTROL_PORT="$_extracted_port"
    fi
    unset _extracted_port
  fi
fi
: "${GLUETUN_CONTROL_PORT:=8000}"
: "${GLUETUN_API_HOST:=127.0.0.1}"
: "${GLUETUN_API_KEY:=}"
: "${FORWARDED_PORT_FILE:=/tmp/gluetun/forwarded_port}"

# Build QBT_API_BASE from components if not already set
if [[ -n "${QBT_HOST:-}" && -n "${QBT_PORT:-}" ]]; then
  : "${QBT_API_BASE:=http://${QBT_HOST}:${QBT_PORT}}"
fi
: "${QBT_API_BASE:=http://127.0.0.1:8080}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${COOKIE_JAR:=/tmp/vpn-port-guard-qbt.cookie}"
: "${STATUS_FILE:=${ARR_DOCKER_DIR:-/var/lib/arr}/gluetun/state/port-guard-status.json}"

# Support both CONTROLLER_POLL_INTERVAL (new) and legacy POLL_INTERVAL
: "${CONTROLLER_POLL_INTERVAL:=${POLL_INTERVAL:-10}}"
: "${POLL_INTERVAL:=${CONTROLLER_POLL_INTERVAL}}"
: "${CONTROLLER_REQUIRE_PF:=false}"

# Optional debug logging
: "${VPN_PORT_GUARD_DEBUG:=false}"

STATUS_DIR="$(dirname "${STATUS_FILE}")"
mkdir -p -- "${STATUS_DIR}" || {
  log "Unable to create status directory ${STATUS_DIR}"
  exit 1
}
COOKIE_DIR="$(dirname "${COOKIE_JAR}")"
mkdir -p -- "${COOKIE_DIR}" || true

_qbt_state="unknown"
_last_forwarded_port=0

json_escape() {
  local raw="$1"
  raw=${raw//\\/\\\\}
  raw=${raw//"/\\"}
  raw=${raw//$'\n'/\\n}
  printf '%s' "$raw"
}

write_status() {
  local vpn_status="$1"
  local forwarded_port="$2"
  local pf_enabled_raw="$3"
  local qbt_status="$4"
  local last_error="$5"
  local now
  now="$(date +%s 2>/dev/null || printf '0')"

  local forwarding_state
  if [[ "$forwarded_port" =~ ^[1-9][0-9]*$ ]]; then
    forwarding_state="active"
  else
    forwarding_state="unavailable"
    forwarded_port=0
  fi

  local controller_mode="preferred"
  local pf_enabled="false"
  if bool_true "$pf_enabled_raw"; then
    controller_mode="strict"
    pf_enabled="true"
  fi

  local tmp
  if ! tmp="$(mktemp "${STATUS_DIR}/port-guard-status.XXXXXX" 2>/dev/null)"; then
    log "Unable to create temporary status file"
    return 1
  fi

  local escaped_error escaped_vpn escaped_qbt
  escaped_error="$(json_escape "${last_error}")"
  escaped_vpn="$(json_escape "${vpn_status}")"
  escaped_qbt="$(json_escape "${qbt_status}")"

  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg vpn_status "$vpn_status" \
      --arg forwarding_state "$forwarding_state" \
      --arg controller_mode "$controller_mode" \
      --arg qbt_status "$qbt_status" \
      --arg last_error "$last_error" \
      --argjson forwarded_port "$forwarded_port" \
      --argjson pf_enabled "$pf_enabled" \
      --argjson last_update "$now" \
      '{
        vpn_status: $vpn_status,
        forwarded_port: $forwarded_port,
        pf_enabled: $pf_enabled,
        forwarding_state: $forwarding_state,
        controller_mode: $controller_mode,
        qbt_status: $qbt_status,
        last_update: $last_update,
        last_update_epoch: $last_update,
        last_error: $last_error
      }' >"${tmp}" || {
        log "Failed to render status JSON"
        rm -f -- "$tmp"
        return 1
      }
  else
    cat >"${tmp}" <<EOF_JSON
{
  "vpn_status": "${escaped_vpn}",
  "forwarded_port": ${forwarded_port},
  "pf_enabled": ${pf_enabled},
  "forwarding_state": "${forwarding_state}",
  "controller_mode": "${controller_mode}",
  "qbt_status": "${escaped_qbt}",
  "last_update": ${now},
  "last_update_epoch": ${now},
  "last_error": "${escaped_error}"
}
EOF_JSON
  fi

  mv -f -- "$tmp" "$STATUS_FILE"
}

parse_port_payload() {
  local payload_file="$1"
  local port=""
  if command -v jq >/dev/null 2>&1; then
    port="$(jq -r '.port // .data.port // 0' "$payload_file" 2>/dev/null || printf '0')"
  else
    port="$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "$payload_file" | head -n1 | tr -d '\n')"
  fi
  if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s' "$port"
  else
    printf '0'
  fi
}

fetch_forwarded_port() {
  local api_url="http://${GLUETUN_API_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded"
  local tmp http_code port
  tmp="$(mktemp "${STATUS_DIR}/gluetun-port.XXXXXX" 2>/dev/null || printf '')"
  if [[ -n "$tmp" ]]; then
    local curl_args=(--silent --show-error --fail --connect-timeout 5 --max-time 10 -w '%{http_code}' -o "$tmp")
    if [[ -n "${GLUETUN_API_KEY}" ]]; then
      curl_args+=(-H "X-API-Key: ${GLUETUN_API_KEY}")
    fi
    http_code="$(curl "${curl_args[@]}" "$api_url" 2>/dev/null || printf '')"
    if [[ "$http_code" == "200" ]]; then
      port="$(parse_port_payload "$tmp")"
      rm -f -- "$tmp"
      log_debug "Fetched port from Gluetun API: ${port}"
      printf '%s' "$port"
      return 0
    else
      log_debug "Gluetun API returned HTTP ${http_code:-'connection failed'}, trying fallback"
    fi
    rm -f -- "$tmp"
  fi

  log_debug "Attempting to read forwarded port from file: ${FORWARDED_PORT_FILE}"
  if [[ -f "$FORWARDED_PORT_FILE" ]]; then
    port="$(tr -cd '0-9' <"$FORWARDED_PORT_FILE" | tr -d '\n')"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      log_debug "Read port from file: ${port}"
      printf '%s' "$port"
      return 0
    fi
  fi
  log_debug "No valid forwarded port available from API or file"
  printf '0'
  return 1
}

qbt_login() {
  local code
  log_debug "Attempting qBittorrent login to ${QBT_API_BASE}"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
    --connect-timeout 5 --max-time 10 \
    --data-urlencode "username=${QBT_USER}" \
    --data-urlencode "password=${QBT_PASS}" \
    "${QBT_API_BASE}/api/v2/auth/login" 2>/dev/null || printf '')"
  if [[ "$code" == "200" ]] && grep -q 'SID' "$COOKIE_JAR" 2>/dev/null; then
    log_debug "qBittorrent login successful"
    return 0
  fi
  log_debug "qBittorrent login failed with HTTP ${code:-'connection error'}"
  rm -f -- "$COOKIE_JAR" 2>/dev/null || true
  return 1
}

qbt_post() {
  local path="$1"; shift
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" --connect-timeout 5 --max-time 10 "$@" "${QBT_API_BASE}${path}" 2>/dev/null || printf '')"
  if [[ "$code" == "401" ]]; then
    if qbt_login; then
      code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" --connect-timeout 5 --max-time 10 "$@" "${QBT_API_BASE}${path}" 2>/dev/null || printf '')"
    fi
  fi
  [[ "$code" == "200" ]]
}

apply_qbt_port() {
  local port="$1"
  local payload
  payload="$(printf '{"listen_port":%s,"random_port":false}' "$port")"
  log_debug "Updating qBittorrent listen port to ${port}"
  if qbt_post "/api/v2/app/setPreferences" --data-urlencode "json=${payload}"; then
    _qbt_state="active"
    _last_forwarded_port="$port"
    log_debug "qBittorrent listen port updated successfully"
    return 0
  fi
  _qbt_state="error"
  log_debug "Failed to update qBittorrent listen port"
  return 1
}

pause_qbt() {
  if [[ "${_qbt_state}" == "paused" ]]; then
    return 0
  fi
  if qbt_post "/api/v2/torrents/pause" --data "hashes=all"; then
    _qbt_state="paused"
    return 0
  fi
  _qbt_state="error"
  return 1
}

resume_qbt() {
  if [[ "${_qbt_state}" == "active" ]]; then
    return 0
  fi
  if qbt_post "/api/v2/torrents/resume" --data "hashes=all"; then
    _qbt_state="active"
    return 0
  fi
  _qbt_state="error"
  return 1
}

initialise() {
  log_debug "Initializing with:"
  log_debug "  Gluetun API: http://${GLUETUN_API_HOST}:${GLUETUN_CONTROL_PORT}"
  log_debug "  qBittorrent API: ${QBT_API_BASE}"
  log_debug "  Poll interval: ${POLL_INTERVAL}s"
  log_debug "  Require port forwarding: ${CONTROLLER_REQUIRE_PF}"
  log_debug "  Status file: ${STATUS_FILE}"
  log_debug "  Forwarded port file: ${FORWARDED_PORT_FILE}"
  
  write_status "init" 0 "$CONTROLLER_REQUIRE_PF" "unknown" "initializing" || true
  
  if qbt_login; then
    log_debug "Initial qBittorrent login successful"
  else
    log "Warning: Initial qBittorrent login failed, will retry on first poll"
  fi
}

main_loop() {
  local last_error
  while true; do
    sleep "${POLL_INTERVAL}"
    last_error=""
    local vpn_status="down"
    local port
    
    log_debug "Starting poll cycle"
    port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
    log_debug "Fetched port: ${port}"
    
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      vpn_status="running"
      log_debug "VPN status: running (port ${port})"
    elif [[ -s "$FORWARDED_PORT_FILE" ]]; then
      vpn_status="running"
      log_debug "VPN status: running (port file exists but no valid port)"
    else
      vpn_status="down"
      log_debug "VPN status: down"
    fi

    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      if [[ "$port" != "${_last_forwarded_port}" ]]; then
        log "Applying forwarded port ${port} to qBittorrent"
        if ! apply_qbt_port "$port"; then
          last_error="failed to set qBittorrent listen port"
          log_debug "Error: ${last_error}"
        else
          log_debug "Successfully applied port ${port}"
        fi
      else
        log_debug "Port unchanged (${port}), skipping update"
      fi
      if bool_true "$CONTROLLER_REQUIRE_PF"; then
        log_debug "Strict mode: ensuring torrents resumed"
        resume_qbt || last_error="failed to resume torrents"
      else
        _qbt_state="active"
      fi
    else
      log_debug "No valid forwarded port available"
      if bool_true "$CONTROLLER_REQUIRE_PF"; then
        log "Strict mode: pausing torrents (no forwarded port)"
        if ! pause_qbt; then
          last_error="failed to pause torrents"
          log_debug "Error: ${last_error}"
        fi
      fi
    fi

    write_status "$vpn_status" "${port:-0}" "$CONTROLLER_REQUIRE_PF" "${_qbt_state:-unknown}" "${last_error}" || true
    log_debug "Poll cycle complete"
  done
}

log "Starting vpn-port-guard (poll=${POLL_INTERVAL}s, require_pf=${CONTROLLER_REQUIRE_PF})"
initialise
main_loop

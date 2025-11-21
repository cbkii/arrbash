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

# Use consolidated API libraries
if [[ -f "${REPO_ROOT}/scripts/gluetun-api.sh" ]]; then
  # shellcheck source=scripts/gluetun-api.sh
  . "${REPO_ROOT}/scripts/gluetun-api.sh"
fi

if [[ -f "${REPO_ROOT}/scripts/qbt-api.sh" ]]; then
  # shellcheck source=scripts/qbt-api.sh
  . "${REPO_ROOT}/scripts/qbt-api.sh"
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

# Environment defaults - now using consolidated API libraries
# Note: GLUETUN_CONTROL_URL, GLUETUN_API_KEY set by gluetun-api.sh
# Note: QBT_HOST, QBT_PORT, QBT_USER, QBT_PASS set by qbt-api.sh
: "${FORWARDED_PORT_FILE:=/tmp/gluetun/forwarded_port}"
: "${STATUS_FILE:=${ARR_DOCKER_DIR:-/var/lib/arr}/gluetun/state/port-guard-status.json}"

# Controller polling configuration
: "${CONTROLLER_POLL_INTERVAL:=10}"
: "${CONTROLLER_REQUIRE_PF:=false}"

# Optional debug logging
: "${VPN_PORT_GUARD_DEBUG:=false}"

STATUS_DIR="$(dirname "${STATUS_FILE}")"
mkdir -p -- "${STATUS_DIR}" || {
  log "Unable to create status directory ${STATUS_DIR}"
  exit 1
}

_qbt_state="unknown"
_last_forwarded_port=0

json_escape() {
  local raw="$1"
  raw=${raw//\\/\\\\}
  raw=${raw//"/\\\"}
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
    port="$(sed -nE 's/.*"port"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$payload_file" | head -n1 | tr -d '\n')"
  fi
  if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s' "$port"
  else
    printf '0'
  fi
}

fetch_forwarded_port() {
  # Use consolidated gluetun_api_forwarded_port from gluetun-api.sh
  local port
  if declare -f gluetun_api_forwarded_port >/dev/null 2>&1; then
    port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      log_debug "Fetched port from Gluetun API: ${port}"
      printf '%s' "$port"
      return 0
    fi
  fi

  # Fallback to file-based method
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
  # Use consolidated qbt_api_login from qbt-api.sh
  log_debug "Attempting qBittorrent login using consolidated API"
  if qbt_api_login 2>/dev/null; then
    log_debug "qBittorrent login successful"
    return 0
  fi
  log_debug "qBittorrent login failed"
  return 1
}

apply_qbt_port() {
  local port="$1"
  log_debug "Updating qBittorrent listen port to ${port}"
  
  # Use consolidated qbt_set_listen_port from qbt-api.sh
  if declare -f qbt_set_listen_port >/dev/null 2>&1; then
    if qbt_set_listen_port "$port" 2>/dev/null; then
      _qbt_state="active"
      _last_forwarded_port="$port"
      log_debug "qBittorrent listen port updated successfully"
      return 0
    fi
  fi
  
  _qbt_state="error"
  log_debug "Failed to update qBittorrent listen port"
  return 1
}

pause_qbt() {
  if [[ "${_qbt_state}" == "paused" ]]; then
    return 0
  fi
  
  # Use consolidated qbt_pause_all from qbt-api.sh
  if declare -f qbt_pause_all >/dev/null 2>&1; then
    if qbt_pause_all 2>/dev/null; then
      _qbt_state="paused"
      return 0
    fi
  fi
  
  _qbt_state="error"
  return 1
}

resume_qbt() {
  if [[ "${_qbt_state}" == "active" ]]; then
    return 0
  fi
  
  # Use consolidated qbt_resume_all from qbt-api.sh
  if declare -f qbt_resume_all >/dev/null 2>&1; then
    if qbt_resume_all 2>/dev/null; then
      _qbt_state="active"
      return 0
    fi
  fi
  
  _qbt_state="error"
  return 1
}

initialise() {
  log_debug "Initializing with:"
  log_debug "  Gluetun API: ${GLUETUN_CONTROL_URL:-http://127.0.0.1:8000}"
  log_debug "  qBittorrent API: http://${QBT_HOST:-127.0.0.1}:${QBT_PORT:-8082}"
  log_debug "  Poll interval: ${CONTROLLER_POLL_INTERVAL}s"
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
        resume_qbt || true  # best effort even in preferred mode
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
    sleep "${POLL_INTERVAL}"
  done
}

log "Starting vpn-port-guard (poll=${POLL_INTERVAL}s, require_pf=${CONTROLLER_REQUIRE_PF})"
initialise
main_loop

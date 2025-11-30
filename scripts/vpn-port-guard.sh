#!/usr/bin/env bash
# shellcheck shell=bash
# vpn-port-guard: Controller to synchronize qBittorrent listen port with Gluetun's forwarded port
#
# Optimized for Gluetun v3.40+ with ProtonVPN port forwarding
#
# Key features:
# - Uses Gluetun's /v1/portforward API (recommended for v3.40+)
# - File-based fallback is deprecated but supported for compatibility
# - Writes status to port-guard-status.json for stack health monitoring
# - Supports both strict (pause on no port) and preferred (best effort) modes

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

# --- Logging ---
log() {
  printf '[vpn-port-guard] %s\n' "$*"
}

log_debug() {
  if bool_true "${VPN_PORT_GUARD_DEBUG:-false}"; then
    printf '[vpn-port-guard] DEBUG: %s\n' "$*"
  fi
}

log_error() {
  printf '[vpn-port-guard] ERROR: %s\n' "$*" >&2
}

bool_true() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | on | ON) return 0 ;;
    *) return 1 ;;
  esac
}

# --- Configuration ---
# Gluetun API settings (inherited from gluetun-api.sh)
: "${GLUETUN_CONTROL_URL:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"

# qBittorrent API settings (inherited from qbt-api.sh)
: "${QBT_HOST:=127.0.0.1}"
: "${QBT_PORT:=8082}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"

# Status file location (deprecated file-based method for fallback only)
: "${FORWARDED_PORT_FILE:=/tmp/gluetun/forwarded_port}"
: "${STATUS_FILE:=/gluetun_state/port-guard-status.json}"

# Controller behavior
: "${CONTROLLER_POLL_INTERVAL:=15}"
: "${CONTROLLER_REQUIRE_PF:=false}"
: "${CONTROLLER_STARTUP_DELAY:=5}"
: "${CONTROLLER_MAX_API_RETRIES:=3}"

# Validate numeric configuration values
if ! [[ "${CONTROLLER_POLL_INTERVAL}" =~ ^[0-9]+$ ]]; then
  log "Warning: Invalid CONTROLLER_POLL_INTERVAL='${CONTROLLER_POLL_INTERVAL}', using default 15"
  CONTROLLER_POLL_INTERVAL=15
fi
if ! [[ "${CONTROLLER_STARTUP_DELAY}" =~ ^[0-9]+$ ]]; then
  log "Warning: Invalid CONTROLLER_STARTUP_DELAY='${CONTROLLER_STARTUP_DELAY}', using default 5"
  CONTROLLER_STARTUP_DELAY=5
fi
if ! [[ "${CONTROLLER_MAX_API_RETRIES}" =~ ^[0-9]+$ ]]; then
  log "Warning: Invalid CONTROLLER_MAX_API_RETRIES='${CONTROLLER_MAX_API_RETRIES}', using default 3"
  CONTROLLER_MAX_API_RETRIES=3
fi

# Debug mode
: "${VPN_PORT_GUARD_DEBUG:=false}"

# Enable debug for gluetun-api.sh if our debug is enabled
if bool_true "${VPN_PORT_GUARD_DEBUG}"; then
  export GLUETUN_API_DEBUG=true
fi

# --- Status directory setup ---
STATUS_DIR="$(dirname "${STATUS_FILE}")"
if ! mkdir -p -- "${STATUS_DIR}" 2>/dev/null; then
  log_error "Unable to create status directory ${STATUS_DIR}"
  exit 1
fi

if ! arr_repair_port_guard_status_file "$STATUS_FILE"; then
  log_error "Existing ${STATUS_FILE} is not writable; fix permissions before continuing"
  exit 1
fi

# --- Graceful shutdown handler ---
_on_exit() {
  # Best-effort write; ignore errors during shutdown
  write_status "stopped" 0 "$CONTROLLER_REQUIRE_PF" "${_qbt_state:-unknown}" "controller exited" || true
}
trap _on_exit EXIT TERM INT

# --- State tracking ---
_qbt_state="unknown"
_last_forwarded_port=0
_consecutive_api_failures=0
_last_successful_api_call=0

# --- JSON helpers ---
json_escape() {
  local raw="$1"
  raw=${raw//\\/\\\\}
  raw=${raw//\"/\\\"}
  raw=${raw//$'\n'/\\n}
  raw=${raw//$'\r'/\\r}
  raw=${raw//$'\t'/\\t}
  raw=${raw//$'\b'/\\b}
  raw=${raw//$'\f'/\\f}
  printf '%s' "$raw"
}

# --- Status file management ---
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
    log_error "Unable to create temporary status file"
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
      --argjson api_failures "${_consecutive_api_failures}" \
      '{
        vpn_status: $vpn_status,
        forwarded_port: $forwarded_port,
        pf_enabled: $pf_enabled,
        forwarding_state: $forwarding_state,
        controller_mode: $controller_mode,
        qbt_status: $qbt_status,
        last_update: $last_update,
        last_update_epoch: $last_update,
        last_error: $last_error,
        api_failures: $api_failures
      }' >"${tmp}" || {
        log_error "Failed to render status JSON"
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
  "last_error": "${escaped_error}",
  "api_failures": ${_consecutive_api_failures}
}
EOF_JSON
  fi

  if mv -f -- "$tmp" "$STATUS_FILE" 2>/dev/null; then
    log_debug "Status written to ${STATUS_FILE}"
    return 0
  else
    log_error "Failed to move status file to ${STATUS_FILE}"
    rm -f -- "$tmp"
    return 1
  fi
}

# --- Port fetching ---
# Fetches the forwarded port from Gluetun API (primary) or status file (deprecated fallback)
fetch_forwarded_port() {
  local port=""
  
  # PRIMARY: Use Gluetun's /v1/portforward API (recommended for v3.40+)
  if declare -f gluetun_api_forwarded_port >/dev/null 2>&1; then
    log_debug "Querying Gluetun API for forwarded port..."
    port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')"
    
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      _consecutive_api_failures=0
      _last_successful_api_call="$(date +%s)"
      log_debug "Got port ${port} from Gluetun API"
      printf '%s' "$port"
      return 0
    fi
    
    # Track API failures
    ((_consecutive_api_failures++)) || true
    if ((_consecutive_api_failures >= CONTROLLER_MAX_API_RETRIES)); then
      log_error "Gluetun API failed ${_consecutive_api_failures} consecutive times"
    else
      log_debug "Gluetun API returned no valid port (attempt ${_consecutive_api_failures})"
    fi
  else
    log_debug "gluetun_api_forwarded_port function not available, using fallback"
  fi

  # FALLBACK: Read from deprecated status file (VPN_PORT_FORWARDING_STATUS_FILE)
  # Note: This method is deprecated in Gluetun v3.40+ and will be removed in v4.0
  if [[ -f "$FORWARDED_PORT_FILE" ]]; then
    log_debug "Trying deprecated file-based fallback: ${FORWARDED_PORT_FILE}"
    port="$(tr -cd '0-9' <"$FORWARDED_PORT_FILE" 2>/dev/null | head -c 5)"
    # Strip leading zeros for proper arithmetic comparison
    port="${port#"${port%%[!0]*}"}"
    if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535)); then
      log_debug "Got port ${port} from status file (deprecated method)"
      printf '%s' "$port"
      return 0
    fi
    log_debug "Status file exists but contains no valid port"
  fi
  
  log_debug "No valid forwarded port available"
  printf '0'
  return 1
}

# --- qBittorrent API wrappers ---
qbt_login() {
  log_debug "Attempting qBittorrent login..."
  if declare -f qbt_api_login >/dev/null 2>&1; then
    if qbt_api_login 2>/dev/null; then
      log_debug "qBittorrent login successful"
      return 0
    fi
  fi
  log_debug "qBittorrent login failed"
  return 1
}

apply_qbt_port() {
  local port="$1"
  log_debug "Updating qBittorrent listen port to ${port}"
  
  if declare -f qbt_set_listen_port >/dev/null 2>&1; then
    if qbt_set_listen_port "$port" "true" 2>/dev/null; then
      _qbt_state="active"
      _last_forwarded_port="$port"
      log "Successfully synced qBittorrent listen port to ${port}"
      return 0
    fi
    log_error "Failed to update qBittorrent listen port to ${port}"
  else
    log_error "qbt_set_listen_port function not available"
  fi
  
  _qbt_state="error"
  return 1
}

pause_qbt() {
  if [[ "${_qbt_state}" == "paused" ]]; then
    return 0
  fi
  
  if declare -f qbt_pause_all >/dev/null 2>&1; then
    if qbt_pause_all 2>/dev/null; then
      _qbt_state="paused"
      log "Paused all torrents (no forwarded port)"
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
  
  if declare -f qbt_resume_all >/dev/null 2>&1; then
    if qbt_resume_all 2>/dev/null; then
      _qbt_state="active"
      log_debug "Resumed all torrents"
      return 0
    fi
  fi
  
  _qbt_state="error"
  return 1
}

# --- Initialization ---
initialise() {
  log "Initializing vpn-port-guard..."
  log_debug "Configuration:"
  log_debug "  Gluetun API URL: ${GLUETUN_CONTROL_URL}"
  log_debug "  Gluetun API Key: ${GLUETUN_API_KEY:+[configured]}"
  log_debug "  qBittorrent: http://${QBT_HOST}:${QBT_PORT}"
  log_debug "  Poll interval: ${CONTROLLER_POLL_INTERVAL}s"
  log_debug "  Require port forwarding: ${CONTROLLER_REQUIRE_PF}"
  log_debug "  Status file: ${STATUS_FILE}"
  
  # Check for API key (required for Gluetun v3.40+)
  if [[ -z "${GLUETUN_API_KEY}" ]]; then
    log "Warning: GLUETUN_API_KEY is not set. Gluetun v3.40+ requires API key authentication."
  fi
  
  # Write initial status immediately so arr_wait_for_port_guard_ready() sees us running
  if ! write_status "starting" 0 "$CONTROLLER_REQUIRE_PF" "initializing" ""; then
    log_error "Failed to write initial status file"
  else
    log "Published initial status to ${STATUS_FILE}"
  fi
  
  # Give Gluetun time to negotiate port forwarding after VPN connects
  if ((CONTROLLER_STARTUP_DELAY > 0)); then
    log_debug "Waiting ${CONTROLLER_STARTUP_DELAY}s for Gluetun to negotiate port forwarding..."
    sleep "${CONTROLLER_STARTUP_DELAY}"
  fi
  
  # Try to get an initial port reading
  local initial_port="0"
  initial_port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
  if [[ "$initial_port" =~ ^[1-9][0-9]*$ ]]; then
    log "Initial forwarded port detected: ${initial_port}"
    write_status "running" "$initial_port" "$CONTROLLER_REQUIRE_PF" "initializing" "" || true
  else
    log "No forwarded port yet (VPN may still be negotiating)"
  fi
  
  # Attempt qBittorrent login
  local qbt_login_attempts=0
  local qbt_login_max=3
  while ((qbt_login_attempts < qbt_login_max)); do
    if qbt_login; then
      log "Connected to qBittorrent API"
      break
    fi
    ((qbt_login_attempts++))
    if ((qbt_login_attempts < qbt_login_max)); then
      log_debug "qBittorrent login attempt ${qbt_login_attempts}/${qbt_login_max} failed, retrying..."
      sleep 2
    else
      log "Warning: Could not connect to qBittorrent API after ${qbt_login_max} attempts"
    fi
  done
}

# --- Main loop ---
main_loop() {
  local last_error=""
  local poll_count=0
  
  while true; do
    ((poll_count++)) || true
    last_error=""
    local vpn_status="unknown"
    local port="0"
    
    log_debug "=== Poll cycle #${poll_count} ==="
    
    # Fetch forwarded port from Gluetun API
    port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
    
    # Determine VPN status based on port availability
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      vpn_status="running"
      log_debug "VPN running with forwarded port ${port}"
    else
      # Try to get VPN status from API
      if declare -f gluetun_api_status >/dev/null 2>&1; then
        vpn_status="$(gluetun_api_status 2>/dev/null || printf 'unknown')"
      fi
      log_debug "VPN status: ${vpn_status} (no forwarded port)"
    fi

    # Process port forwarding
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      # Valid port - update qBittorrent if changed
      if [[ "$port" != "${_last_forwarded_port}" ]]; then
        log "Port changed: ${_last_forwarded_port} -> ${port}"
        if ! apply_qbt_port "$port"; then
          last_error="failed to set qBittorrent listen port"
        fi
      fi
      
      # Ensure torrents are running
      if ! resume_qbt; then
        if bool_true "$CONTROLLER_REQUIRE_PF"; then
          last_error="${last_error:+$last_error; }failed to resume torrents"
        fi
      fi
    else
      # No valid port
      if bool_true "$CONTROLLER_REQUIRE_PF"; then
        log_debug "Strict mode: no forwarded port, pausing torrents"
        if ! pause_qbt; then
          last_error="failed to pause torrents"
        fi
      else
        log_debug "Preferred mode: no forwarded port but not pausing"
      fi
    fi

    # Update status file
    write_status "$vpn_status" "${port:-0}" "$CONTROLLER_REQUIRE_PF" "${_qbt_state:-unknown}" "${last_error}" || true
    
    log_debug "Poll cycle #${poll_count} complete, sleeping ${CONTROLLER_POLL_INTERVAL}s"
    sleep "${CONTROLLER_POLL_INTERVAL}"
  done
}

# --- Entry point ---
log "Starting vpn-port-guard v2.0 (optimized for Gluetun v3.40+)"
log "Poll interval: ${CONTROLLER_POLL_INTERVAL}s, Strict mode: ${CONTROLLER_REQUIRE_PF}"
initialise
main_loop

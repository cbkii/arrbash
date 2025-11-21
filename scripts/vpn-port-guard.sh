#!/usr/bin/env bash
# shellcheck disable=SC1091
# vpn-port-guard controller
# Watches Gluetun's control API and keeps qBittorrent aligned with ProtonVPN forwarding.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=../stack-common.sh
. "${REPO_ROOT}/scripts/stack-common.sh"

if ! declare -f msg >/dev/null 2>&1; then
  msg() { printf '%s\n' "$*"; }
fi

controller_log() {
  msg "[vpn-port-guard] $*"
}
# shellcheck source=gluetun-api.sh
. "${SCRIPT_DIR}/gluetun-api.sh"
# shellcheck source=qbt-api.sh
. "${SCRIPT_DIR}/qbt-api.sh"

if ! command -v jq >/dev/null 2>&1; then
  printf '[vpn-port-guard] jq is required but not installed\n' >&2
  exit 1
fi

: "${CONTROLLER_POLL_INTERVAL:=${VPN_PORT_GUARD_POLL_SECONDS:-15}}"
: "${CONTROLLER_STATUS_FILE:=/gluetun_state/port-guard-status.json}"
: "${CONTROLLER_TRIGGER_FILE:=/gluetun_state/port-guard.trigger}"
: "${CONTROLLER_TMP_DIR:=/tmp/vpn-port-guard}"
: "${CONTROLLER_EVENTS_FILE:=/gluetun_state/port-guard-events.log}"

# Consolidate multiple config variables into a single canonical one
# Priority: CONTROLLER_REQUIRE_PF > CONTROLLER_REQUIRE_PORT_FORWARDING > VPN_PORT_GUARD_REQUIRE_FORWARDING
: "${CONTROLLER_REQUIRE_PF:=${CONTROLLER_REQUIRE_PORT_FORWARDING:-${VPN_PORT_GUARD_REQUIRE_FORWARDING:-false}}}"

_controller_last_port=0
_controller_consecutive_failures=0
_controller_max_consecutive_failures=5

controller_bool() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | on | ON)
      printf 'true'
      ;;
    *)
      printf 'false'
      ;;
  esac
}

CONTROLLER_REQUIRE_STRICT="$(controller_bool "${CONTROLLER_REQUIRE_PF}")"
if [[ "${CONTROLLER_REQUIRE_STRICT}" == "true" ]]; then
  CONTROLLER_MODE_STRING="strict"
else
  CONTROLLER_MODE_STRING="preferred"
fi

controller_ensure_dir() {
  local dir="$1"
  if command -v install >/dev/null 2>&1; then
    install -d -m 0755 -- "$dir" || return 1
  else
    mkdir -p -- "$dir" || return 1
    chmod 0755 -- "$dir" || return 1
  fi
  return 0
}

if ! controller_ensure_dir "${CONTROLLER_TMP_DIR}"; then
  controller_log "Failed to prepare controller tmp dir ${CONTROLLER_TMP_DIR}"
  exit 1
fi

controller_state_dir="$(dirname "${CONTROLLER_STATUS_FILE}")"
if ! controller_ensure_dir "${controller_state_dir}"; then
  controller_log "Failed to prepare controller state dir ${controller_state_dir}"
  exit 1
fi

controller_events_dir="$(dirname "${CONTROLLER_EVENTS_FILE}")"
if ! controller_ensure_dir "${controller_events_dir}"; then
  controller_log "Failed to prepare controller events dir ${controller_events_dir}"
  exit 1
fi

controller_log_event() {
  local message="$1"
  local timestamp
  timestamp="$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || printf '0000-00-00T00:00:00Z')"
  { printf '[%s] %s\n' "${timestamp}" "$message"; } >>"${CONTROLLER_EVENTS_FILE}" 2>/dev/null || true
}

controller_record_vpn_state() {
  local state="$1"
  if [[ "${_controller_vpn_state:-}" != "$state" ]]; then
    _controller_vpn_state="$state"
    controller_log_event "vpn:${state}"
  fi
}

controller_write_state() {
  local vpn_status="${1:-unknown}"
  local port_raw="${2:-0}"
  local forwarding_state="${3:-unavailable}"
  local qbt_status="${4:-unknown}"
  local pf_arg="${5:-${CONTROLLER_REQUIRE_STRICT}}"
  local last_error="${6:-}"

  local port="0"
  if [[ -n "${port_raw}" && "${port_raw}" =~ ^[0-9]+$ ]]; then
    port="${port_raw}"
  fi

  local last_port="0"

  case "${forwarding_state}" in
    active | unavailable | error | initializing | unreachable) ;;
    *) forwarding_state="unavailable" ;;
  esac

  case "${qbt_status}" in
    active | paused | error) ;;
    *) qbt_status="error" ;;
  esac

  local pf_enabled
  pf_enabled="$(controller_bool "${pf_arg}")"

  local epoch
  epoch="$(date +%s 2>/dev/null || printf '0')"

  if [[ "${_controller_last_port:-0}" =~ ^[0-9]+$ ]] && [[ "${_controller_last_port:-0}" -gt 0 ]]; then
    last_port="${_controller_last_port}"
  else
    last_port="0"
  fi

  if [[ "$port" -gt 0 ]]; then
    _controller_last_port="$port"
    last_port="$port"
  fi

  local tmp
  local tmp_template="${controller_state_dir}/state.XXXXXX"
  if ! tmp="$(mktemp "${tmp_template}" 2>/dev/null)"; then
    controller_log "Unable to create temporary state file"
    return 1
  fi

  trap 'rm -f "${tmp}"' RETURN

  local json_content
  if ! json_content="$(jq -n \
    --arg vpn_status "${vpn_status}" \
    --arg forwarding_state "${forwarding_state}" \
    --arg controller_mode "${CONTROLLER_MODE_STRING}" \
    --arg qbt_status "${qbt_status}" \
    --argjson forwarded_port "${port}" \
    --argjson pf_enabled "${pf_enabled}" \
    --argjson last_update_epoch "${epoch}" \
    --argjson last_port "${last_port}" \
    --arg last_error "${last_error}" \
    '{
        vpn_status: $vpn_status,
        forwarded_port: $forwarded_port,
        pf_enabled: $pf_enabled,
        forwarding_state: $forwarding_state,
        controller_mode: $controller_mode,
        qbt_status: $qbt_status,
        last_update_epoch: $last_update_epoch,
        last_port: $last_port,
        last_error: $last_error
      }' 2>&1)"; then
    controller_log "ERROR: Failed to render controller status JSON: ${json_content}"
    return 1
  fi
  
  # Validate the JSON content before writing to file
  if ! jq empty <<< "${json_content}" 2>/dev/null; then
    controller_log "ERROR: Generated invalid JSON, not updating status file"
    return 1
  fi

  if ! printf '%s\n' "${json_content}" >"${tmp}"; then
    controller_log "ERROR: Failed to write controller status to temp file"
    return 1
  fi

  if ! mv -f "${tmp}" "${CONTROLLER_STATUS_FILE}"; then
    controller_log "Failed to move temporary state file to ${CONTROLLER_STATUS_FILE}"
    return 1
  fi

  trap - RETURN
  return 0
}

controller_mark_init() {
  _controller_qbt_state="paused"
  controller_log_event "controller:init"
  controller_write_state "init" 0 "initializing" "paused" "${CONTROLLER_REQUIRE_STRICT}" "initializing"
}

controller_pause_qbt() {
  if [[ "${_controller_qbt_state:-}" == "paused" ]]; then
    return 0
  fi
  if qbt_pause_all; then
    _controller_qbt_state="paused"
    controller_log_event "qbt:paused"
    return 0
  fi
  _controller_qbt_state="error"
  return 1
}

controller_resume_qbt() {
  if [[ "${_controller_qbt_state:-}" == "active" ]]; then
    return 0
  fi
  if qbt_resume_all; then
    _controller_qbt_state="active"
    controller_log_event "qbt:resumed"
    return 0
  fi
  _controller_qbt_state="error"
  return 1
}

controller_current_qbt_state() {
  printf '%s' "${_controller_qbt_state:-unknown}"
}

controller_apply_port() {
  local target_port="$1"
  if [[ -z "$target_port" || ! "$target_port" =~ ^[0-9]+$ ]]; then
    controller_log "ERROR: Invalid port '${target_port}' from Gluetun (expected numeric value)"
    return 1
  fi
  
  if [[ "$target_port" -lt 1024 || "$target_port" -gt 65535 ]]; then
    controller_log "ERROR: Port ${target_port} out of valid range (1024-65535)"
    return 1
  fi
  
  local current
  current="$(qbt_current_listen_port 2>/dev/null || printf '0')"
  if [[ "$current" != "$target_port" ]]; then
    controller_log "Applying forwarded port ${target_port} to qBittorrent (previous: ${current})"
    if ! qbt_set_listen_port "$target_port"; then
      controller_log "ERROR: Failed to set qBittorrent listen port to ${target_port}"
      controller_log "  → Check qBittorrent Web UI accessibility and credentials"
      return 1
    fi
    controller_log_event "port:applied ${target_port}"
    controller_log "✓ Successfully applied port ${target_port}"
  fi
  return 0
}

controller_check_trigger() {
  # Check for trigger file and remove it
  # Note: While not fully atomic, this is acceptable for trigger signaling
  # where multiple processes seeing the same trigger is benign
  if [[ ! -f "${CONTROLLER_TRIGGER_FILE}" ]]; then
    return 1
  fi
  
  if rm -f "${CONTROLLER_TRIGGER_FILE}" 2>/dev/null; then
    controller_log "Trigger file detected, forcing immediate poll"
    return 0
  fi
  
  # File existed but couldn't be removed (permissions or race)
  return 1
}

controller_startup_diagnostics() {
  controller_log "Running startup diagnostics..."
  
  # Check required commands
  local missing_cmds=()
  for cmd in curl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_cmds+=("$cmd")
    fi
  done
  
  if ((${#missing_cmds[@]} > 0)); then
    controller_log "ERROR: Missing required commands: ${missing_cmds[*]}"
    return 1
  fi
  
  # Validate configuration (note: we modify the variable here for the lifetime of the controller)
  if [[ -n "${CONTROLLER_POLL_INTERVAL}" ]] && ! [[ "${CONTROLLER_POLL_INTERVAL}" =~ ^[0-9]+$ ]]; then
    controller_log "WARNING: Invalid CONTROLLER_POLL_INTERVAL '${CONTROLLER_POLL_INTERVAL}', using default 15"
    CONTROLLER_POLL_INTERVAL=15
  fi
  
  if [[ "${CONTROLLER_POLL_INTERVAL}" -lt 5 ]]; then
    controller_log "WARNING: CONTROLLER_POLL_INTERVAL too low (${CONTROLLER_POLL_INTERVAL}s), using minimum 5s"
    CONTROLLER_POLL_INTERVAL=5
  fi
  
  # Check Gluetun connectivity (non-fatal, will retry in main loop)
  controller_log "Testing Gluetun API connectivity at ${GLUETUN_CONTROL_URL}..."
  if gluetun_api_status >/dev/null 2>&1; then
    controller_log "✓ Gluetun API reachable"
  else
    controller_log "⚠ Gluetun API not reachable yet (will retry in main loop)"
  fi
  
  # Check qBittorrent connectivity (non-fatal, will retry in main loop)
  controller_log "Testing qBittorrent API connectivity at ${QBT_HOST}:${QBT_PORT}..."
  if qbt_api_healthcheck 2>/dev/null; then
    controller_log "✓ qBittorrent API reachable"
  else
    controller_log "⚠ qBittorrent API not reachable yet (will retry in main loop)"
  fi
  
  controller_log "Diagnostics complete (mode=${CONTROLLER_MODE_STRING}, poll=${CONTROLLER_POLL_INTERVAL}s)"
  return 0
}

main() {
  controller_log "Starting vpn-port-guard (poll=${CONTROLLER_POLL_INTERVAL}s, mode=${CONTROLLER_MODE_STRING})"
  
  # Run startup diagnostics
  if ! controller_startup_diagnostics; then
    controller_log "Startup diagnostics failed, exiting"
    exit 1
  fi
  
  controller_log "🛡  Port Guard: initializing status file at ${CONTROLLER_STATUS_FILE}"
  controller_mark_init

  controller_pause_qbt || controller_log "⚠ Unable to pause qBittorrent during startup"
  qbt_api_login || controller_log "⚠ Unable to authenticate with qBittorrent API yet (will retry)"

  local sleep_next=0
  _controller_consecutive_failures=0
  
  while true; do
    if ((sleep_next > 0)); then
      sleep "${sleep_next}"
    fi
    sleep_next="${CONTROLLER_POLL_INTERVAL}"

    if controller_check_trigger; then
      sleep_next=0
    fi

    local status status_rc
    status_rc=0
    status="$(gluetun_api_status 2>/dev/null || printf 'unknown')" || status_rc=$?
    local port port_rc
    port_rc=0
    port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')" || port_rc=$?

    local last_error=""

    local forwarded_port="0"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      forwarded_port="$port"
    fi

    local forwarding_state="unavailable"
    if [[ "$forwarded_port" != 0 ]]; then
      forwarding_state="active"
    fi

    if ((status_rc != 0)); then
      ((_controller_consecutive_failures++))
      if ((_controller_consecutive_failures >= _controller_max_consecutive_failures)); then
        controller_log "ERROR: Gluetun API unreachable for ${_controller_consecutive_failures} consecutive attempts"
      else
        controller_log "Gluetun control API unreachable (attempt ${_controller_consecutive_failures}/${_controller_max_consecutive_failures}); keeping torrents paused"
      fi
      controller_record_vpn_state "down"
      controller_pause_qbt || true
      controller_write_state "unknown" 0 "unreachable" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "gluetun control API unreachable"
      continue
    fi
    
    # Reset failure counter on successful API call
    _controller_consecutive_failures=0

    if ((port_rc != 0)) && [[ -z "${last_error}" ]]; then
      last_error="unable to read forwarded port payload"
    fi

    if ! qbt_api_healthcheck; then
      controller_log "qBittorrent API unreachable; attempting to re-authenticate"
      # Try to re-authenticate which will force a fresh login
      if qbt_api_login 2>/dev/null && qbt_api_healthcheck 2>/dev/null; then
        controller_log "qBittorrent API re-authentication successful"
      else
        controller_log "qBittorrent API remains unreachable; pausing torrents until container recovers"
        controller_pause_qbt || true
        if [[ "$forwarded_port" != 0 ]]; then
          forwarding_state="error"
        fi
        if [[ -z "$last_error" ]]; then
          last_error="qBittorrent API unreachable"
        fi
        controller_write_state "$status" "$forwarded_port" "$forwarding_state" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
        continue
      fi
    fi

    if [[ "$status" != "running" ]]; then
      controller_log "VPN not ready (status=${status}); keeping torrents paused"
      controller_record_vpn_state "down"
      controller_pause_qbt || true
      controller_write_state "$status" "$forwarded_port" "unavailable" "paused" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
      continue
    fi

    controller_record_vpn_state "up"

    if [[ "$forwarded_port" != 0 ]]; then
      if controller_apply_port "$forwarded_port"; then
        if controller_resume_qbt; then
          controller_write_state "running" "$forwarded_port" "active" "active" "${CONTROLLER_REQUIRE_STRICT}" ""
        else
          controller_write_state "running" "$forwarded_port" "active" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
        fi
      else
        forwarding_state="error"
        controller_pause_qbt || true
        controller_write_state "running" "$forwarded_port" "$forwarding_state" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "failed to set qBittorrent listen port"
      fi
      continue
    fi

    if [[ "$CONTROLLER_REQUIRE_STRICT" == "true" ]]; then
      controller_log "Forwarded port unavailable; strict mode enabled so torrents remain paused"
      controller_pause_qbt || true
      controller_write_state "running" 0 "unavailable" "paused" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
    else
      controller_log "Forwarded port unavailable; torrents running without inbound port"
      if controller_resume_qbt; then
        controller_write_state "running" 0 "unavailable" "active" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
      else
        controller_write_state "running" 0 "unavailable" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "$last_error"
      fi
    fi
  done
}

controller_shutdown() {
  controller_log "Received shutdown signal, cleaning up..."
  controller_log_event "controller:shutdown"
  controller_record_vpn_state "down"
  controller_pause_qbt || controller_log "⚠ Unable to pause qBittorrent during shutdown"
  controller_write_state "down" 0 "unavailable" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}" "controller shutting down"
  qbt_api_cleanup
  controller_log "Shutdown complete"
  exit 0
}

trap controller_shutdown EXIT INT TERM

main "$@"

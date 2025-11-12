#!/usr/bin/env bash
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

: "${CONTROLLER_POLL_INTERVAL:=${VPN_PORT_GUARD_POLL_SECONDS:-15}}"
: "${CONTROLLER_STATUS_FILE:=/gluetun_state/port-guard-status.json}"
: "${CONTROLLER_TRIGGER_FILE:=/gluetun_state/port-guard.trigger}"
: "${CONTROLLER_TMP_DIR:=/tmp/vpn-port-guard}"
: "${CONTROLLER_REQUIRE_PF:=}"
: "${CONTROLLER_REQUIRE_PORT_FORWARDING:=}"
: "${VPN_PORT_GUARD_REQUIRE_FORWARDING:=}"

controller_bool() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      printf 'true'
      ;;
    *)
      printf 'false'
      ;;
  esac
}

controller_mode_raw="${CONTROLLER_REQUIRE_PF}"
if [[ -z "${controller_mode_raw}" ]]; then
  controller_mode_raw="${CONTROLLER_REQUIRE_PORT_FORWARDING:-${VPN_PORT_GUARD_REQUIRE_FORWARDING:-false}}"
fi

CONTROLLER_REQUIRE_STRICT="$(controller_bool "${controller_mode_raw}")"
if [[ "${CONTROLLER_REQUIRE_STRICT}" == "true" ]]; then
  CONTROLLER_MODE_STRING="strict"
else
  CONTROLLER_MODE_STRING="preferred"
fi

mkdir -p "${CONTROLLER_TMP_DIR}" >/dev/null 2>&1 || true
mkdir -p "$(dirname "${CONTROLLER_STATUS_FILE}")" >/dev/null 2>&1 || true

controller_write_state() {
  local vpn_status="${1:-unknown}"
  local port_raw="${2:-0}"
  local forwarding_state="${3:-unavailable}"
  local qbt_status="${4:-unknown}"
  local pf_arg="${5:-${CONTROLLER_REQUIRE_STRICT}}"

  local port="0"
  if [[ -n "${port_raw}" && "${port_raw}" =~ ^[0-9]+$ ]]; then
    port="${port_raw}"
  fi

  case "${forwarding_state}" in
    active|unavailable|error) ;;
    *) forwarding_state="unavailable" ;;
  esac

  case "${qbt_status}" in
    active|paused|error) ;;
    *) qbt_status="error" ;;
  esac

  local pf_enabled
  pf_enabled="$(controller_bool "${pf_arg}")"

  local epoch
  epoch="$(date +%s 2>/dev/null || printf '0')"

  local tmp
  if ! tmp="$(mktemp "${CONTROLLER_TMP_DIR}/state.XXXXXX" 2>/dev/null)"; then
    controller_log "Unable to create temporary state file"
    return 1
  fi

  trap 'rm -f "${tmp}"' RETURN

  if ! jq -n \
      --arg vpn_status "${vpn_status}" \
      --arg forwarding_state "${forwarding_state}" \
      --arg controller_mode "${CONTROLLER_MODE_STRING}" \
      --arg qbt_status "${qbt_status}" \
      --argjson forwarded_port "${port}" \
      --argjson pf_enabled "${pf_enabled}" \
      --argjson last_update_epoch "${epoch}" \
      '{
        vpn_status: $vpn_status,
        forwarded_port: $forwarded_port,
        pf_enabled: $pf_enabled,
        forwarding_state: $forwarding_state,
        controller_mode: $controller_mode,
        qbt_status: $qbt_status,
        last_update_epoch: $last_update_epoch
      }' >"${tmp}"; then
    controller_log "Failed to render controller status JSON"
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
  controller_write_state "init" 0 "unavailable" "paused" "${CONTROLLER_REQUIRE_STRICT}"
}

controller_pause_qbt() {
  if [[ "${_controller_qbt_state:-}" == "paused" ]]; then
    return 0
  fi
  if qbt_pause_all; then
    _controller_qbt_state="paused"
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
    controller_log "Invalid port '${target_port}' from Gluetun"
    return 1
  fi
  local current
  current="$(qbt_current_listen_port 2>/dev/null || printf '0')"
  if [[ "$current" != "$target_port" ]]; then
    controller_log "Applying forwarded port ${target_port} to qBittorrent"
    if ! qbt_set_listen_port "$target_port"; then
      controller_log "Failed to set qBittorrent listen port"
      return 1
    fi
  fi
  return 0
}

controller_check_trigger() {
  if [[ -f "${CONTROLLER_TRIGGER_FILE}" ]]; then
    rm -f "${CONTROLLER_TRIGGER_FILE}" 2>/dev/null || true
    return 0
  fi
  return 1
}

main() {
  controller_log "Starting vpn-port-guard (poll=${CONTROLLER_POLL_INTERVAL}s, mode=${CONTROLLER_MODE_STRING})"
  controller_mark_init

  controller_pause_qbt || true
  qbt_api_login || controller_log "Unable to authenticate with qBittorrent API yet"

  local sleep_next=0
  while true; do
    if (( sleep_next > 0 )); then
      sleep "${sleep_next}"
    fi
    sleep_next="${CONTROLLER_POLL_INTERVAL}"

    if controller_check_trigger; then
      sleep_next=0
    fi

    local status
    status="$(gluetun_api_status 2>/dev/null || printf 'unknown')"
    local port
    port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')"

    local forwarded_port="0"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      forwarded_port="$port"
    fi

    local forwarding_state="unavailable"
    if [[ "$forwarded_port" != 0 ]]; then
      forwarding_state="active"
    fi

    if ! qbt_api_healthcheck; then
      controller_log "qBittorrent API unreachable; pausing until container recovers"
      controller_pause_qbt || true
      if [[ "$forwarded_port" != 0 ]]; then
        forwarding_state="error"
      fi
      controller_write_state "$status" "$forwarded_port" "$forwarding_state" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}"
      continue
    fi

    if [[ "$status" != "running" ]]; then
      controller_log "VPN not ready (status=${status}); keeping torrents paused"
      controller_pause_qbt || true
      controller_write_state "$status" "$forwarded_port" "unavailable" "paused" "${CONTROLLER_REQUIRE_STRICT}"
      continue
    fi

    if [[ "$forwarded_port" != 0 ]]; then
      if controller_apply_port "$forwarded_port"; then
        if controller_resume_qbt; then
          controller_write_state "running" "$forwarded_port" "active" "active" "${CONTROLLER_REQUIRE_STRICT}"
        else
          controller_write_state "running" "$forwarded_port" "active" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}"
        fi
      else
        forwarding_state="error"
        controller_pause_qbt || true
        controller_write_state "running" "$forwarded_port" "$forwarding_state" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}"
      fi
      continue
    fi

    if [[ "$CONTROLLER_REQUIRE_STRICT" == "true" ]]; then
      controller_log "Forwarded port unavailable; strict mode enabled so torrents remain paused"
      controller_pause_qbt || true
      controller_write_state "running" 0 "unavailable" "paused" "${CONTROLLER_REQUIRE_STRICT}"
    else
      controller_log "Forwarded port unavailable; torrents running without inbound port"
      if controller_resume_qbt; then
        controller_write_state "running" 0 "unavailable" "active" "${CONTROLLER_REQUIRE_STRICT}"
      else
        controller_write_state "running" 0 "unavailable" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}"
      fi
    fi
  done
}

trap 'controller_log "Shutting down"; controller_pause_qbt || true; controller_write_state "down" 0 "unavailable" "$(controller_current_qbt_state)" "${CONTROLLER_REQUIRE_STRICT}"' EXIT

main "$@"

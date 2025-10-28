#!/usr/bin/env bash
# vpn-port-guard controller
# Watches Gluetun's control API and keeps qBittorrent aligned with ProtonVPN forwarding.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=../stack-common.sh
. "${REPO_ROOT}/scripts/stack-common.sh"
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
  CONTROLLER_MODE_STRING="required"
else
  CONTROLLER_MODE_STRING="preferred"
fi

mkdir -p "${CONTROLLER_TMP_DIR}" >/dev/null 2>&1 || true
mkdir -p "$(dirname "${CONTROLLER_STATUS_FILE}")" >/dev/null 2>&1 || true

controller_log() {
  msg "[vpn-port-guard] $*"
}

controller_write_state() {
  local vpn_status="$1"
  local port="$2"
  local pf_arg="$3"
  local forwarding_state="$4"
  local qbt_status="$5"

  local pf_enabled
  pf_enabled="$(controller_bool "$pf_arg")"

  if [[ -z "${port}" || ! "${port}" =~ ^[0-9]+$ ]]; then
    port=0
  fi

  case "${forwarding_state}" in
    active|missing) ;;
    *) forwarding_state="missing" ;;
  esac

  local epoch
  epoch="$(date +%s)"

  local tmp
  if ! tmp="$(mktemp "${CONTROLLER_TMP_DIR}/state.XXXXXX" 2>/dev/null)"; then
    controller_log "Unable to create temporary state file"
    return 1
  fi
  cat >"${tmp}" <<JSON
{
  "vpn_status": "${vpn_status}",
  "forwarded_port": ${port},
  "pf_enabled": ${pf_enabled},
  "forwarding_state": "${forwarding_state}",
  "controller_mode": "${CONTROLLER_MODE_STRING}",
  "qbt_status": "${qbt_status}",
  "last_update_epoch": ${epoch}
}
JSON
  mv "${tmp}" "${CONTROLLER_STATUS_FILE}"
}

controller_mark_init() {
  controller_write_state "init" 0 "false" "missing" "paused"
}

controller_pause_qbt() {
  if [[ "${_controller_qbt_state:-}" == "paused" ]]; then
    return 0
  fi
  if qbt_pause_all; then
    _controller_qbt_state="paused"
    return 0
  fi
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
  return 1
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

    local forwarding_state="missing"
    local port_present=false
    if [[ "$forwarded_port" != 0 ]]; then
      forwarding_state="active"
      port_present=true
    fi

    if ! qbt_api_healthcheck; then
      controller_log "qBittorrent API unreachable; pausing until container recovers"
      controller_pause_qbt || true
      controller_write_state "$status" "$forwarded_port" "$port_present" "$forwarding_state" "error"
      continue
    fi

    if [[ "$status" != "running" ]]; then
      controller_log "VPN not ready (status=${status}); keeping torrents paused"
      controller_pause_qbt || true
      controller_write_state "$status" "$forwarded_port" "false" "missing" "paused"
      continue
    fi

    if [[ "$forwarded_port" != 0 ]]; then
      if controller_apply_port "$forwarded_port"; then
        controller_resume_qbt || true
        controller_write_state "running" "$forwarded_port" "true" "active" "active"
      else
        controller_pause_qbt || true
        controller_write_state "running" "$forwarded_port" "false" "active" "error"
      fi
      continue
    fi

    if [[ "$CONTROLLER_REQUIRE_STRICT" == "true" ]]; then
      controller_log "Forwarded port unavailable; strict mode enabled so torrents remain paused"
      controller_pause_qbt || true
      controller_write_state "running" 0 "false" "missing" "paused"
    else
      controller_log "Forwarded port unavailable; torrents running without inbound port"
      controller_resume_qbt || true
      controller_write_state "running" 0 "false" "missing" "active"
    fi
  done
}

trap 'controller_log "Shutting down"; controller_pause_qbt || true; controller_write_state "down" 0 "false" "missing" "paused"' EXIT

main "$@"

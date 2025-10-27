# shellcheck shell=bash
# Purpose: Implement Gluetun health monitoring and recovery logic.
# Inputs: Helper functions from vpn-auto-{state,config,signals,metrics}.sh and gluetun.sh.
# Outputs: Updates watchdog state, triggers recoveries, and keeps qBittorrent in sync.
# Exit codes: Functions return non-zero when recovery steps fail; process_once returns 0 on success.
#
# Historical issue: previous logic restarted the container directly, rewrote SERVER_COUNTRIES,
# and relied on qBittorrent throughput heuristics. The new controller uses Gluetun's control
# API as the primary recovery path, rate-limits retries, and performs post-recovery port syncs.

if [[ -n "${__VPN_AUTO_CONTROL_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_CONTROL_LOADED=1

VPN_AUTO_CONTROL_LAST_ERROR=""
VPN_AUTO_HEALTH_STATUS="unknown"
VPN_AUTO_HEALTH_IP=""
VPN_AUTO_HEALTH_PORT=0
VPN_AUTO_HEALTH_PORT_STATUS=""
VPN_AUTO_HEALTH_REASON=""

vpn_auto_control_request() {
  local path="$1"
  local attempts=0
  local output=""
  VPN_AUTO_CONTROL_LAST_ERROR=""
  while ((attempts < 2)); do
    output="$(gluetun_control_get "$path" 2>/dev/null || printf '')"
    if [[ -n "$output" ]]; then
      printf '%s' "$output"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 2
  done
  VPN_AUTO_CONTROL_LAST_ERROR="Failed to query ${path}"
  return 1
}

vpn_auto_health_snapshot() {
  VPN_AUTO_HEALTH_STATUS="unknown"
  VPN_AUTO_HEALTH_IP=""
  VPN_AUTO_HEALTH_PORT=0
  VPN_AUTO_HEALTH_PORT_STATUS=""
  VPN_AUTO_HEALTH_REASON=""
  local payload=""

  if payload="$(vpn_auto_control_request "/v1/openvpn/status")"; then
    local status
    status="$( _gluetun_extract_json_string "$payload" status )"
    if [[ -z "$status" ]]; then
      status="unknown"
    fi
    VPN_AUTO_HEALTH_STATUS="$status"
  else
    VPN_AUTO_HEALTH_REASON="${VPN_AUTO_CONTROL_LAST_ERROR}"
  fi

  if payload="$(vpn_auto_control_request "/v1/publicip/ip")"; then
    if [[ "$payload" == '{'* ]]; then
      VPN_AUTO_HEALTH_IP="$( _gluetun_extract_json_string "$payload" ip )"
      if [[ -z "$VPN_AUTO_HEALTH_IP" ]]; then
        VPN_AUTO_HEALTH_IP="$( _gluetun_extract_json_string "$payload" public_ip )"
      fi
    else
      payload="$(printf '%s' "$payload" | tr -d '\r\n"')"
      VPN_AUTO_HEALTH_IP="$payload"
    fi
  fi

  if vpn_auto_pf_required; then
    if payload="$(vpn_auto_control_request "/v1/openvpn/portforwarded")"; then
      if gluetun_port_forward_details "$payload"; then
        VPN_AUTO_HEALTH_PORT="${GLUETUN_PORT_FORWARD_PORT:-0}"
        VPN_AUTO_HEALTH_PORT_STATUS="${GLUETUN_PORT_FORWARD_STATUS:-}"
      fi
    fi
  fi
}

vpn_auto_health_is_healthy() {
  local reason=""
  local now
  now="$(vpn_auto_now_epoch)"

  if [[ "$VPN_AUTO_HEALTH_STATUS" != "running" ]]; then
    reason="OpenVPN status: ${VPN_AUTO_HEALTH_STATUS:-unknown}"
  fi

  if [[ -z "$VPN_AUTO_HEALTH_IP" ]]; then
    if [[ -n "$reason" ]]; then
      reason+="; "
    fi
    reason+="public IP unavailable"
  else
    # shellcheck disable=SC2034  # persisted by vpn_auto_state_save
    VPN_AUTO_STATE_LAST_PUBLIC_IP="$VPN_AUTO_HEALTH_IP"
  fi

  if vpn_auto_pf_required; then
    local grace
    grace="$(vpn_auto_reconnect_pf_grace_seconds)"
    if [[ -z "$grace" || ! "$grace" =~ ^[0-9]+$ ]]; then
      grace=300
    fi
    if [[ "$VPN_AUTO_HEALTH_PORT" =~ ^[0-9]+$ && "$VPN_AUTO_HEALTH_PORT" -gt 0 ]]; then
      # shellcheck disable=SC2034
      VPN_AUTO_STATE_LAST_FORWARD_PORT="$VPN_AUTO_HEALTH_PORT"
      # shellcheck disable=SC2034
      VPN_AUTO_STATE_LAST_PORT_SUCCESS_EPOCH="$now"
      VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH=0
    else
      if ((VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH == 0)); then
        VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH="$now"
      fi
      local since
      since="$VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH"
      if ((now - since > grace)); then
        local detail="forwarded port unavailable"
        if [[ -n "$VPN_AUTO_HEALTH_PORT_STATUS" ]]; then
          detail+=" (${VPN_AUTO_HEALTH_PORT_STATUS})"
        fi
        if [[ -n "$reason" ]]; then
          reason+="; "
        fi
        reason+="$detail"
      fi
    fi
  else
    VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH=0
  fi

  if [[ -z "$reason" ]]; then
    # shellcheck disable=SC2034
    VPN_AUTO_STATE_LAST_HEALTHY_EPOCH="$now"
    # shellcheck disable=SC2034
    VPN_AUTO_STATE_LAST_ERROR=""
    VPN_AUTO_HEALTH_REASON=""
    return 0
  fi

  VPN_AUTO_HEALTH_REASON="$reason"
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_ERROR="$reason"
  return 1
}

vpn_auto_wait_for_health() {
  local timeout="${1:-120}"
  local start
  start="$(vpn_auto_now_epoch)"
  while true; do
    vpn_auto_health_snapshot
    if vpn_auto_health_is_healthy; then
      return 0
    fi
    local current
    current="$(vpn_auto_now_epoch)"
    if ((current - start >= timeout)); then
      break
    fi
    sleep 5
  done
  return 1
}

vpn_auto_cycle_openvpn_control() {
  if ! gluetun_cycle_openvpn; then
    VPN_AUTO_CONTROL_LAST_ERROR="Failed to cycle OpenVPN via control API"
    return 1
  fi
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_ACTION="control"
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH="$(vpn_auto_now_epoch)"
  return 0
}

vpn_auto_container_id_for_service() {
  local service="$1"
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  local id=""
  if [[ -n "${STACK:-}" ]]; then
    id="$(docker ps --filter "label=com.docker.compose.project=${STACK}" --filter "label=com.docker.compose.service=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
  fi
  if [[ -z "$id" ]]; then
    id="$(docker ps --filter "label=com.docker.compose.service=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
  fi
  if [[ -z "$id" ]]; then
    id="$(docker ps --filter "name=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
  fi
  if [[ -n "$id" ]]; then
    printf '%s' "$id"
    return 0
  fi
  return 1
}

vpn_auto_restart_gluetun_container() {
  local now
  now="$(vpn_auto_now_epoch)"
  if vpn_auto_compose_available && [[ -n "${ARR_STACK_DIR:-}" ]]; then
    if arr_resolve_compose_cmd 0 >/dev/null 2>&1; then
      if (
        cd "$ARR_STACK_DIR" 2>/dev/null &&
        "${DOCKER_COMPOSE_CMD[@]}" restart gluetun >/dev/null 2>&1
      ); then
        # shellcheck disable=SC2034
        VPN_AUTO_STATE_LAST_ACTION="compose"
        # shellcheck disable=SC2034
        VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH="$now"
        return 0
      fi
    fi
  fi

  local container
  if container="$(vpn_auto_container_id_for_service gluetun)"; then
    if docker restart "$container" >/dev/null 2>&1; then
      # shellcheck disable=SC2034
      VPN_AUTO_STATE_LAST_ACTION="docker"
      # shellcheck disable=SC2034
      VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH="$now"
      return 0
    fi
  fi
  VPN_AUTO_CONTROL_LAST_ERROR="Failed to restart Gluetun container"
  return 1
}

vpn_auto_sync_qbt_after_recovery() {
  if ! vpn_auto_pf_required; then
    VPN_AUTO_STATE_PENDING_PORT_SYNC=0
    return 0
  fi
  local forwarded="$1"
  if [[ -z "$forwarded" || ! "$forwarded" =~ ^[0-9]+$ || "$forwarded" -le 0 ]]; then
    VPN_AUTO_STATE_PENDING_PORT_SYNC=1
    return 1
  fi
  local qbt_port
  qbt_port="$(vpn_auto_qbt_get_listen_port 2>/dev/null || printf '0')"
  if [[ "$qbt_port" =~ ^[0-9]+$ ]]; then
    VPN_AUTO_STATE_LAST_QBT_PORT="$qbt_port"
  else
    VPN_AUTO_STATE_LAST_QBT_PORT=0
  fi
  if [[ "$qbt_port" == "$forwarded" && "$qbt_port" != "0" ]]; then
    VPN_AUTO_STATE_PENDING_PORT_SYNC=0
    return 0
  fi
  if vpn_auto_qbt_sync_port "$forwarded"; then
    sleep 2
    qbt_port="$(vpn_auto_qbt_get_listen_port 2>/dev/null || printf '0')"
    if [[ "$qbt_port" =~ ^[0-9]+$ ]]; then
      VPN_AUTO_STATE_LAST_QBT_PORT="$qbt_port"
    else
      VPN_AUTO_STATE_LAST_QBT_PORT=0
    fi
    if [[ "$qbt_port" == "$forwarded" && "$qbt_port" != "0" ]]; then
      VPN_AUTO_STATE_PENDING_PORT_SYNC=0
      return 0
    fi
    VPN_AUTO_STATE_PENDING_PORT_SYNC=1
    return 1
  fi
  VPN_AUTO_STATE_PENDING_PORT_SYNC=1
  return 1
}

vpn_auto_update_status() {
  local status="$1"
  local detail="$2"
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_STATUS="$status"
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_DETAIL="$detail"
  vpn_auto_write_status "$status" "$detail" "$VPN_AUTO_HEALTH_IP" "$VPN_AUTO_HEALTH_PORT" "$VPN_AUTO_STATE_LAST_QBT_PORT"
}

vpn_auto_reconnect_process_once() {
  vpn_auto_reconnect_load_env
  vpn_auto_state_load

  local now
  now="$(vpn_auto_now_epoch)"
  # shellcheck disable=SC2034
  VPN_AUTO_STATE_LAST_CHECK_EPOCH="$now"

  if vpn_auto_reconnect_manual_pause_active; then
    vpn_auto_update_status "paused" "Auto-reconnect paused by override"
    vpn_auto_state_save
    return 0
  fi

  if vpn_auto_reconnect_kill_active; then
    vpn_auto_update_status "paused" "Auto-reconnect disabled for 24h"
    vpn_auto_state_save
    return 0
  fi

  if ! vpn_auto_reconnect_is_enabled; then
    vpn_auto_update_status "disabled" "VPN_AUTO_RECONNECT_ENABLED=0"
    vpn_auto_state_save
    return 0
  fi

  local forced=0
  if vpn_auto_reconnect_force_once_requested; then
    forced=1
    vpn_auto_reconnect_consume_force_once_flag
    VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH=0
  fi

  vpn_auto_health_snapshot
  local healthy=0
  if vpn_auto_health_is_healthy; then
    healthy=1
  fi

  if ((healthy)); then
    VPN_AUTO_STATE_CONSECUTIVE_FAILURES=0
    local pending_sync="${VPN_AUTO_STATE_PENDING_PORT_SYNC:-0}"
    local pf_needed=0
    if vpn_auto_pf_required; then
      pf_needed=1
    fi
    if ((pf_needed)) && [[ "$pending_sync" != "0" ]]; then
      if vpn_auto_sync_qbt_after_recovery "$VPN_AUTO_HEALTH_PORT"; then
        msg "VPN auto: qBittorrent port aligned (${VPN_AUTO_HEALTH_PORT})"
      else
        warn "VPN auto: qBittorrent port ${VPN_AUTO_HEALTH_PORT} still pending"
      fi
    elif ((pf_needed == 0)); then
      VPN_AUTO_STATE_PENDING_PORT_SYNC=0
    fi
    vpn_auto_update_status "healthy" "OpenVPN tunnel healthy"
    vpn_auto_state_save
    return 0
  fi

  VPN_AUTO_STATE_CONSECUTIVE_FAILURES=$((VPN_AUTO_STATE_CONSECUTIVE_FAILURES + 1))
  local reason="$VPN_AUTO_HEALTH_REASON"
  if [[ -z "$reason" ]]; then
    reason="Unknown VPN health failure"
  fi

  local cooldown_remaining=0
  if ((forced == 0)); then
    local cooldown="${VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH:-0}"
    if [[ "$cooldown" =~ ^[0-9]+$ ]] && ((cooldown > now)); then
      cooldown_remaining=$((cooldown - now))
    fi
  fi

  if ((cooldown_remaining > 0)); then
    vpn_auto_update_status "cooldown" "Cooldown ${cooldown_remaining}s remaining (${reason})"
    vpn_auto_state_save
    return 0
  fi

  msg "VPN auto: attempting recovery (${reason})"
  local recovered=0
  local recovery_detail=""

  if vpn_auto_cycle_openvpn_control; then
    if vpn_auto_wait_for_health 120; then
      recovered=1
      recovery_detail="restarted via control API"
    fi
  fi

  if ((recovered == 0)); then
    if vpn_auto_restart_gluetun_container && vpn_auto_wait_for_health 180; then
      recovered=1
      recovery_detail="restarted Gluetun container"
    fi
  fi

  if ((recovered)); then
    msg "VPN auto: recovery successful (${recovery_detail})"
    # shellcheck disable=SC2034
    VPN_AUTO_STATE_LAST_RECOVERY_EPOCH="$(vpn_auto_now_epoch)"
    VPN_AUTO_STATE_CONSECUTIVE_FAILURES=0
    VPN_AUTO_STATE_PENDING_PORT_SYNC=1
    VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH=$((now + $(vpn_auto_reconnect_cooldown_seconds)))
    if vpn_auto_pf_required; then
      if vpn_auto_sync_qbt_after_recovery "$VPN_AUTO_HEALTH_PORT"; then
        msg "VPN auto: confirmed qBittorrent port ${VPN_AUTO_HEALTH_PORT}"
      else
        warn "VPN auto: Gluetun recovered but qBittorrent port ${VPN_AUTO_HEALTH_PORT} still pending"
      fi
    fi
    vpn_auto_update_status "recovered" "${recovery_detail}"
    vpn_auto_append_history "recovery" "success" "$recovery_detail"
    vpn_auto_state_save
    return 0
  fi

  warn "VPN auto: recovery failed (${VPN_AUTO_CONTROL_LAST_ERROR:-${reason}})"
  local retry_delay
  retry_delay="$(vpn_auto_reconnect_retry_delay_seconds)"
  VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH=$((now + retry_delay))
  VPN_AUTO_STATE_PENDING_PORT_SYNC=1
  vpn_auto_update_status "error" "${reason}"
  vpn_auto_append_history "recovery" "failure" "${VPN_AUTO_CONTROL_LAST_ERROR:-${reason}}"
  vpn_auto_state_save
  return 1
}

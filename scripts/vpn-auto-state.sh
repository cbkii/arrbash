# shellcheck shell=bash
# Purpose: Manage persistent state and status files for the VPN watchdog.
# Inputs: ARR_STACK_DIR, ARR_DOCKER_DIR, STACK, helper functions from scripts/common.sh.
# Outputs: JSON status/state documents consumed by arr.vpn.auto.* helpers and summary output.
# Exit codes: Functions return non-zero when state cannot be loaded or persisted.
#
# Historical issue: the previous implementation stored dozens of unrelated metrics
# (qBittorrent throughput, jitter, rotation indices) and relied on Bash-only features
# such as mapfile/arrays. Those constructs crashed under zsh and obscured the actual
# Gluetun health state the watchdog needs to track. The new implementation keeps a
# minimal, portable schema focused on Gluetun control API health and recovery data.
# Audit: quoting tightened for persistence; history JSON relies on jq while staying shell-portable.

if [[ -n "${__VPN_AUTO_STATE_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_STATE_LOADED=1

VPN_AUTO_STATE_SCHEMA_VERSION=2

vpn_auto_state_reset() {
  VPN_AUTO_STATE_LAST_STATUS="unknown"
  VPN_AUTO_STATE_LAST_DETAIL=""
  VPN_AUTO_STATE_LAST_PUBLIC_IP=""
  VPN_AUTO_STATE_LAST_FORWARD_PORT=0
  VPN_AUTO_STATE_LAST_QBT_PORT=0
  VPN_AUTO_STATE_LAST_CHECK_EPOCH=0
  VPN_AUTO_STATE_LAST_HEALTHY_EPOCH=0
  VPN_AUTO_STATE_LAST_PORT_SUCCESS_EPOCH=0
  VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH=0
  VPN_AUTO_STATE_CONSECUTIVE_FAILURES=0
  VPN_AUTO_STATE_LAST_RECOVERY_EPOCH=0
  VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH=0
  VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH=0
  VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH=0
  VPN_AUTO_STATE_PENDING_PORT_SYNC=0
  VPN_AUTO_STATE_LAST_ACTION="none"
  VPN_AUTO_STATE_LAST_ERROR=""
  VPN_AUTO_STATE_LAST_PROTOCOL=""
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_FROM=""
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_TO=""
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_REASON=""
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_EPOCH=0
}

vpn_auto_state_reset

vpn_auto_now_epoch() {
  if declare -f arr_now_epoch >/dev/null 2>&1; then
    arr_now_epoch
    return
  fi
  date +%s
}

vpn_auto_epoch_to_iso() {
  local epoch="$1"
  if [[ -z "$epoch" || "$epoch" == "0" ]]; then
    printf ''
    return 0
  fi
  if declare -f arr_epoch_to_iso >/dev/null 2>&1; then
    arr_epoch_to_iso "$epoch"
    return
  fi
  date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf ''
}

vpn_auto_iso_now() {
  if declare -f arr_date_utc >/dev/null 2>&1; then
    arr_date_utc '+%Y-%m-%dT%H:%M:%SZ'
    return
  fi
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

vpn_auto_state_base_dir() {
  if declare -f arr_gluetun_auto_reconnect_dir >/dev/null 2>&1; then
    arr_gluetun_auto_reconnect_dir
    return
  fi

  local root=""
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    root="$(arr_gluetun_dir 2>/dev/null || printf '')"
  fi
  if [[ -z "$root" ]]; then
    local docker_root="${ARR_DOCKER_DIR:-}"
    if [[ -z "$docker_root" ]] && declare -f arr_docker_data_root >/dev/null 2>&1; then
      docker_root="$(arr_docker_data_root 2>/dev/null || printf '')"
    fi
    if [[ -z "$docker_root" ]]; then
      return 1
    fi
    root="${docker_root%/}/gluetun"
  fi
  printf '%s/auto-reconnect' "${root%/}"
}

vpn_auto_state_file() {
  local dir
  dir="$(vpn_auto_state_base_dir 2>/dev/null || printf '')"
  if [[ -z "$dir" ]]; then
    return 1
  fi
  printf '%s/state.json' "${dir%/}"
}

vpn_auto_status_file() {
  local base="${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}"
  printf '%s/.vpn-auto-reconnect-status.json' "${base%/}"
}

vpn_auto_history_file() {
  local dir
  dir="$(vpn_auto_state_base_dir 2>/dev/null || printf '')"
  if [[ -z "$dir" ]]; then
    return 1
  fi
  printf '%s/history.log' "${dir%/}"
}

vpn_auto_cookie_file() {
  local dir
  dir="$(vpn_auto_state_base_dir 2>/dev/null || printf '')"
  if [[ -z "$dir" ]]; then
    return 1
  fi
  printf '%s/session.cookie' "${dir%/}"
}

vpn_auto_pf_state_file() {
  local root=""
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    root="$(arr_gluetun_dir 2>/dev/null || printf '')"
  else
    local docker_root="${ARR_DOCKER_DIR:-}"
    if [[ -z "$docker_root" ]] && declare -f arr_docker_data_root >/dev/null 2>&1; then
      docker_root="$(arr_docker_data_root 2>/dev/null || printf '')"
    fi
    if [[ -z "$docker_root" ]]; then
      return 1
    fi
    root="${docker_root%/}/gluetun"
  fi
  local name="${PF_ASYNC_STATE_FILE:-pf-state.json}"
  printf '%s/%s' "${root%/}" "$name"
}

vpn_auto_pf_hook_path() {
  local root=""
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    root="$(arr_gluetun_dir 2>/dev/null || printf '')"
  else
    local docker_root="${ARR_DOCKER_DIR:-}"
    if [[ -z "$docker_root" ]] && declare -f arr_docker_data_root >/dev/null 2>&1; then
      docker_root="$(arr_docker_data_root 2>/dev/null || printf '')"
    fi
    if [[ -z "$docker_root" ]]; then
      return 1
    fi
    root="${docker_root%/}/gluetun"
  fi
  printf '%s/hooks/update-qbt-port.sh' "${root%/}"
}

vpn_auto_has_jq() {
  command -v jq >/dev/null 2>&1
}

vpn_auto_json_get_string() {
  local payload="$1"
  local key="$2"
  local value=""
  if vpn_auto_has_jq; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi
  if [[ -z "$value" ]]; then
    value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"\\]*\\)\".*/\\1/p" | head -n1)"
  fi
  printf '%s' "$value"
}

vpn_auto_json_get_number() {
  local payload="$1"
  local key="$2"
  local value=""
  if vpn_auto_has_jq; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi
  if [[ -z "$value" ]]; then
    value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\(-\?[0-9][0-9]*\).*/\\1/p" | head -n1)"
  fi
  if [[ "$value" =~ ^-?[0-9]+$ ]]; then
    printf '%s' "$value"
  else
    printf '0'
  fi
}

vpn_auto_state_load() {
  vpn_auto_state_reset
  local file
  file="$(vpn_auto_state_file 2>/dev/null || printf '')"
  if [[ -z "$file" || ! -f "$file" ]]; then
    return 0
  fi
  local json
  json="$(cat "$file" 2>/dev/null || printf '')"
  if [[ -z "$json" ]]; then
    return 0
  fi
  VPN_AUTO_STATE_LAST_STATUS="$(vpn_auto_json_get_string "$json" last_status)"
  VPN_AUTO_STATE_LAST_DETAIL="$(vpn_auto_json_get_string "$json" last_detail)"
  VPN_AUTO_STATE_LAST_PUBLIC_IP="$(vpn_auto_json_get_string "$json" last_public_ip)"
  VPN_AUTO_STATE_LAST_FORWARD_PORT="$(vpn_auto_json_get_number "$json" last_forward_port)"
  VPN_AUTO_STATE_LAST_QBT_PORT="$(vpn_auto_json_get_number "$json" last_qbt_port)"
  VPN_AUTO_STATE_LAST_CHECK_EPOCH="$(vpn_auto_json_get_number "$json" last_check_epoch)"
  VPN_AUTO_STATE_LAST_HEALTHY_EPOCH="$(vpn_auto_json_get_number "$json" last_healthy_epoch)"
  VPN_AUTO_STATE_LAST_PORT_SUCCESS_EPOCH="$(vpn_auto_json_get_number "$json" last_port_success_epoch)"
  VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH="$(vpn_auto_json_get_number "$json" port_missing_since_epoch)"
  VPN_AUTO_STATE_CONSECUTIVE_FAILURES="$(vpn_auto_json_get_number "$json" consecutive_failures)"
  VPN_AUTO_STATE_LAST_RECOVERY_EPOCH="$(vpn_auto_json_get_number "$json" last_recovery_epoch)"
  VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH="$(vpn_auto_json_get_number "$json" last_control_restart_epoch)"
  VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH="$(vpn_auto_json_get_number "$json" last_container_restart_epoch)"
  VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH="$(vpn_auto_json_get_number "$json" cooldown_until_epoch)"
  VPN_AUTO_STATE_PENDING_PORT_SYNC="$(vpn_auto_json_get_number "$json" pending_port_sync)"
  VPN_AUTO_STATE_LAST_ACTION="$(vpn_auto_json_get_string "$json" last_action)"
  VPN_AUTO_STATE_LAST_ERROR="$(vpn_auto_json_get_string "$json" last_error)"
  VPN_AUTO_STATE_LAST_PROTOCOL="$(vpn_auto_json_get_string "$json" last_protocol)"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_FROM="$(vpn_auto_json_get_string "$json" last_protocol_switch_from)"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_TO="$(vpn_auto_json_get_string "$json" last_protocol_switch_to)"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_REASON="$(vpn_auto_json_get_string "$json" last_protocol_switch_reason)"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_EPOCH="$(vpn_auto_json_get_number "$json" last_protocol_switch_epoch)"
}

vpn_auto_state_save() {
  local file dir
  file="$(vpn_auto_state_file 2>/dev/null || printf '')"
  if [[ -z "$file" ]]; then
    return 1
  fi
  dir="$(dirname -- "$file")"
  ensure_dir_mode "$dir" "$DATA_DIR_MODE"
  local now
  now="$(vpn_auto_now_epoch)"
  local json
  if vpn_auto_has_jq; then
    json="$({
      jq -nc \
        --argjson version "$VPN_AUTO_STATE_SCHEMA_VERSION" \
        --arg last_status "${VPN_AUTO_STATE_LAST_STATUS:-}" \
        --arg last_detail "${VPN_AUTO_STATE_LAST_DETAIL:-}" \
        --arg last_public_ip "${VPN_AUTO_STATE_LAST_PUBLIC_IP:-}" \
        --argjson last_forward_port "${VPN_AUTO_STATE_LAST_FORWARD_PORT:-0}" \
        --argjson last_qbt_port "${VPN_AUTO_STATE_LAST_QBT_PORT:-0}" \
        --argjson last_check_epoch "${VPN_AUTO_STATE_LAST_CHECK_EPOCH:-0}" \
        --argjson last_healthy_epoch "${VPN_AUTO_STATE_LAST_HEALTHY_EPOCH:-0}" \
        --argjson last_port_success_epoch "${VPN_AUTO_STATE_LAST_PORT_SUCCESS_EPOCH:-0}" \
        --argjson port_missing_since_epoch "${VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH:-0}" \
        --argjson consecutive_failures "${VPN_AUTO_STATE_CONSECUTIVE_FAILURES:-0}" \
        --argjson last_recovery_epoch "${VPN_AUTO_STATE_LAST_RECOVERY_EPOCH:-0}" \
        --argjson last_control_restart_epoch "${VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH:-0}" \
        --argjson last_container_restart_epoch "${VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH:-0}" \
        --argjson cooldown_until_epoch "${VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH:-0}" \
        --argjson pending_port_sync "${VPN_AUTO_STATE_PENDING_PORT_SYNC:-0}" \
        --arg last_action "${VPN_AUTO_STATE_LAST_ACTION:-}" \
        --arg last_error "${VPN_AUTO_STATE_LAST_ERROR:-}" \
        --arg last_protocol "${VPN_AUTO_STATE_LAST_PROTOCOL:-}" \
        --arg last_protocol_switch_from "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_FROM:-}" \
        --arg last_protocol_switch_to "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_TO:-}" \
        --arg last_protocol_switch_reason "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_REASON:-}" \
        --argjson last_protocol_switch_epoch "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_EPOCH:-0}" \
        --argjson updated "$now" \
        '{version:$version,updated:$updated,last_status:$last_status,last_detail:$last_detail,last_public_ip:$last_public_ip,last_forward_port:$last_forward_port,last_qbt_port:$last_qbt_port,last_check_epoch:$last_check_epoch,last_healthy_epoch:$last_healthy_epoch,last_port_success_epoch:$last_port_success_epoch,port_missing_since_epoch:$port_missing_since_epoch,consecutive_failures:$consecutive_failures,last_recovery_epoch:$last_recovery_epoch,last_control_restart_epoch:$last_control_restart_epoch,last_container_restart_epoch:$last_container_restart_epoch,cooldown_until_epoch:$cooldown_until_epoch,pending_port_sync:$pending_port_sync,last_action:$last_action,last_error:$last_error,last_protocol:$last_protocol,last_protocol_switch_from:$last_protocol_switch_from,last_protocol_switch_to:$last_protocol_switch_to,last_protocol_switch_reason:$last_protocol_switch_reason,last_protocol_switch_epoch:$last_protocol_switch_epoch}'
    } 2>/dev/null)"
  fi
  if [[ -z "$json" ]]; then
    json=$({
      cat <<JSON
{
  "version": ${VPN_AUTO_STATE_SCHEMA_VERSION},
  "updated": $now,
  "last_status": "${VPN_AUTO_STATE_LAST_STATUS:-}",
  "last_detail": "${VPN_AUTO_STATE_LAST_DETAIL:-}",
  "last_public_ip": "${VPN_AUTO_STATE_LAST_PUBLIC_IP:-}",
  "last_forward_port": ${VPN_AUTO_STATE_LAST_FORWARD_PORT:-0},
  "last_qbt_port": ${VPN_AUTO_STATE_LAST_QBT_PORT:-0},
  "last_check_epoch": ${VPN_AUTO_STATE_LAST_CHECK_EPOCH:-0},
  "last_healthy_epoch": ${VPN_AUTO_STATE_LAST_HEALTHY_EPOCH:-0},
  "last_port_success_epoch": ${VPN_AUTO_STATE_LAST_PORT_SUCCESS_EPOCH:-0},
  "port_missing_since_epoch": ${VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH:-0},
  "consecutive_failures": ${VPN_AUTO_STATE_CONSECUTIVE_FAILURES:-0},
  "last_recovery_epoch": ${VPN_AUTO_STATE_LAST_RECOVERY_EPOCH:-0},
  "last_control_restart_epoch": ${VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH:-0},
  "last_container_restart_epoch": ${VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH:-0},
  "cooldown_until_epoch": ${VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH:-0},
  "pending_port_sync": ${VPN_AUTO_STATE_PENDING_PORT_SYNC:-0},
  "last_action": "${VPN_AUTO_STATE_LAST_ACTION:-}",
  "last_error": "${VPN_AUTO_STATE_LAST_ERROR:-}",
  "last_protocol": "${VPN_AUTO_STATE_LAST_PROTOCOL:-}",
  "last_protocol_switch_from": "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_FROM:-}",
  "last_protocol_switch_to": "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_TO:-}",
  "last_protocol_switch_reason": "${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_REASON:-}",
  "last_protocol_switch_epoch": ${VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_EPOCH:-0}
}
JSON
    } 2>/dev/null)
  fi
  printf '%s\n' "$json" >"$file"
  ensure_secret_file_mode "$file"
}

vpn_auto_write_status() {
  local status="$1"
  local detail="$2"
  local extra_public_ip="$3"
  local extra_forward_port="$4"
  local extra_qbt_port="$5"
  local dir file
  file="$(vpn_auto_status_file)"
  dir="$(dirname -- "$file")"
  ensure_dir "$dir"
  local now_iso
  now_iso="$(vpn_auto_iso_now)"
  local payload
  if vpn_auto_has_jq; then
    payload="$({
      jq -nc \
        --arg timestamp "$now_iso" \
        --arg status "$status" \
        --arg detail "$detail" \
        --arg public_ip "${extra_public_ip:-}" \
        --argjson forwarded_port "${extra_forward_port:-0}" \
        --argjson qbt_port "${extra_qbt_port:-0}" \
        --argjson consecutive_failures "${VPN_AUTO_STATE_CONSECUTIVE_FAILURES:-0}" \
        --arg last_action "${VPN_AUTO_STATE_LAST_ACTION:-}" \
        --arg last_error "${VPN_AUTO_STATE_LAST_ERROR:-}" \
        --arg last_recovery "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_RECOVERY_EPOCH:-0}")" \
        --arg port_missing_since "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH:-0}")" \
        --arg cooldown_until "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH:-0}")" \
        --arg last_control "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH:-0}")" \
        --arg last_container "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH:-0}")" \
        '{timestamp:$timestamp,status:$status,detail:$detail,public_ip:($public_ip==""?null:$public_ip),forwarded_port:$forwarded_port,qbt_port:$qbt_port,consecutive_failures:$consecutive_failures,last_action:$last_action,last_error:($last_error==""?null:$last_error),last_recovery:($last_recovery==""?null:$last_recovery),cooldown_until:($cooldown_until==""?null:$cooldown_until),last_control_restart:($last_control==""?null:$last_control),last_container_restart:($last_container==""?null:$last_container),port_missing_since:($port_missing_since==""?null:$port_missing_since)}'
    } 2>/dev/null)"
  fi
  if [[ -z "$payload" ]]; then
    payload=$({
      cat <<JSON
{
  "timestamp": "${now_iso}",
  "status": "${status}",
  "detail": "${detail}",
  "public_ip": "${extra_public_ip:-}",
  "forwarded_port": ${extra_forward_port:-0},
  "qbt_port": ${extra_qbt_port:-0},
  "consecutive_failures": ${VPN_AUTO_STATE_CONSECUTIVE_FAILURES:-0},
  "last_action": "${VPN_AUTO_STATE_LAST_ACTION:-}",
  "last_error": "${VPN_AUTO_STATE_LAST_ERROR:-}",
  "last_recovery": "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_RECOVERY_EPOCH:-0}")",
  "cooldown_until": "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_COOLDOWN_UNTIL_EPOCH:-0}")",
  "last_control_restart": "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_CONTROL_RESTART_EPOCH:-0}")",
  "last_container_restart": "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_LAST_CONTAINER_RESTART_EPOCH:-0}")",
  "port_missing_since": "$(vpn_auto_epoch_to_iso "${VPN_AUTO_STATE_PORT_MISSING_SINCE_EPOCH:-0}")"
}
JSON
    } 2>/dev/null)
  fi
  printf '%s\n' "$payload" >"$file"
  ensure_nonsecret_file_mode "$file"
}

vpn_auto_state_record_protocol_switch() {
  local from="$1"
  local to="$2"
  local reason="$3"
  local epoch
  epoch="$(vpn_auto_now_epoch)"

  VPN_AUTO_STATE_LAST_PROTOCOL="$to"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_FROM="$from"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_TO="$to"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_REASON="$reason"
  VPN_AUTO_STATE_LAST_PROTOCOL_SWITCH_EPOCH="$epoch"
  VPN_AUTO_STATE_LAST_ACTION="protocol-switch"
}

vpn_auto_append_history() {
  local action="$1"
  local status="$2"
  local detail="$3"
  local file
  file="$(vpn_auto_history_file 2>/dev/null || printf '')"
  if [[ -z "$file" ]]; then
    return 0
  fi
  local dir
  dir="$(dirname -- "$file")"
  ensure_dir_mode "$dir" "$DATA_DIR_MODE"
  local ts
  ts="$(vpn_auto_iso_now)"
  local entry=""
  # JSON audit:
  # - Serialize history entries with jq to guarantee valid escaping of arbitrary detail text.
  if ! vpn_auto_has_jq; then
    return 0
  fi
  if ! entry="$({
    jq -nc \
      --arg ts "${ts}" \
      --arg action "${action}" \
      --arg status "${status}" \
      --arg detail "${detail}" \
      --argjson failures "${VPN_AUTO_STATE_CONSECUTIVE_FAILURES:-0}" \
      '{ts:$ts,action:$action,status:$status,detail:($detail==""?null:$detail),consecutive_failures:$failures}'
  } 2>/dev/null)"; then
    return 0
  fi
  printf '%s\n' "${entry}" >>"${file}"
  ensure_nonsecret_file_mode "$file"
  local limit="${VPN_AUTO_HISTORY_MAX_LINES:-500}"
  if [[ "$limit" =~ ^[0-9]+$ ]] && ((limit > 0)); then
    local current
    current=$(wc -l <"$file" 2>/dev/null || printf '0')
    if [[ "$current" =~ ^[0-9]+$ ]] && ((current > limit)); then
      tail -n "$limit" "$file" >"${file}.tmp" 2>/dev/null && mv "${file}.tmp" "$file"
    fi
  fi
}

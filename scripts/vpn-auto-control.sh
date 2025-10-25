# shellcheck shell=bash
# Purpose: Execute reconnect attempts, apply jitter/backoff, and coordinate Gluetun restarts.
# Inputs: Depends on metrics helpers, Docker CLI, VPN rotation settings, and qBittorrent credentials.
# Outputs: Logs reconnect actions, updates status/state files, and triggers VPN container restarts when needed.
# Exit codes: Functions return non-zero when reconnect attempts fail or health checks time out.
if [[ -n "${__VPN_AUTO_CONTROL_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_CONTROL_LOADED=1

vpn_auto_reconnect_apply_jitter_delay() {
  local jitter
  jitter="$(vpn_auto_reconnect_jitter_seconds)"
  [[ "$jitter" =~ ^[0-9]+$ ]] || jitter=0
  if ((jitter <= 0)); then
    VPN_AUTO_STATE_JITTER_APPLIED=0
    return 0
  fi
  local delay
  delay=$((RANDOM % (jitter + 1)))
  VPN_AUTO_STATE_JITTER_APPLIED="$delay"
  if ((delay > 0)); then
    sleep "$delay"
  fi
  return 0
}

# Issues OpenVPN cycle via Gluetun control API and records result
vpn_auto_reconnect_restart_gluetun() {
  if ! command -v docker >/dev/null 2>&1; then
    log_warn "VPN auto cannot restart Gluetun: docker command missing"
    return 1
  fi
  if ! docker inspect gluetun >/dev/null 2>&1; then
    log_warn "VPN auto cannot restart Gluetun: container not found"
    return 1
  fi
  if ! docker restart gluetun >/dev/null 2>&1; then
    log_warn "VPN auto failed to restart Gluetun"
    return 1
  fi
  return 0
}

# Waits for Gluetun health and public IP endpoints to report success
vpn_auto_reconnect_wait_for_health() {
  local timeout=120
  local interval=5
  local elapsed=0
  local host="${LOCALHOST_IP:-127.0.0.1}"
  local port="${GLUETUN_CONTROL_PORT:-8000}"
  local url
  if [[ $host == *:* && $host != [* ]]; then
    url="http://[$host]:${port}/v1/openvpn/status"
  else
    url="http://${host}:${port}/v1/openvpn/status"
  fi
  if ! command -v docker >/dev/null 2>&1; then
    log_warn "VPN auto cannot confirm Gluetun health: docker command missing"
    return 1
  fi

  local curl_available=1
  local -a curl_cmd=()
  if command -v curl >/dev/null 2>&1; then
    curl_cmd=(curl -fsS --max-time 5)
    if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
      curl_cmd+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
    fi
  else
    curl_available=0
    if [[ "${VPN_AUTO_RECONNECT_CURL_WARNED:-0}" -eq 0 ]]; then
      log_warn "VPN auto skipping Gluetun API verification: curl not available"
      VPN_AUTO_RECONNECT_CURL_WARNED=1
    fi
  fi

  while ((elapsed < timeout)); do
    local status
    status="$(docker inspect --format '{{.State.Health.Status}}' gluetun 2>/dev/null || printf '')"
    if [[ "$status" == "healthy" ]]; then
      if ((curl_available == 0)); then
        return 0
      fi
      if "${curl_cmd[@]}" "$url" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done
  log_warn "VPN auto health endpoint did not respond within ${timeout}s"
  return 1
}

# Applies selected VPN country via Gluetun API before reconnect attempt
vpn_auto_reconnect_apply_country() {
  local country="$1"
  if [[ -z "$country" ]]; then
    return 1
  fi
  local sanitized=""
  if ! sanitized="$(vpn_auto_reconnect_sanitize_country_csv "$country" 2>/dev/null)" || [[ -z "$sanitized" ]]; then
    # Fall back to the current configuration or a conservative default when input is invalid.
    sanitized="$(vpn_auto_reconnect_sanitize_country_csv "${SERVER_COUNTRIES:-}" 2>/dev/null || printf '')"
    if [[ -z "$sanitized" ]]; then
      sanitized="Netherlands"
    fi
  fi
  persist_env_var "SERVER_COUNTRIES" "$sanitized"
  VPN_AUTO_STATE_LAST_COUNTRY="${sanitized%%,*}"
}

# Executes full reconnect flow including jitter, API calls, and state updates
vpn_auto_reconnect_attempt() {
  local country="$1"
  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  local pre_attempt_low="${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0}"
  VPN_AUTO_STATE_JITTER_APPLIED=0

  local min_interval=300
  if [[ -n "${VPN_AUTO_STATE_LAST_RECONNECT:-}" ]]; then
    local last_epoch
    last_epoch="$(vpn_auto_reconnect_iso_to_epoch "$VPN_AUTO_STATE_LAST_RECONNECT" || echo 0)"
    [[ "$last_epoch" =~ ^[0-9]+$ ]] || last_epoch=0
    if ((now - last_epoch < min_interval)); then
      local wait_time=$((min_interval - (now - last_epoch)))
      vpn_auto_reconnect_set_next_action $((last_epoch + min_interval))
      vpn_auto_reconnect_write_status "throttled" "Rate limit: wait ${wait_time}s before next attempt"
      vpn_auto_reconnect_append_history "skip" "$country" "false" "rate-limit" "$pre_attempt_low" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "${VPN_AUTO_STATE_CLASSIFICATION:-failure}"
      return 1
    fi
  fi
  if ! vpn_auto_reconnect_apply_country "$country"; then
    vpn_auto_reconnect_write_status "error" "Failed to update SERVER_COUNTRIES"
    vpn_auto_reconnect_append_history "attempt" "$country" "false" "apply-country" "$pre_attempt_low" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "${VPN_AUTO_STATE_CLASSIFICATION:-failure}"
    return 1
  fi
  # Apply jitter immediately before restarting to avoid herd behaviour.
  vpn_auto_reconnect_apply_jitter_delay
  if ! vpn_auto_reconnect_restart_gluetun; then
    vpn_auto_reconnect_failure_history_update "$country" "$now"
    VPN_AUTO_STATE_RESTART_FAILURES=$((${VPN_AUTO_STATE_RESTART_FAILURES:-0} + 1))
    vpn_auto_reconnect_write_status "error" "Gluetun restart failed"
    vpn_auto_reconnect_append_history "attempt" "$country" "false" "restart-failed" "$pre_attempt_low" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "${VPN_AUTO_STATE_CLASSIFICATION:-failure}"
    if ((VPN_AUTO_STATE_RESTART_FAILURES >= 3)); then
      VPN_AUTO_STATE_AUTO_DISABLED=1
      VPN_AUTO_STATE_DISABLED_UNTIL=$((now + $(vpn_auto_reconnect_cooldown_seconds)))
      VPN_AUTO_STATE_LAST_STATUS="Auto-disabled after repeated restart failures"
      vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_DISABLED_UNTIL"
      vpn_auto_reconnect_write_status "disabled" "Repeated restart failures; touch .vpn-auto-reconnect-once to override"
      VPN_AUTO_RECONNECT_SUPPRESS_RETRY=1
    fi
    return 1
  fi
  VPN_AUTO_STATE_RESTART_FAILURES=0
  if ! vpn_auto_reconnect_wait_for_health; then
    vpn_auto_reconnect_failure_history_update "$country" "$now"
    vpn_auto_reconnect_write_status "error" "VPN health check failed"
    vpn_auto_reconnect_append_history "attempt" "$country" "false" "health-check" "$pre_attempt_low" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "${VPN_AUTO_STATE_CLASSIFICATION:-failure}"
    return 1
  fi
  VPN_AUTO_STATE_LAST_RECONNECT="$(vpn_auto_reconnect_epoch_to_iso "$now" || printf '')"
  VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  VPN_AUTO_STATE_COOLDOWN_UNTIL=$((now + $(vpn_auto_reconnect_cooldown_seconds)))
  VPN_AUTO_STATE_RETRY_BACKOFF=5
  VPN_AUTO_STATE_RETRY_TOTAL=0
  VPN_AUTO_STATE_AUTO_DISABLED=0
  VPN_AUTO_STATE_LAST_STATUS="Reconnected to ${country}"
  vpn_auto_reconnect_register_rotation_success
  vpn_auto_reconnect_failure_history_clear "$country"
  vpn_auto_reconnect_resync_pf
  vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_COOLDOWN_UNTIL"
  VPN_AUTO_STATE_CLASSIFICATION="busy"
  vpn_auto_reconnect_write_status "reconnected" "Reconnected to ${country} (PF worker resync triggered)"
  vpn_auto_reconnect_append_history "attempt" "$country" "true" "reconnected" "$pre_attempt_low" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "${VPN_AUTO_STATE_CLASSIFICATION:-failure}"
  return 0
}

# Implements exponential backoff and disables feature when retry budget exhausted
vpn_auto_reconnect_handle_retry_failure() {
  local backoff="${VPN_AUTO_STATE_RETRY_BACKOFF:-5}"
  [[ "$backoff" =~ ^[0-9]+$ ]] || backoff=5
  local total="${VPN_AUTO_STATE_RETRY_TOTAL:-0}"
  [[ "$total" =~ ^[0-9]+$ ]] || total=0
  total=$((total + backoff))
  VPN_AUTO_STATE_RETRY_TOTAL="$total"
  local max_minutes
  max_minutes="$(vpn_auto_reconnect_max_retry_minutes)"
  local next_seconds=$((backoff * 60))
  vpn_auto_reconnect_set_next_action $(($(vpn_auto_reconnect_now_epoch) + next_seconds))
  if ((backoff < max_minutes)); then
    local next=$((backoff * 2))
    if ((next > max_minutes)); then
      next=$max_minutes
    fi
    VPN_AUTO_STATE_RETRY_BACKOFF="$next"
  fi
  if ((total >= max_minutes)); then
    VPN_AUTO_STATE_AUTO_DISABLED=1
    VPN_AUTO_STATE_DISABLED_UNTIL=$(($(vpn_auto_reconnect_now_epoch) + $(vpn_auto_reconnect_cooldown_seconds)))
    VPN_AUTO_STATE_LAST_STATUS="Auto-disabled after retry budget exhausted"
    vpn_auto_reconnect_write_status "disabled" "Retry budget exceeded; touch .vpn-auto-reconnect-once to override"
    vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_DISABLED_UNTIL"
  fi
}

# Evaluates all gating conditions to decide if reconnect should run now
vpn_auto_reconnect_should_attempt() {
  local force="${1:-0}"

  vpn_auto_reconnect_set_next_action 0
  VPN_AUTO_STATE_CLASSIFICATION="monitoring"

  if vpn_auto_reconnect_manual_pause_active; then
    vpn_auto_reconnect_write_status "paused" "Pause file present"
    return 1
  fi

  if ((force == 0)) && ! vpn_auto_reconnect_is_enabled; then
    vpn_auto_reconnect_write_status "disabled" "VPN_AUTO_RECONNECT_ENABLED=0"
    return 1
  fi

  if ((force == 0)) && vpn_auto_reconnect_kill_active; then
    vpn_auto_reconnect_write_status "paused" "24h kill switch active"
    return 1
  fi

  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  local disabled_until="${VPN_AUTO_STATE_DISABLED_UNTIL:-0}"
  [[ "$disabled_until" =~ ^[0-9]+$ ]] || disabled_until=0

  if ((force == 0)) && ((disabled_until > now)); then
    vpn_auto_reconnect_write_status "cooldown" "Auto-reconnect disabled until $(vpn_auto_reconnect_epoch_to_iso "$disabled_until" || printf '')"
    return 1
  fi

  if ((force == 0)) && ((VPN_AUTO_STATE_AUTO_DISABLED == 1)); then
    vpn_auto_reconnect_write_status "disabled" "Auto-disabled; create .vpn-auto-reconnect-once to override"
    vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_DISABLED_UNTIL"
    return 1
  fi

  # Only attempt reconnects when inside an explicitly configured window.
  if ((force == 0)) && vpn_auto_reconnect_inside_allowed_window; then
    vpn_auto_reconnect_write_status "waiting" "Outside allowed window"
    VPN_AUTO_STATE_CLASSIFICATION="idle"
    return 1
  fi

  if ((force == 0)) && ((VPN_AUTO_STATE_COOLDOWN_UNTIL > now)); then
    vpn_auto_reconnect_write_status "cooldown" "Cooling down until $(vpn_auto_reconnect_epoch_to_iso "$VPN_AUTO_STATE_COOLDOWN_UNTIL" || printf '')"
    vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_COOLDOWN_UNTIL"
    return 1
  fi

  return 0
}

# Single iteration of worker loop handling force flags, reconnect logic, and persistence
vpn_auto_reconnect_process_once() {
  vpn_auto_reconnect_load_env
  vpn_auto_reconnect_reset_rotation_window
  vpn_auto_reconnect_load_state
  VPN_AUTO_RECONNECT_SUPPRESS_RETRY=0
  local force=0
  if vpn_auto_reconnect_force_once_requested; then
    force=1
  fi

  if ! vpn_auto_reconnect_should_attempt "$force"; then
    vpn_auto_reconnect_write_state
    return 0
  fi

  if ((force)); then
    vpn_auto_reconnect_consume_force_once_flag
    VPN_AUTO_STATE_AUTO_DISABLED=0
    VPN_AUTO_STATE_DISABLED_UNTIL=0
    vpn_auto_reconnect_write_status "forcing" "One-shot reconnect override active"
  fi

  local transfer
  transfer="$(vpn_auto_reconnect_fetch_transfer_info || printf '')"
  if [[ -z "$transfer" ]]; then
    VPN_AUTO_STATE_CLASSIFICATION="busy"
    vpn_auto_reconnect_write_status "error" "Failed to query qBittorrent speeds"
    vpn_auto_reconnect_write_state
    return 1
  fi

  if ! vpn_auto_has_jq; then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
    VPN_AUTO_STATE_CLASSIFICATION="monitoring"
    if ((VPN_AUTO_RECONNECT_JQ_WARNED == 0)); then
      VPN_AUTO_RECONNECT_JQ_WARNED=1
      VPN_AUTO_STATE_LAST_STATUS="jq missing; auto-reconnect paused"
      vpn_auto_reconnect_write_status "degraded" "jq missing; auto-reconnect paused"
    fi
    vpn_auto_reconnect_write_state
    return 0
  fi
  VPN_AUTO_RECONNECT_JQ_WARNED=0

  local dl_speed
  local up_speed
  dl_speed="$(jq -r '.dl_info_speed // 0' <<<"$transfer" 2>/dev/null || printf '0')"
  up_speed="$(jq -r '.up_info_speed // 0' <<<"$transfer" 2>/dev/null || printf '0')"
  [[ "$dl_speed" =~ ^[0-9]+$ ]] || dl_speed=0
  [[ "$up_speed" =~ ^[0-9]+$ ]] || up_speed=0
  local total_speed=$((dl_speed + up_speed))
  local threshold
  threshold="$(vpn_auto_reconnect_speed_threshold_bytes)"
  local status_detail="Down ${dl_speed} B/s, Up ${up_speed} B/s"

  local now_epoch
  now_epoch="$(vpn_auto_reconnect_now_epoch)"
  local previous_low="${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0}"
  [[ "$previous_low" =~ ^[0-9]+$ ]] || previous_low=0
  if ((total_speed < threshold)); then
    if ((previous_low == 0)); then
      vpn_auto_reconnect_record_low "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    fi
    VPN_AUTO_STATE_CONSECUTIVE_LOW=$((previous_low + 1))
  else
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  fi

  local explicit_activity=0
  if vpn_auto_reconnect_detect_activity; then
    explicit_activity=1
  fi
  if ((dl_speed > 1048576 || up_speed > 1048576)); then
    explicit_activity=1
  fi
  if vpn_auto_reconnect_high_load_detected; then
    explicit_activity=1
  fi

  local active_download
  local active_upload
  local active_combined
  active_download="$(jq -r '.active_download_count // 0' <<<"$transfer" 2>/dev/null || printf '0')"
  active_upload="$(jq -r '.active_upload_count // 0' <<<"$transfer" 2>/dev/null || printf '0')"
  active_combined=$((active_download + active_upload))
  if ((active_combined == 0)); then
    active_combined="$(jq -r '.active_torrents_count // 0' <<<"$transfer" 2>/dev/null || printf '0')"
  fi
  if [[ ! "$active_combined" =~ ^[0-9]+$ ]]; then
    active_combined=0
  fi

  local last_activity_epoch=0
  if [[ -n "${VPN_AUTO_STATE_LAST_ACTIVITY:-}" ]]; then
    last_activity_epoch="$(vpn_auto_reconnect_iso_to_epoch "$VPN_AUTO_STATE_LAST_ACTIVITY" || printf '0')"
  fi
  [[ "$last_activity_epoch" =~ ^[0-9]+$ ]] || last_activity_epoch=0
  local recent_activity=0
  if ((last_activity_epoch > 0 && now_epoch - last_activity_epoch <= VPN_AUTO_RECONNECT_ACTIVITY_GRACE_SECONDS)); then
    recent_activity=1
  fi
  if ((explicit_activity)); then
    recent_activity=1
  fi

  local last_low_epoch=0
  if [[ -n "${VPN_AUTO_STATE_LAST_LOW:-}" ]]; then
    last_low_epoch="$(vpn_auto_reconnect_iso_to_epoch "$VPN_AUTO_STATE_LAST_LOW" || printf '0')"
  fi
  [[ "$last_low_epoch" =~ ^[0-9]+$ ]] || last_low_epoch=0

  # Determine the coarse classification before applying failure heuristics.
  local classification="low"
  if ((total_speed >= threshold)); then
    classification="busy"
  elif ((recent_activity)); then
    classification="busy"
  elif ((active_combined == 0 && last_low_epoch > 0 && now_epoch - last_low_epoch >= VPN_AUTO_RECONNECT_IDLE_GRACE_SECONDS)); then
    classification="idle"
  fi

  local required
  required="$(vpn_auto_reconnect_consecutive_required)"
  [[ "$required" =~ ^[0-9]+$ ]] || required=3
  if ((force)); then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=$required
    classification="failure"
  fi

  if [[ "$classification" == "busy" ]]; then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
    VPN_AUTO_STATE_CLASSIFICATION="busy"
    vpn_auto_reconnect_write_status "busy" "${status_detail} (activity detected)"
    vpn_auto_reconnect_write_state
    return 0
  fi

  if [[ "$classification" == "idle" ]]; then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
    VPN_AUTO_STATE_CLASSIFICATION="idle"
    vpn_auto_reconnect_write_status "idle" "${status_detail} (idle; awaiting demand)"
    vpn_auto_reconnect_write_state
    return 0
  fi

  local pf_snapshot
  pf_snapshot="$(vpn_auto_reconnect_pf_status_snapshot)"
  local pf_status="$pf_snapshot"
  local pf_last_success=""
  if [[ "$pf_snapshot" == *"|"* ]]; then
    pf_status="${pf_snapshot%%|*}"
    pf_last_success="${pf_snapshot#*|}"
  fi
  local pf_last_epoch=0
  if [[ -n "$pf_last_success" ]]; then
    pf_last_epoch="$(vpn_auto_reconnect_iso_to_epoch "$pf_last_success" || printf '0')"
  fi
  [[ "$pf_last_epoch" =~ ^[0-9]+$ ]] || pf_last_epoch=0
  local pf_recent_success=0
  if ((pf_last_epoch > 0 && now_epoch - pf_last_epoch <= VPN_AUTO_RECONNECT_PF_SUCCESS_GRACE)); then
    pf_recent_success=1
  fi
  local pf_status_lc="${pf_status,,}"
  local pf_acquired=0
  if [[ "$pf_status_lc" == "acquired" ]]; then
    pf_acquired=1
  fi
  if ((pf_recent_success)); then
    pf_acquired=1
  fi

  local seeding_floor="${VPN_AUTO_RECONNECT_SEEDING_FLOOR_BYTES:-0}"
  [[ "$seeding_floor" =~ ^[0-9]+$ ]] || seeding_floor=0
  local failure_candidate=0
  if ((force)); then
    failure_candidate=1
  elif ((VPN_AUTO_STATE_CONSECUTIVE_LOW >= required)) && ((up_speed <= seeding_floor)) && ((pf_acquired == 0)); then
    failure_candidate=1
  fi
  if ((failure_candidate)); then
    classification="failure"
  fi

  VPN_AUTO_STATE_CLASSIFICATION="$classification"

  if [[ "$classification" != "failure" ]]; then
    local remaining=$((required - VPN_AUTO_STATE_CONSECUTIVE_LOW))
    if ((remaining < 0)); then
      remaining=0
    fi
    vpn_auto_reconnect_write_status "monitoring" "${status_detail} (consecutive_low=${VPN_AUTO_STATE_CONSECUTIVE_LOW}/${required})"
    vpn_auto_reconnect_write_state
    return 0
  fi

  # Cap guard – enforce VPN_ROTATION_MAX_PER_DAY unless forced.
  if vpn_auto_reconnect_daily_cap_exceeded "$force"; then
    local cap
    cap="$(vpn_auto_reconnect_rotation_cap)"
    vpn_auto_reconnect_reset_rotation_window
    local next_day=$((${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0} + 86400))
    vpn_auto_reconnect_set_next_action "$next_day"
    vpn_auto_reconnect_write_status "waiting" "Daily rotation cap reached (${VPN_AUTO_STATE_ROTATION_COUNT_DAY}/${cap})"
    vpn_auto_reconnect_append_history "skip" "" "false" "cap" "${VPN_AUTO_STATE_CONSECUTIVE_LOW}" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "$classification"
    vpn_auto_reconnect_write_state
    return 0
  fi

  local country
  if ! country="$(vpn_auto_reconnect_pick_country)"; then
    vpn_auto_reconnect_write_status "error" "No Proton countries available"
    vpn_auto_reconnect_append_history "skip" "" "false" "no-country" "${VPN_AUTO_STATE_CONSECUTIVE_LOW}" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "$classification"
    vpn_auto_reconnect_write_state
    return 1
  fi

  if ! vpn_auto_reconnect_attempt "$country"; then
    if ((VPN_AUTO_RECONNECT_SUPPRESS_RETRY == 0)); then
      vpn_auto_reconnect_handle_retry_failure
    else
      VPN_AUTO_RECONNECT_SUPPRESS_RETRY=0
    fi
    vpn_auto_reconnect_write_state
    return 1
  fi

  vpn_auto_reconnect_write_state
  return 0
}

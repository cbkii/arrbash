# shellcheck shell=bash
# Purpose: Execute reconnect attempts, apply jitter/backoff, and coordinate Gluetun restarts.
# Inputs: Depends on metrics helpers, Docker CLI, VPN rotation settings, and qBittorrent credentials.
# Outputs: Logs reconnect actions, updates status/state files, and triggers VPN container restarts when needed.
# Exit codes: Functions return non-zero when reconnect attempts fail or health checks time out.
if [[ -n "${__VPN_AUTO_CONTROL_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_CONTROL_LOADED=1

VPN_AUTO_HEALTH_STATUS=""
VPN_AUTO_HEALTH_IP=""
VPN_AUTO_HEALTH_PORT=0
VPN_AUTO_HEALTH_REASON=""

# ProtonVPN deployments expect port forwarding; flag the requirement centrally.
vpn_auto_reconnect_forwarding_expected() {
  [[ "${VPN_SERVICE_PROVIDER:-}" == "protonvpn" && "${VPN_PORT_FORWARDING:-on}" == "on" ]]
}

# Query Gluetun's control server for the OpenVPN status using the documented API.
# Earlier revisions shell'd out to `docker inspect` which missed the control plane
# entirely and failed when Gluetun changed its healthcheck names. The control
# server is now the single source of truth.
vpn_auto_reconnect_gluetun_status() {
  local payload=""
  payload="$(gluetun_control_get "/v1/openvpn/status" 2>/dev/null || printf '')"
  if [[ -z "$payload" ]]; then
    return 1
  fi

  local status=""
  if command -v jq >/dev/null 2>&1; then
    status="$(printf '%s' "$payload" | jq -r '.status // empty' 2>/dev/null || printf '')"
  fi

  if [[ -z "$status" ]]; then
    status="$(printf '%s' "$payload" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1 || printf '')"
  fi

  [[ -n "$status" ]] || return 1
  printf '%s' "$status"
}

# Wrapper for fetch_public_ip so health checks can call it without duplicating
# the IPv4/IPv6 parsing logic already centralised in gluetun.sh.
vpn_auto_reconnect_public_ip() {
  fetch_public_ip 2>/dev/null || printf ''
}

# Wrapper for fetch_forwarded_port with numeric validation.
vpn_auto_reconnect_forwarded_port() {
  local value
  value="$(fetch_forwarded_port 2>/dev/null || printf '0')"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    value=0
  fi
  printf '%s' "$value"
}

# Collect Gluetun health data with short retries to avoid flapping on a single
# transient failure. Results populate VPN_AUTO_HEALTH_* globals.
vpn_auto_reconnect_health_snapshot() {
  VPN_AUTO_HEALTH_STATUS=""
  VPN_AUTO_HEALTH_IP=""
  VPN_AUTO_HEALTH_PORT=0
  VPN_AUTO_HEALTH_REASON=""

  local attempts=0
  local max_attempts=3
  local require_port=0
  if vpn_auto_reconnect_forwarding_expected; then
    require_port=1
  fi

  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  local last_reconnect_epoch=0
  if [[ -n "${VPN_AUTO_STATE_LAST_RECONNECT:-}" ]]; then
    last_reconnect_epoch="$(vpn_auto_reconnect_iso_to_epoch "$VPN_AUTO_STATE_LAST_RECONNECT" || printf '0')"
  fi
  [[ "$last_reconnect_epoch" =~ ^[0-9]+$ ]] || last_reconnect_epoch=0

  while ((attempts < max_attempts)); do
    local status
    status="$(vpn_auto_reconnect_gluetun_status 2>/dev/null || printf '')"
    local public_ip
    public_ip="$(vpn_auto_reconnect_public_ip || printf '')"
    local forwarded_port
    forwarded_port="$(vpn_auto_reconnect_forwarded_port)"

    if [[ -n "$status" ]]; then
      VPN_AUTO_HEALTH_STATUS="$status"
    fi
    if [[ -n "$public_ip" ]]; then
      VPN_AUTO_HEALTH_IP="$public_ip"
    fi
    VPN_AUTO_HEALTH_PORT="$forwarded_port"

    local status_ok=0
    if [[ "$status" == "running" ]]; then
      status_ok=1
    fi

    local ip_ok=0
    if [[ -n "$public_ip" ]]; then
      ip_ok=1
    fi

    local port_ok=1
    if ((require_port)); then
      if ((forwarded_port > 0)); then
        port_ok=1
      else
        port_ok=0
        if ((last_reconnect_epoch > 0 && now - last_reconnect_epoch < 180)); then
          port_ok=1
        fi
      fi
    fi

    if ((status_ok && ip_ok && port_ok)); then
      VPN_AUTO_HEALTH_REASON=""
      return 0
    fi

    local reasons=()
    if ((status_ok == 0)); then
      reasons+=("OpenVPN status ${status:-unknown}")
    fi
    if ((ip_ok == 0)); then
      reasons+=("no exit IP")
    fi
    if ((require_port)) && ((port_ok == 0)); then
      reasons+=("forwarded port pending")
    fi
    if ((${#reasons[@]} > 0)); then
      VPN_AUTO_HEALTH_REASON="$(IFS='; '; printf '%s' "${reasons[*]}")"
    else
      VPN_AUTO_HEALTH_REASON="control query failed"
    fi

    attempts=$((attempts + 1))
    if ((attempts < max_attempts)); then
      sleep 3
    fi
  done

  [[ -n "$VPN_AUTO_HEALTH_REASON" ]] || VPN_AUTO_HEALTH_REASON="control server unreachable"
  return 1
}

# Execute the Gluetun port-forward hook inside the container to keep qBittorrent
# aligned with the forwarded port. Running it inside the namespace preserves the
# kill-switch guarantees; previous host-side curls leaked traffic outside Gluetun.
vpn_auto_reconnect_run_pf_hook() {
  local port="$1"
  if [[ -z "$port" ]]; then
    return 1
  fi

  if ! command -v docker >/dev/null 2>&1; then
    warn "VPN auto cannot sync qBittorrent port: docker command missing"
    return 1
  fi

  local container
  container="$(service_container_name gluetun)"

  if ! docker exec "$container" test -x /gluetun/hooks/update-qbt-port.sh >/dev/null 2>&1; then
    warn "VPN auto cannot locate /gluetun/hooks/update-qbt-port.sh inside ${container}"
    return 1
  fi

  if ! docker exec "$container" /gluetun/hooks/update-qbt-port.sh "$port" >/dev/null 2>&1; then
    warn "VPN auto failed to invoke Gluetun port-forward hook"
    return 1
  fi

  return 0
}

# Ensure qBittorrent listens on the forwarded port exposed by Gluetun.
vpn_auto_reconnect_sync_qbt_port() {
  local forwarded
  forwarded="$(vpn_auto_reconnect_forwarded_port)"
  if [[ ! "$forwarded" =~ ^[0-9]+$ ]] || ((forwarded <= 0)); then
    return 0
  fi

  local current=""
  current="$(vpn_auto_reconnect_qbt_listen_port 2>/dev/null || printf '0')"
  if [[ ! "$current" =~ ^[0-9]+$ ]]; then
    current=0
  fi

  if ((current == forwarded)); then
    return 0
  fi

  msg "Forwarded port ${forwarded} differs from qBittorrent listen port ${current}; triggering hook resync"
  vpn_auto_reconnect_run_pf_hook "$forwarded"
}

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

# Restart Gluetun safely using the documented control API first. The old
# implementation called `docker restart gluetun`, bypassed ARR_STACK_DIR, and
# risked reattaching qBittorrent outside the kill switch. We now cycle OpenVPN in
# place and only fall back to Compose when absolutely necessary.
vpn_auto_reconnect_cycle_openvpn() {
  if gluetun_cycle_openvpn; then
    return 0
  fi

  msg "Gluetun control API restart failed; attempting docker compose restart"

  if ! command -v docker >/dev/null 2>&1; then
    warn "VPN auto cannot restart Gluetun: docker command missing"
    return 1
  fi

  if ! restart_stack_service gluetun; then
    warn "VPN auto failed to restart Gluetun via docker compose"
    return 1
  fi

  sleep 5
  return 0
}

# Waits for Gluetun to report a healthy tunnel using the control server.
vpn_auto_reconnect_wait_for_health() {
  local timeout=120
  local interval=5
  local elapsed=0

  while ((elapsed < timeout)); do
    if vpn_auto_reconnect_health_snapshot; then
      return 0
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done

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
    sanitized="$(vpn_auto_reconnect_sanitize_country_csv "${SERVER_COUNTRIES:-}" 2>/dev/null || printf '')"
    if [[ -z "$sanitized" ]]; then
      sanitized="Netherlands"
    fi
  fi

  # Earlier versions rewrote SERVER_COUNTRIES inside .env on every rotation,
  # forcing unnecessary compose churn. Record the choice for status reporting but
  # leave config management to explicit arr.env.* calls.
  # shellcheck disable=SC2034  # exported in status JSON
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
  if ! vpn_auto_reconnect_cycle_openvpn; then
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
    local reason="${VPN_AUTO_HEALTH_REASON:-VPN health check failed}"
    vpn_auto_reconnect_write_status "error" "$reason"
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
  vpn_auto_reconnect_sync_qbt_port || true
  vpn_auto_reconnect_set_next_action "$VPN_AUTO_STATE_COOLDOWN_UNTIL"
  VPN_AUTO_STATE_CLASSIFICATION="busy"
  local summary="Reconnected to ${country}"
  if [[ -n "$VPN_AUTO_HEALTH_IP" ]]; then
    summary+="; exit ${VPN_AUTO_HEALTH_IP}"
  fi
  if ((VPN_AUTO_HEALTH_PORT > 0)); then
    summary+="; forwarded port ${VPN_AUTO_HEALTH_PORT}"
  fi
  vpn_auto_reconnect_write_status "reconnected" "$summary"
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
    # shellcheck disable=SC2034  # surfaced via status writer
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

# Single iteration of worker loop handling force flags, reconnect logic, and persistence.
# Earlier revs guessed tunnel health via qBittorrent throughput and external IP curls,
# which produced false positives and ignored Gluetun's control server. The new flow
# trusts Gluetun's API for status, exit IP, and forwarded port, then falls back to the
# documented stop/start controls when recovery is required.
vpn_auto_reconnect_process_once() {
  vpn_auto_reconnect_load_env
  vpn_auto_reconnect_reset_rotation_window
  vpn_auto_reconnect_load_state
  VPN_AUTO_RECONNECT_SUPPRESS_RETRY=0

  local force=0
  if vpn_auto_reconnect_force_once_requested; then
    force=1
  fi

  local health_ok=0
  local health_detail=""
  if vpn_auto_reconnect_health_snapshot; then
    health_ok=1
    if [[ -n "$VPN_AUTO_HEALTH_STATUS" ]]; then
      health_detail="OpenVPN ${VPN_AUTO_HEALTH_STATUS}"
    fi
    if [[ -n "$VPN_AUTO_HEALTH_IP" ]]; then
      health_detail+="; exit ${VPN_AUTO_HEALTH_IP}"
    fi
    if vpn_auto_reconnect_forwarding_expected && ((VPN_AUTO_HEALTH_PORT > 0)); then
      health_detail+="; forwarded port ${VPN_AUTO_HEALTH_PORT}"
    fi
    health_detail="${health_detail#; }"
  else
    health_detail="${VPN_AUTO_HEALTH_REASON:-control server unreachable}"
  fi

  if ! vpn_auto_reconnect_should_attempt "$force"; then
    if ((force == 0 && health_ok)); then
      vpn_auto_reconnect_sync_qbt_port || true
    fi
    vpn_auto_reconnect_write_state
    return 0
  fi

  if ((force)); then
    vpn_auto_reconnect_consume_force_once_flag
    VPN_AUTO_STATE_AUTO_DISABLED=0
    VPN_AUTO_STATE_DISABLED_UNTIL=0
    vpn_auto_reconnect_write_status "forcing" "One-shot reconnect override active"
  elif ((health_ok)); then
    VPN_AUTO_STATE_CLASSIFICATION="healthy"
    vpn_auto_reconnect_write_status "healthy" "${health_detail:-Gluetun tunnel healthy}"
    vpn_auto_reconnect_sync_qbt_port || true
    vpn_auto_reconnect_write_state
    return 0
  fi

  VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  VPN_AUTO_STATE_CLASSIFICATION="recovering"
  if [[ -n "$health_detail" ]]; then
    vpn_auto_reconnect_write_status "recovering" "Recovering from: ${health_detail}"
  else
    vpn_auto_reconnect_write_status "recovering" "Attempting Gluetun reconnect"
  fi

  if vpn_auto_reconnect_daily_cap_exceeded "$force"; then
    local cap
    cap="$(vpn_auto_reconnect_rotation_cap)"
    vpn_auto_reconnect_reset_rotation_window
    local next_day=$((${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0} + 86400))
    vpn_auto_reconnect_set_next_action "$next_day"
    vpn_auto_reconnect_write_status "waiting" "Daily rotation cap reached (${VPN_AUTO_STATE_ROTATION_COUNT_DAY}/${cap})"
    vpn_auto_reconnect_append_history "skip" "" "false" "cap" "${VPN_AUTO_STATE_CONSECUTIVE_LOW}" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "recovering"
    vpn_auto_reconnect_write_state
    return 0
  fi

  local country
  if ! country="$(vpn_auto_reconnect_pick_country)"; then
    vpn_auto_reconnect_write_status "error" "No Proton countries available"
    vpn_auto_reconnect_append_history "skip" "" "false" "no-country" "${VPN_AUTO_STATE_CONSECUTIVE_LOW}" "${VPN_AUTO_STATE_RETRY_TOTAL}" "${VPN_AUTO_STATE_JITTER_APPLIED}" "recovering"
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

  if ! vpn_auto_reconnect_health_snapshot; then
    health_detail="${VPN_AUTO_HEALTH_REASON:-Reconnected; awaiting Gluetun health}"
    health_ok=0
  else
    health_ok=1
    health_detail="OpenVPN ${VPN_AUTO_HEALTH_STATUS:-running}"
    if [[ -n "$VPN_AUTO_HEALTH_IP" ]]; then
      health_detail+="; exit ${VPN_AUTO_HEALTH_IP}"
    fi
    if vpn_auto_reconnect_forwarding_expected && ((VPN_AUTO_HEALTH_PORT > 0)); then
      health_detail+="; forwarded port ${VPN_AUTO_HEALTH_PORT}"
    fi
    health_detail="${health_detail#; }"
  fi

  if ((health_ok)); then
    VPN_AUTO_STATE_CLASSIFICATION="healthy"
    vpn_auto_reconnect_write_status "healthy" "${health_detail:-Gluetun tunnel healthy}"
  else
    VPN_AUTO_STATE_CLASSIFICATION="degraded"
    vpn_auto_reconnect_write_status "degraded" "$health_detail"
  fi

  vpn_auto_reconnect_sync_qbt_port || true
  vpn_auto_reconnect_write_state
  return 0
}

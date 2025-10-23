# shellcheck shell=bash
# Purpose: Surface VPN auto-reconnect configuration toggles, thresholds, and rotation policies.
# Inputs: Reads environment variables such as VPN_AUTO_RECONNECT_ENABLED, VPN_SPEED_THRESHOLD_KBPS, and rotation limits.
# Outputs: Normalizes numeric thresholds and updates global state tracking windows for reconnect attempts.
# Exit codes: Functions return non-zero when configuration values are invalid or exceed safety guards.
# Manual override flag helpers live in vpn-auto-signals.sh.
if [[ -n "${__VPN_AUTO_CONFIG_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_CONFIG_LOADED=1

vpn_auto_reconnect_is_enabled() {
  [[ "${VPN_AUTO_RECONNECT_ENABLED:-0}" == "1" ]]
}

# Loads env defaults used by reconnect logic (thresholds, credentials)
vpn_auto_reconnect_load_env() {
  local env_file="${ARR_ENV_FILE:-}"
  if [[ -z "$env_file" ]]; then
    if declare -f arr_env_file >/dev/null 2>&1; then
      env_file="$(arr_env_file)"
    elif declare -f arr_stack_dir >/dev/null 2>&1; then
      env_file="$(arr_stack_dir)/.env"
    fi
  fi
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}

# Converts KB/s threshold into bytes per second for comparisons
vpn_auto_reconnect_speed_threshold_bytes() {
  local kbps="${VPN_SPEED_THRESHOLD_KBPS:-12}"
  [[ "$kbps" =~ ^[0-9]+$ ]] || kbps=12
  if ((kbps <= 0)); then
    kbps=12
  fi
  printf '%s' $((kbps * 125))
}

# Determines interval between throughput checks in seconds
vpn_auto_reconnect_check_interval_seconds() {
  local minutes="${VPN_CHECK_INTERVAL_MINUTES:-20}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=20
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' $((minutes * 60))
}

# Number of consecutive low samples required before considering action
vpn_auto_reconnect_consecutive_required() {
  local count="${VPN_CONSECUTIVE_CHECKS:-3}"
  [[ "$count" =~ ^[0-9]+$ ]] || count=3
  if ((count <= 0)); then
    count=3
  fi
  printf '%s' "$count"
}

# Returns cooldown duration between reconnects based on env
vpn_auto_reconnect_cooldown_seconds() {
  local minutes="${VPN_COOLDOWN_MINUTES:-60}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=60
  if ((minutes <= 0)); then
    minutes=60
  fi
  printf '%s' $((minutes * 60))
}

# Total minutes the exponential backoff may accumulate before disabling
vpn_auto_reconnect_max_retry_minutes() {
  local minutes="${VPN_MAX_RETRY_MINUTES:-20}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=20
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' "$minutes"
}

# Daily rotation cap controlling how many reconnects can occur
vpn_auto_reconnect_rotation_cap() {
  local cap="${VPN_ROTATION_MAX_PER_DAY:-6}"
  [[ "$cap" =~ ^[0-9]+$ ]] || cap=6
  if ((cap < 0)); then
    cap=0
  fi
  printf '%s' "$cap"
}

# Maximum jitter window to randomize reconnect attempts
vpn_auto_reconnect_jitter_seconds() {
  local seconds="${VPN_ROTATION_JITTER_SECONDS:-0}"
  [[ "$seconds" =~ ^[0-9]+$ ]] || seconds=0
  if ((seconds < 0)); then
    seconds=0
  fi
  printf '%s' "$seconds"
}

# Normalizes current day start (UTC) for rotation counting
vpn_auto_reconnect_current_day_epoch() {
  local today
  today="$(date -u '+%Y-%m-%d')"
  date -u -d "${today}T00:00:00Z" '+%s' 2>/dev/null || printf '0'
}

# Resets daily rotation counters when date boundary crosses
vpn_auto_reconnect_reset_rotation_window() {
  local today
  today="$(vpn_auto_reconnect_current_day_epoch)"
  [[ "$today" =~ ^[0-9]+$ ]] || today=0
  if ((today == 0)); then
    return
  fi
  [[ "${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0}" =~ ^[0-9]+$ ]] || VPN_AUTO_STATE_ROTATION_DAY_EPOCH=0
  if ((VPN_AUTO_STATE_ROTATION_DAY_EPOCH != today)); then
    VPN_AUTO_STATE_ROTATION_DAY_EPOCH="$today"
    VPN_AUTO_STATE_ROTATION_COUNT_DAY=0
  fi
}

# Checks if daily reconnect cap has already been reached
vpn_auto_reconnect_daily_cap_exceeded() {
  local force="${1:-0}"
  local cap
  cap="$(vpn_auto_reconnect_rotation_cap)"
  [[ "$cap" =~ ^[0-9]+$ ]] || cap=0
  vpn_auto_reconnect_reset_rotation_window
  [[ "${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0}" =~ ^[0-9]+$ ]] || VPN_AUTO_STATE_ROTATION_COUNT_DAY=0
  if ((cap == 0)); then
    return 1
  fi
  if ((force != 0)); then
    return 1
  fi
  if ((VPN_AUTO_STATE_ROTATION_COUNT_DAY >= cap)); then
    return 0
  fi
  return 1
}

# Records a successful reconnect against the daily cap and history
vpn_auto_reconnect_register_rotation_success() {
  vpn_auto_reconnect_reset_rotation_window
  local today
  today="${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0}"
  if [[ ! "$today" =~ ^[0-9]+$ || "$today" -le 0 ]]; then
    today="$(vpn_auto_reconnect_current_day_epoch)"
    [[ "$today" =~ ^[0-9]+$ ]] || today=0
    VPN_AUTO_STATE_ROTATION_DAY_EPOCH="$today"
  fi
  [[ "${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0}" =~ ^[0-9]+$ ]] || VPN_AUTO_STATE_ROTATION_COUNT_DAY=0
  VPN_AUTO_STATE_ROTATION_COUNT_DAY=$((VPN_AUTO_STATE_ROTATION_COUNT_DAY + 1))
  if ((today > 0)); then
    VPN_AUTO_STATE_ROTATION_DAY_EPOCH="$today"
  fi
}

# Evaluates whether current time falls within configured allowed hours
vpn_auto_reconnect_inside_allowed_window() {
  local start_hour="${VPN_ALLOWED_HOURS_START:-}"
  local end_hour="${VPN_ALLOWED_HOURS_END:-}"
  if [[ -z "$start_hour" || -z "$end_hour" ]]; then
    return 0
  fi
  if [[ ! "$start_hour" =~ ^[0-9]+$ || ! "$end_hour" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  local now_raw
  now_raw="$(LC_ALL=C arr_date_local +%H 2>/dev/null || printf '00')"
  if [[ ! "$now_raw" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  local now=$((10#${now_raw}))
  start_hour=$((10#${start_hour}))
  end_hour=$((10#${end_hour}))
  if ((start_hour == end_hour)); then
    return 0
  fi
  if ((start_hour < end_hour)); then
    if ((now >= start_hour && now < end_hour)); then
      return 0
    fi
    return 1
  fi
  # Window wraps past midnight
  if ((now >= start_hour || now < end_hour)); then
    return 0
  fi
  return 1
}


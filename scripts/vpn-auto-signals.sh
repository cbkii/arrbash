# shellcheck shell=bash
# Purpose: Track manual overrides, wake signals, and activity history for VPN auto-reconnect.
# Inputs: Utilises ARR_STACK_DIR, VPN override files, and activity metrics from metrics helpers.
# Outputs: Updates wake/force files, persists history JSON, and annotates runtime state variables.
# Exit codes: Functions return non-zero when overrides cannot be processed or history files fail to update.
if [[ -n "${__VPN_AUTO_SIGNALS_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_SIGNALS_LOADED=1

vpn_auto_escape_json_string() {
  local input="${1-}"
  local output=""
  local char=""
  local code=""
  local hex=""
  local LC_ALL=C

  while IFS= read -r -n1 char || [[ -n "$char" ]]; do
    case "$char" in
      $'\n')
        output+=$'\\n'
        ;;
      $'\r')
        output+=$'\\r'
        ;;
      $'\t')
        output+=$'\\t'
        ;;
      '"')
        output+=$'\\"'
        ;;
      '\\')
        output+=$'\\\\'
        ;;
      *)
        printf -v code '%d' "'$char"
        if ((code < 32)); then
          printf -v hex '%02X' "$code"
          output+="\\u00${hex}"
        else
          output+="$char"
        fi
        ;;
    esac
  done <<<"$input"

  printf '%s' "$output"
}

vpn_auto_reconnect_override_path() {
  printf '%s/.vpn-auto-reconnect-%s' "${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}" "$1"
}

# Wake flag path used to trigger immediate evaluation
vpn_auto_reconnect_wake_file() {
  vpn_auto_reconnect_override_path 'wake'
}

# Indicates if wake flag exists requesting immediate processing
vpn_auto_reconnect_wake_requested() {
  local file
  file="$(vpn_auto_reconnect_wake_file)"
  [[ -f "$file" ]]
}

# Removes wake flag after noticing it
vpn_auto_reconnect_consume_wake() {
  local file
  file="$(vpn_auto_reconnect_wake_file)"
  if [[ -f "$file" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}

# Checks for pause override file that suspends reconnects
vpn_auto_reconnect_manual_pause_active() {
  local file
  file="$(vpn_auto_reconnect_override_path pause)"
  [[ -f "$file" ]]
}

# Detects kill switch flag that halts reconnects for 24h
vpn_auto_reconnect_kill_active() {
  local file
  file="$(vpn_auto_reconnect_override_path 'kill-24h')"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  local mtime
  if ! mtime="$(stat -c '%Y' "$file" 2>/dev/null)"; then
    return 0
  fi
  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  if ((now - mtime > 86400)); then
    rm -f "$file" 2>/dev/null || true
    return 1
  fi
  return 0
}

# Checks for one-shot override forcing a reconnect attempt
vpn_auto_reconnect_force_once_requested() {
  local file
  file="$(vpn_auto_reconnect_override_path once)"
  [[ -f "$file" ]]
}

# Removes the force-once override after use
vpn_auto_reconnect_consume_force_once_flag() {
  local file
  file="$(vpn_auto_reconnect_override_path once)"
  if [[ -f "$file" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}

# Records timestamp of observed torrent activity to avoid false failures
vpn_auto_reconnect_record_activity() {
  local iso="$1"
  VPN_AUTO_STATE_LAST_ACTIVITY="$iso"
}

# Tracks when throughput dips below threshold for future evaluation
vpn_auto_reconnect_record_low() {
  local iso="$1"
  VPN_AUTO_STATE_LAST_LOW="$iso"
}

# Appends structured attempt history for debugging and alias helpers
vpn_auto_reconnect_append_history() {
  local action="$1"
  local country="$2"
  local success_flag="${3:-}" # expect "true" or "false"
  local reason="$4"
  local consecutive="${5:-0}"
  local retry_total="${6:-0}"
  local jitter_value="${7:-0}"
  local classification_value="${8:-${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}}"

  local file
  file="$(vpn_auto_reconnect_history_file)"
  local dir
  dir="$(dirname -- "$file")"
  ensure_dir_mode "$dir" "$DATA_DIR_MODE"

  local ts
  ts="$(LC_ALL=C date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local success_json
  if [[ "$success_flag" == "true" ]]; then
    success_json=true
  elif [[ "$success_flag" == "false" ]]; then
    success_json=false
  else
    success_json=null
  fi
  [[ "$consecutive" =~ ^[0-9]+$ ]] || consecutive=0
  [[ "$retry_total" =~ ^[0-9]+$ ]] || retry_total=0
  [[ "$jitter_value" =~ ^[0-9]+$ ]] || jitter_value=0

  local line
  if vpn_auto_has_jq; then
    line="$(
      jq -nc \
        --arg ts "$ts" \
        --arg action "$action" \
        --arg country "$country" \
        --arg reason "$reason" \
        --arg classification "$classification_value" \
        --argjson success "$success_json" \
        --argjson consecutive "$consecutive" \
        --argjson retry "$retry_total" \
        --argjson jitter "$jitter_value" \
        '{ts:$ts,action:$action,country:($country==""?null:$country),success:$success,reason:($reason==""?null:$reason),consecutive_low:$consecutive,retry_total:$retry,jitter:$jitter,classification:$classification}'
    )"
  else
    local ts_json
    ts_json="\"$(vpn_auto_escape_json_string "$ts")\""
    local action_json
    action_json="\"$(vpn_auto_escape_json_string "$action")\""
    local classification_json
    classification_json="\"$(vpn_auto_escape_json_string "$classification_value")\""
    local country_json="null"
    if [[ -n "$country" ]]; then
      country_json="\"$(vpn_auto_escape_json_string "$country")\""
    fi
    local reason_json="null"
    if [[ -n "$reason" ]]; then
      reason_json="\"$(vpn_auto_escape_json_string "$reason")\""
    fi
    line="{\"ts\":${ts_json},\"action\":${action_json},\"country\":${country_json},\"success\":$success_json,\"reason\":${reason_json},\"consecutive_low\":$consecutive,\"retry_total\":$retry_total,\"jitter\":$jitter_value,\"classification\":${classification_json}}"
  fi
  printf '%s\n' "$line" >>"$file"
  ensure_nonsecret_file_mode "$file"

  local max_entries="${VPN_AUTO_HISTORY_MAX_LINES:-500}"
  [[ "$max_entries" =~ ^[0-9]+$ ]] || max_entries=500
  if ((max_entries <= 0)); then
    max_entries=500
  fi

  local current_lines="0"
  if current_lines="$(LC_ALL=C wc -l <"$file" 2>/dev/null | tr -d '[:space:]')"; then
    [[ "$current_lines" =~ ^[0-9]+$ ]] || current_lines=0
  else
    current_lines=0
  fi

  if ((current_lines > max_entries)); then
    local tmp_trim=""
    if tmp_trim="$(arr_mktemp_file "${file}.trim.XXXXXX")"; then
      if LC_ALL=C tail -n "$max_entries" "$file" >"$tmp_trim" 2>/dev/null; then
        if mv "$tmp_trim" "$file" 2>/dev/null; then
          arr_unregister_temp_path "$tmp_trim"
          ensure_nonsecret_file_mode "$file"
        else
          arr_cleanup_temp_path "$tmp_trim"
        fi
      else
        arr_cleanup_temp_path "$tmp_trim"
      fi
    fi
  fi
}

# Updates failure history for a country to discourage rapid retries
vpn_auto_reconnect_failure_history_update() {
  local country="$1"
  local timestamp="$2"
  if ! vpn_auto_has_jq; then
    VPN_AUTO_STATE_FAILURE_HISTORY="{}"
    return
  fi
  local current
  current="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
  VPN_AUTO_STATE_FAILURE_HISTORY="$(jq --arg country "$country" --argjson ts "$timestamp" '
    . as $root
    | ($root[$country] // {last:0,count:0}) as $existing
    | .[$country] = {last:$ts,count:(($existing.count // 0) + 1)}
  ' <<<"$current" 2>/dev/null || printf '{}')"
}

# Reduces failure penalty after a successful attempt for the country
vpn_auto_reconnect_failure_history_clear() {
  local country="$1"
  if [[ -z "$country" ]]; then
    return
  fi
  if ! vpn_auto_has_jq; then
    VPN_AUTO_STATE_FAILURE_HISTORY="{}"
    return
  fi
  local current
  current="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
  VPN_AUTO_STATE_FAILURE_HISTORY="$(jq --arg country "$country" '
    . as $root
    | ($root[$country] // {last:0,count:0}) as $existing
    | .[$country] = {last:0,count:( ($existing.count // 0) > 0 ? ($existing.count - 1) : 0 )}
  ' <<<"$current" 2>/dev/null || printf '{}')"
}

# Checks if a country failed recently within provided cutoff
vpn_auto_reconnect_failure_recent() {
  local country="$1"
  local cutoff="$2"
  if ! vpn_auto_has_jq; then
    return 1
  fi
  local current
  current="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
  local ts
  ts="$(jq -r --arg country "$country" '.[$country].last // 0' <<<"$current" 2>/dev/null || printf '0')"
  [[ "$ts" =~ ^[0-9]+$ ]] || ts=0
  if ((ts == 0)); then
    return 1
  fi
  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  if ((now - ts < cutoff)); then
    return 0
  fi
  return 1
}

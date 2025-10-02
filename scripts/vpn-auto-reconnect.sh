# shellcheck shell=bash
# VPN auto-reconnect helpers sourced by arrstack components
#
# AUTO-RECONNECT OVERVIEW
#   Classification rules:
#     • busy            – throughput above threshold or explicit client activity detected.
#     • idle            – no active torrents, no recent WebUI/log hints, and last low sample older than the idle grace period.
#     • low             – below threshold but not yet a confirmed failure candidate.
#     • failure         – sustained low throughput without seeding signals and PF worker not reporting an acquired lease.
#   Rotation safety:
#     • Daily cap enforced via VPN_ROTATION_MAX_PER_DAY with UTC day rollover.
#     • Optional jitter (VPN_ROTATION_JITTER_SECONDS) randomises restart timing for multi-host deployments.
#     • Backoff budget persists across attempts and surfaces retry metadata in status.json.

VPN_AUTO_RECONNECT_STATE_VERSION=2
VPN_AUTO_RECONNECT_CURL_WARNED=0
VPN_AUTO_RECONNECT_JQ_WARNED=0
VPN_AUTO_RECONNECT_CURRENT_INTERVAL=0
VPN_AUTO_RECONNECT_IDLE_GRACE_SECONDS=1800
VPN_AUTO_RECONNECT_ACTIVITY_GRACE_SECONDS=1800
VPN_AUTO_RECONNECT_PF_SUCCESS_GRACE=86400
VPN_AUTO_RECONNECT_SEEDING_FLOOR_BYTES=4096
VPN_AUTO_RECONNECT_SUPPRESS_RETRY=0

# Resolves auto-reconnect working directory under docker-data
vpn_auto_reconnect_state_dir() {
  local base="${ARR_DOCKER_DIR:-}"
  if [[ -z "$base" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      base="${ARR_STACK_DIR%/}/docker-data"
    else
      base="${HOME:-.}/srv/docker-data"
    fi
  fi
  printf '%s/gluetun/auto-reconnect' "${base%/}"
}

# Returns path to persisted state.json for reconnect worker
vpn_auto_reconnect_state_file() {
  printf '%s/state.json' "$(vpn_auto_reconnect_state_dir)"
}

# Path to human-readable status JSON stored alongside stack root
vpn_auto_reconnect_status_file() {
  local stack_dir="${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}"
  printf '%s/.vpn-auto-reconnect-status.json' "${stack_dir%/}"
}

# Cookie jar used for qBittorrent API sessions
vpn_auto_reconnect_cookie_file() {
  printf '%s/session.cookie' "$(vpn_auto_reconnect_state_dir)"
}

# History log tracking reconnect attempts and outcomes
vpn_auto_reconnect_history_file() {
  printf '%s/history.log' "$(vpn_auto_reconnect_state_dir)"
}

if ! declare -f pf_state_lock_file >/dev/null 2>&1; then
  pf_state_lock_file() {
    local state_file=""
    if declare -f pf_state_path >/dev/null 2>&1; then
      state_file="$(pf_state_path)"
    else
      local base="${ARR_DOCKER_DIR:-}"
      if [[ -z "$base" ]]; then
        if [[ -n "${ARR_STACK_DIR:-}" ]]; then
          base="${ARR_STACK_DIR%/}/docker-data"
        else
          base="${HOME:-.}/srv/docker-data"
        fi
      fi
      local pf_file="${PF_ASYNC_STATE_FILE:-pf-state.json}"
      state_file="${base%/}/gluetun/${pf_file}"
    fi

    printf '%s.lock' "$state_file"
  }
fi

# Locates Gluetun port-forward worker state file, honoring overrides
vpn_auto_reconnect_pf_state_file() {
  if declare -f pf_state_path >/dev/null 2>&1; then
    pf_state_path
    return
  fi
  local base="${ARR_DOCKER_DIR:-}"
  if [[ -z "$base" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      base="${ARR_STACK_DIR%/}/docker-data"
    else
      base="${HOME:-.}/srv/docker-data"
    fi
  fi
  local pf_file="${PF_ASYNC_STATE_FILE:-pf-state.json}"
  printf '%s/gluetun/%s' "${base%/}" "$pf_file"
}

if ! declare -f pf_write_with_lock >/dev/null 2>&1; then
  pf_write_with_lock() {
    if ! declare -f write_pf_state >/dev/null 2>&1; then
      return 1
    fi

    local lock_file
    lock_file="$(pf_state_lock_file)"
    local lock_dir
    lock_dir="$(dirname -- "$lock_file")"
    if declare -f ensure_dir_mode >/dev/null 2>&1; then
      ensure_dir_mode "$lock_dir" "${DATA_DIR_MODE:-700}"
    else
      mkdir -p "$lock_dir" 2>/dev/null || true
      chmod 700 "$lock_dir" 2>/dev/null || true
    fi

    local lock_fd
    exec {lock_fd}>"$lock_file"
    flock -x "$lock_fd"

    write_pf_state "$@"

    flock -u "$lock_fd"
    exec {lock_fd}>&-
  }
fi

# Removes cached PF state and triggers async worker restart after reconnect
vpn_auto_reconnect_resync_pf() {
  local state_file
  state_file="$(vpn_auto_reconnect_pf_state_file 2>/dev/null || printf '')"
  local base_dir=""
  if [[ -n "$state_file" ]]; then
    base_dir="$(dirname -- "$state_file")"
    rm -f "$state_file" 2>/dev/null || true
  fi
  if [[ -z "$base_dir" ]]; then
    local base="${ARR_DOCKER_DIR:-}"
    if [[ -z "$base" ]]; then
      if [[ -n "${ARR_STACK_DIR:-}" ]]; then
        base="${ARR_STACK_DIR%/}/docker-data"
      else
        base="${HOME:-.}/srv/docker-data"
      fi
    fi
    base_dir="${base%/}/gluetun"
  fi
  rm -f "$base_dir/forwarded_port" "$base_dir/forwarded_port.json" 2>/dev/null || true
  if declare -f start_async_pf_if_enabled >/dev/null 2>&1; then
    start_async_pf_if_enabled || true
  fi
}

# Returns current PF status and last_success values for decision logic
vpn_auto_reconnect_pf_status_snapshot() {
  local file
  file="$(vpn_auto_reconnect_pf_state_file 2>/dev/null || printf '')"
  local status=""
  local last_success=""
  if [[ -n "$file" && -f "$file" ]]; then
    if command -v jq >/dev/null 2>&1; then
      status="$(jq -r '.status // ""' "$file" 2>/dev/null || printf '')"
      last_success="$(jq -r '.last_success // ""' "$file" 2>/dev/null || printf '')"
    else
      status="$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n1 || printf '')"
      last_success="$(sed -n 's/.*"last_success"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n1 || printf '')"
    fi
  fi
  printf '%s|%s' "$status" "$last_success"
}

# UTC now helper (seconds) for consistent scheduling math
vpn_auto_reconnect_now_epoch() {
  date -u +%s
}

# Converts epoch seconds to ISO8601; returns failure on invalid input
vpn_auto_reconnect_epoch_to_iso() {
  local epoch="$1"
  if [[ -z "$epoch" || ! "$epoch" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ'
}

# Parses ISO8601 string back to epoch seconds if valid
vpn_auto_reconnect_iso_to_epoch() {
  local iso="$1"
  if [[ -z "$iso" ]]; then
    return 1
  fi
  date -u -d "$iso" '+%s' 2>/dev/null || return 1
}

# Splits comma-separated lists into trimmed lines for iteration
vpn_auto_reconnect_split_csv() {
  local raw="$1"
  local IFS=','
  read -r -a _var <<<"$raw"
  local value
  for value in "${_var[@]}"; do
    value="$(trim_string "$value")"
    [[ -z "$value" ]] && continue
    printf '%s\n' "$value"
  done
}

# Builds candidate country list from rotation env vars with deduping
vpn_auto_reconnect_parse_countries() {
  local combined=""
  if [[ -n "${PVPN_ROTATE_COUNTRIES:-}" ]]; then
    combined="${PVPN_ROTATE_COUNTRIES}"
  fi
  if [[ -n "${SERVER_COUNTRIES:-}" ]]; then
    combined+="${combined:+,}${SERVER_COUNTRIES}"
  fi
  if [[ -z "$combined" ]]; then
    combined="Switzerland,Iceland,Romania,Netherlands"
  fi
  local sanitized
  if ! sanitized="$(vpn_auto_reconnect_sanitize_country_csv "$combined" 2>/dev/null)" || [[ -z "$sanitized" ]]; then
    sanitized="Switzerland,Iceland,Romania,Netherlands"
  fi
  local -a ordered=()
  local -A seen=()
  local entry lower
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    lower="${entry,,}"
    if [[ -z "${seen[$lower]+x}" ]]; then
      ordered+=("$entry")
      seen[$lower]=1
    fi
  done < <(vpn_auto_reconnect_split_csv "$sanitized")
  printf '%s\n' "${ordered[@]}"
}

# Validates/normalizes comma-separated country codes
vpn_auto_reconnect_sanitize_country_csv() {
  local raw="${1:-}"
  [[ -n "$raw" ]] || return 1
  raw="${raw//$'\r'/,}"
  raw="${raw//$'\n'/,}"
  raw="${raw//$'\t'/,}"
  local -a cleaned=()
  local entry
  while IFS= read -r entry; do
    entry="${entry//[^[:alnum:]\- ,]/ }"
    entry="${entry//  / }"
    entry="$(trim_string "$entry")"
    entry="$(printf '%s' "$entry" | tr -s ' ' ' ')"
    entry="$(trim_string "$entry")"
    [[ -z "$entry" ]] && continue
    cleaned+=("$entry")
  done < <(vpn_auto_reconnect_split_csv "$raw")
  ((${#cleaned[@]} > 0)) || return 1
  local result="${cleaned[0]}"
  local item
  for item in "${cleaned[@]:1}"; do
    result+=",$item"
  done
  printf '%s\n' "$result"
}

# Initializes state structure before processing loop begins
vpn_auto_reconnect_reset_state() {
  VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  VPN_AUTO_STATE_ROTATION_INDEX=0
  VPN_AUTO_STATE_LAST_COUNTRY=""
  VPN_AUTO_STATE_LAST_RECONNECT=""
  VPN_AUTO_STATE_LAST_STATUS=""
  VPN_AUTO_STATE_LAST_ACTIVITY=""
  VPN_AUTO_STATE_LAST_LOW=""
  VPN_AUTO_STATE_FAILURE_HISTORY="{}"
  VPN_AUTO_STATE_COOLDOWN_UNTIL=0
  VPN_AUTO_STATE_DISABLED_UNTIL=0
  VPN_AUTO_STATE_AUTO_DISABLED=0
  VPN_AUTO_STATE_RETRY_BACKOFF=5
  VPN_AUTO_STATE_RETRY_TOTAL=0
  VPN_AUTO_STATE_NEXT_DECISION=0
  VPN_AUTO_STATE_ROTATION_DAY_EPOCH=0
  VPN_AUTO_STATE_ROTATION_COUNT_DAY=0
  VPN_AUTO_STATE_CLASSIFICATION="monitoring"
  VPN_AUTO_STATE_JITTER_APPLIED=0
  VPN_AUTO_STATE_NEXT_ACTION=0
  VPN_AUTO_STATE_RESTART_FAILURES=0
}

vpn_auto_reconnect_reset_state

# Loads persisted state JSON (if present) into shell variables
vpn_auto_reconnect_load_state() {
  vpn_auto_reconnect_reset_state
  local file
  file="$(vpn_auto_reconnect_state_file)"
  [[ -f "$file" ]] || return 0
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi
  local json
  if ! json="$(cat "$file" 2>/dev/null)" || [[ -z "$json" ]]; then
    return 0
  fi
  # Consolidate jq extraction to a single pass; fallback retains legacy per-field parsing.
  local jq_output=""
  if jq_output="$(
    jq -r '
      def normalise(entry):
        if (entry | type) == "object" then
          {last: (entry.last // 0), count: (entry.count // 0)}
        elif (entry | type) == "number" then
          {last: entry, count: 1}
        else
          {last: 0, count: 0}
        end;
      def failure_history():
        ( .failure_history // {} ) as $fh
        | reduce ($fh | to_entries[]) as $item ({}; .[$item.key] = normalise($item.value));
      [
        (.consecutive_low // 0 | tostring),
        (.rotation_index // 0 | tostring),
        (.last_country // ""),
        (.last_reconnect // ""),
        (.last_status // ""),
        (.last_activity // ""),
        (.last_low // ""),
        (.cooldown_until // 0 | tostring),
        (.disabled_until // 0 | tostring),
        (.auto_disabled // 0 | tostring),
        (.retry_backoff // 5 | tostring),
        (.retry_total // 0 | tostring),
        (.next_decision_at // 0 | tostring),
        (.rotation_day_epoch // 0 | tostring),
        (.rotation_count_day // 0 | tostring),
        (.classification // "monitoring"),
        (.jitter_applied // 0 | tostring),
        (.next_possible_action // 0 | tostring),
        (.restart_failures // 0 | tostring),
        (failure_history() | tojson)
      ] | @tsv
    ' <<<"$json" 2>/dev/null
  )" && [[ -n "$jq_output" ]]; then
    local failure_history_json=""
    # Read jq_output into array and validate field count
    IFS=$'\t' read -r -a vpn_auto_state_fields <<<"$jq_output"
    if [[ ${#vpn_auto_state_fields[@]} -eq 20 ]]; then
      VPN_AUTO_STATE_CONSECUTIVE_LOW="${vpn_auto_state_fields[0]}"
      VPN_AUTO_STATE_ROTATION_INDEX="${vpn_auto_state_fields[1]}"
      VPN_AUTO_STATE_LAST_COUNTRY="${vpn_auto_state_fields[2]}"
      VPN_AUTO_STATE_LAST_RECONNECT="${vpn_auto_state_fields[3]}"
      VPN_AUTO_STATE_LAST_STATUS="${vpn_auto_state_fields[4]}"
      VPN_AUTO_STATE_LAST_ACTIVITY="${vpn_auto_state_fields[5]}"
      VPN_AUTO_STATE_LAST_LOW="${vpn_auto_state_fields[6]}"
      VPN_AUTO_STATE_COOLDOWN_UNTIL="${vpn_auto_state_fields[7]}"
      VPN_AUTO_STATE_DISABLED_UNTIL="${vpn_auto_state_fields[8]}"
      VPN_AUTO_STATE_AUTO_DISABLED="${vpn_auto_state_fields[9]}"
      VPN_AUTO_STATE_RETRY_BACKOFF="${vpn_auto_state_fields[10]}"
      VPN_AUTO_STATE_RETRY_TOTAL="${vpn_auto_state_fields[11]}"
      VPN_AUTO_STATE_NEXT_DECISION="${vpn_auto_state_fields[12]}"
      VPN_AUTO_STATE_ROTATION_DAY_EPOCH="${vpn_auto_state_fields[13]}"
      VPN_AUTO_STATE_ROTATION_COUNT_DAY="${vpn_auto_state_fields[14]}"
      VPN_AUTO_STATE_CLASSIFICATION="${vpn_auto_state_fields[15]}"
      VPN_AUTO_STATE_JITTER_APPLIED="${vpn_auto_state_fields[16]}"
      VPN_AUTO_STATE_NEXT_ACTION="${vpn_auto_state_fields[17]}"
      VPN_AUTO_STATE_RESTART_FAILURES="${vpn_auto_state_fields[18]}"
      VPN_AUTO_STATE_FAILURE_HISTORY="${vpn_auto_state_fields[19]:-$(printf '{}')}"
    else
      # Fallback to per-field extraction if field count is wrong
      VPN_AUTO_STATE_CONSECUTIVE_LOW="$(jq -r '.consecutive_low // 0' <<<"$json" 2>/dev/null || printf '0')"
      VPN_AUTO_STATE_ROTATION_INDEX="$(jq -r '.rotation_index // 0' <<<"$json" 2>/dev/null || printf '0')"
      VPN_AUTO_STATE_LAST_COUNTRY="$(jq -r '.last_country // ""' <<<"$json" 2>/dev/null || printf '')"
      VPN_AUTO_STATE_LAST_RECONNECT="$(jq -r '.last_reconnect // ""' <<<"$json" 2>/dev/null || printf '')"
      VPN_AUTO_STATE_LAST_STATUS="$(jq -r '.last_status // ""' <<<"$json" 2>/dev/null || printf '')"
      VPN_AUTO_STATE_LAST_ACTIVITY="$(jq -r '.last_activity // ""' <<<"$json" 2>/dev/null || printf '')"
      VPN_AUTO_STATE_LAST_LOW="$(jq -r '.last_low // ""' <<<"$json" 2>/dev/null || printf '')"
      VPN_AUTO_STATE_FAILURE_HISTORY="$(jq -c '
        def normalise(entry):
          if (entry | type) == "object" then
            {last: (entry.last // 0), count: (entry.count // 0)}
          elif (entry | type) == "number" then
            {last: entry, count: 1}
          else
            {last: 0, count: 0}
          end;
        ( .failure_history // {} ) as $fh
        | reduce ($fh | to_entries[]) as $item ({}; .[$item.key] = normalise($item.value))
      ' <<<"$json" 2>/dev/null || printf '{}')"
    fi
  else
    # Fallback if optimized jq extraction fails
    VPN_AUTO_STATE_CONSECUTIVE_LOW="$(jq -r '.consecutive_low // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_ROTATION_INDEX="$(jq -r '.rotation_index // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_LAST_COUNTRY="$(jq -r '.last_country // ""' <<<"$json" 2>/dev/null || printf '')"
    VPN_AUTO_STATE_LAST_RECONNECT="$(jq -r '.last_reconnect // ""' <<<"$json" 2>/dev/null || printf '')"
    VPN_AUTO_STATE_LAST_STATUS="$(jq -r '.last_status // ""' <<<"$json" 2>/dev/null || printf '')"
    VPN_AUTO_STATE_LAST_ACTIVITY="$(jq -r '.last_activity // ""' <<<"$json" 2>/dev/null || printf '')"
    VPN_AUTO_STATE_LAST_LOW="$(jq -r '.last_low // ""' <<<"$json" 2>/dev/null || printf '')"
    VPN_AUTO_STATE_FAILURE_HISTORY="$(jq -c '
      def normalise(entry):
        if (entry | type) == "object" then
          {last: (entry.last // 0), count: (entry.count // 0)}
        elif (entry | type) == "number" then
          {last: entry, count: 1}
        else
          {last: 0, count: 0}
        end;
      ( .failure_history // {} ) as $fh
      | reduce ($fh | to_entries[]) as $item ({}; .[$item.key] = normalise($item.value))
    ' <<<"$json" 2>/dev/null || printf '{}')"
    VPN_AUTO_STATE_COOLDOWN_UNTIL="$(jq -r '.cooldown_until // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_DISABLED_UNTIL="$(jq -r '.disabled_until // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_AUTO_DISABLED="$(jq -r '.auto_disabled // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_RETRY_BACKOFF="$(jq -r '.retry_backoff // 5' <<<"$json" 2>/dev/null || printf '5')"
    VPN_AUTO_STATE_RETRY_TOTAL="$(jq -r '.retry_total // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_NEXT_DECISION="$(jq -r '.next_decision_at // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_ROTATION_DAY_EPOCH="$(jq -r '.rotation_day_epoch // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_ROTATION_COUNT_DAY="$(jq -r '.rotation_count_day // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_CLASSIFICATION="$(jq -r '.classification // "monitoring"' <<<"$json" 2>/dev/null || printf 'monitoring')"
    VPN_AUTO_STATE_JITTER_APPLIED="$(jq -r '.jitter_applied // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_NEXT_ACTION="$(jq -r '.next_possible_action // 0' <<<"$json" 2>/dev/null || printf '0')"
    VPN_AUTO_STATE_RESTART_FAILURES="$(jq -r '.restart_failures // 0' <<<"$json" 2>/dev/null || printf '0')"
  fi
}

# Persists current state to disk with basic validation
vpn_auto_reconnect_write_state() {
  local file
  file="$(vpn_auto_reconnect_state_file)"
  local dir
  dir="$(dirname -- "$file")"
  ensure_dir_mode "$dir" "$DATA_DIR_MODE"
  vpn_auto_reconnect_update_next_decision
  local json
  if command -v jq >/dev/null 2>&1; then
    json="$(
      jq -nc \
        --argjson version "$VPN_AUTO_RECONNECT_STATE_VERSION" \
        --argjson consecutive_low "${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0}" \
        --argjson rotation_index "${VPN_AUTO_STATE_ROTATION_INDEX:-0}" \
        --arg last_country "${VPN_AUTO_STATE_LAST_COUNTRY:-}" \
        --arg last_reconnect "${VPN_AUTO_STATE_LAST_RECONNECT:-}" \
        --arg last_status "${VPN_AUTO_STATE_LAST_STATUS:-}" \
        --arg last_activity "${VPN_AUTO_STATE_LAST_ACTIVITY:-}" \
        --arg last_low "${VPN_AUTO_STATE_LAST_LOW:-}" \
        --argjson cooldown_until "${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0}" \
        --argjson disabled_until "${VPN_AUTO_STATE_DISABLED_UNTIL:-0}" \
        --argjson auto_disabled "${VPN_AUTO_STATE_AUTO_DISABLED:-0}" \
        --argjson retry_backoff "${VPN_AUTO_STATE_RETRY_BACKOFF:-5}" \
        --argjson retry_total "${VPN_AUTO_STATE_RETRY_TOTAL:-0}" \
        --argjson next_decision_at "${VPN_AUTO_STATE_NEXT_DECISION:-0}" \
        --argjson rotation_day_epoch "${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0}" \
        --argjson rotation_count_day "${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0}" \
        --arg classification "${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}" \
        --argjson jitter_applied "${VPN_AUTO_STATE_JITTER_APPLIED:-0}" \
        --argjson next_possible_action "${VPN_AUTO_STATE_NEXT_ACTION:-0}" \
        --argjson restart_failures "${VPN_AUTO_STATE_RESTART_FAILURES:-0}" \
        --argjson now "$(vpn_auto_reconnect_now_epoch)" \
        --argjson failure_history "${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}" \
        '{version:$version,updated:$now,consecutive_low:$consecutive_low,rotation_index:$rotation_index,last_country:$last_country,last_reconnect:($last_reconnect==""?null:$last_reconnect),last_status:$last_status,last_activity:($last_activity==""?null:$last_activity),last_low:($last_low==""?null:$last_low),cooldown_until:$cooldown_until,disabled_until:$disabled_until,auto_disabled:$auto_disabled,retry_backoff:$retry_backoff,retry_total:$retry_total,next_decision_at:$next_decision_at,rotation_day_epoch:$rotation_day_epoch,rotation_count_day:$rotation_count_day,classification:$classification,jitter_applied:$jitter_applied,next_possible_action:$next_possible_action,restart_failures:$restart_failures,failure_history:$failure_history}'
    )"
  else
    json=$(
      cat <<JSON
{
  "version": ${VPN_AUTO_RECONNECT_STATE_VERSION},
  "updated": $(vpn_auto_reconnect_now_epoch),
  "consecutive_low": ${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0},
  "rotation_index": ${VPN_AUTO_STATE_ROTATION_INDEX:-0},
  "last_country": "${VPN_AUTO_STATE_LAST_COUNTRY:-}",
  "last_reconnect": "${VPN_AUTO_STATE_LAST_RECONNECT:-}",
  "last_status": "${VPN_AUTO_STATE_LAST_STATUS:-}",
  "last_activity": "${VPN_AUTO_STATE_LAST_ACTIVITY:-}",
  "last_low": "${VPN_AUTO_STATE_LAST_LOW:-}",
  "cooldown_until": ${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0},
  "disabled_until": ${VPN_AUTO_STATE_DISABLED_UNTIL:-0},
  "auto_disabled": ${VPN_AUTO_STATE_AUTO_DISABLED:-0},
  "retry_backoff": ${VPN_AUTO_STATE_RETRY_BACKOFF:-5},
  "retry_total": ${VPN_AUTO_STATE_RETRY_TOTAL:-0},
  "next_decision_at": ${VPN_AUTO_STATE_NEXT_DECISION:-0},
  "rotation_day_epoch": ${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0},
  "rotation_count_day": ${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0},
  "classification": "${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}",
  "jitter_applied": ${VPN_AUTO_STATE_JITTER_APPLIED:-0},
  "next_possible_action": ${VPN_AUTO_STATE_NEXT_ACTION:-0},
  "restart_failures": ${VPN_AUTO_STATE_RESTART_FAILURES:-0},
  "failure_history": ${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}
}
JSON
    )
  fi
  printf '%s\n' "$json" >"$file"
  ensure_secret_file_mode "$file"
}

# Updates the next scheduled decision timestamp in state tracking
vpn_auto_reconnect_update_next_decision() {
  local interval="${VPN_AUTO_RECONNECT_CURRENT_INTERVAL:-0}"
  if [[ "$interval" =~ ^[0-9]+$ ]] && ((interval > 0)); then
    VPN_AUTO_STATE_NEXT_DECISION=$(($(vpn_auto_reconnect_now_epoch) + interval))
  fi
}

# Schedules next wake time for the worker loop
vpn_auto_reconnect_set_next_action() {
  local epoch="${1:-0}"
  if [[ "$epoch" =~ ^[0-9]+$ && $epoch -gt 0 ]]; then
    VPN_AUTO_STATE_NEXT_ACTION="$epoch"
  else
    VPN_AUTO_STATE_NEXT_ACTION=0
  fi
}

# Writes status JSON consumed by summary and alias helpers
vpn_auto_reconnect_write_status() {
  local status_file
  status_file="$(vpn_auto_reconnect_status_file)"
  local dir
  dir="$(dirname -- "$status_file")"
  ensure_dir "$dir"
  vpn_auto_reconnect_update_next_decision
  local status_value="${1:-idle}"
  local detail_value="${2:-}"
  if [[ -n "$detail_value" ]]; then
    VPN_AUTO_STATE_LAST_STATUS="$detail_value"
  else
    VPN_AUTO_STATE_LAST_STATUS="$status_value"
  fi
  local now_iso
  now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local rotation_cap
  rotation_cap="$(vpn_auto_reconnect_rotation_cap 2>/dev/null || printf '0')"
  [[ "$rotation_cap" =~ ^[0-9]+$ ]] || rotation_cap=0
  local next_action_iso=""
  if [[ "${VPN_AUTO_STATE_NEXT_ACTION:-0}" =~ ^[0-9]+$ && "${VPN_AUTO_STATE_NEXT_ACTION:-0}" -gt 0 ]]; then
    next_action_iso="$(vpn_auto_reconnect_epoch_to_iso "$VPN_AUTO_STATE_NEXT_ACTION" || printf '')"
  fi
  local payload
  if command -v jq >/dev/null 2>&1; then
    payload="$(
      jq -nc \
        --arg timestamp "$now_iso" \
        --arg status "$status_value" \
        --arg detail "$detail_value" \
        --argjson consecutive_low "${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0}" \
        --arg last_country "${VPN_AUTO_STATE_LAST_COUNTRY:-}" \
        --arg last_reconnect "${VPN_AUTO_STATE_LAST_RECONNECT:-}" \
        --arg last_activity "${VPN_AUTO_STATE_LAST_ACTIVITY:-}" \
        --argjson cooldown_until "${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0}" \
        --argjson disabled_until "${VPN_AUTO_STATE_DISABLED_UNTIL:-0}" \
        --argjson auto_disabled "${VPN_AUTO_STATE_AUTO_DISABLED:-0}" \
        --arg last_low "${VPN_AUTO_STATE_LAST_LOW:-}" \
        --argjson retry_backoff "${VPN_AUTO_STATE_RETRY_BACKOFF:-5}" \
        --argjson retry_total "${VPN_AUTO_STATE_RETRY_TOTAL:-0}" \
        --argjson next_decision_at "${VPN_AUTO_STATE_NEXT_DECISION:-0}" \
        --argjson rotation_count_day "${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0}" \
        --argjson rotation_cap "$rotation_cap" \
        --arg classification "${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}" \
        --arg next_action "$next_action_iso" \
        --argjson jitter_applied "${VPN_AUTO_STATE_JITTER_APPLIED:-0}" \
        '{timestamp:$timestamp,status:$status,detail:$detail,consecutive_low:$consecutive_low,last_country:$last_country,last_reconnect:$last_reconnect,last_activity:$last_activity,last_low:$last_low,cooldown_until:$cooldown_until,disabled_until:$disabled_until,auto_disabled:$auto_disabled,retry_backoff:$retry_backoff,retry_total:$retry_total,next_decision_at:$next_decision_at,rotation_count_day:$rotation_count_day,rotation_cap:$rotation_cap,classification:$classification,next_possible_action:($next_action==""?null:$next_action),jitter_applied:$jitter_applied}'
    )"
  else
    payload=$(
      cat <<JSON
{
  "timestamp": "$now_iso",
  "status": "${status_value}",
  "detail": "${detail_value}",
  "consecutive_low": ${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0},
  "last_country": "${VPN_AUTO_STATE_LAST_COUNTRY:-}",
  "last_reconnect": "${VPN_AUTO_STATE_LAST_RECONNECT:-}",
  "last_activity": "${VPN_AUTO_STATE_LAST_ACTIVITY:-}",
  "last_low": "${VPN_AUTO_STATE_LAST_LOW:-}",
  "cooldown_until": ${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0},
  "disabled_until": ${VPN_AUTO_STATE_DISABLED_UNTIL:-0},
  "auto_disabled": ${VPN_AUTO_STATE_AUTO_DISABLED:-0},
  "retry_backoff": ${VPN_AUTO_STATE_RETRY_BACKOFF:-5},
  "retry_total": ${VPN_AUTO_STATE_RETRY_TOTAL:-0},
  "next_decision_at": ${VPN_AUTO_STATE_NEXT_DECISION:-0},
  "rotation_count_day": ${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0},
  "rotation_cap": ${rotation_cap},
  "classification": "${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}",
  "next_possible_action": "${next_action_iso}",
  "jitter_applied": ${VPN_AUTO_STATE_JITTER_APPLIED:-0}
}
JSON
    )
  fi
  printf '%s\n' "$payload" >"$status_file"
  ensure_nonsecret_file_mode "$status_file"
}

# Reflects whether feature is enabled via env knob
vpn_auto_reconnect_is_enabled() {
  [[ "${VPN_AUTO_RECONNECT_ENABLED:-0}" == "1" ]]
}

# Loads env defaults used by reconnect logic (thresholds, credentials)
vpn_auto_reconnect_load_env() {
  local env_file="${ARR_ENV_FILE:-}"
  if [[ -z "$env_file" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      env_file="${ARR_STACK_DIR%/}/.env"
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
  local now
  now="$(date +%H)"
  ((now += 0)) || true
  ((start_hour += 0)) || true
  ((end_hour += 0)) || true
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

# Computes override flag path for manual pause/force triggers
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
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
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
  if command -v jq >/dev/null 2>&1; then
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
    line="{\"ts\":\"$ts\",\"action\":\"$action\",\"country\":\"$country\",\"success\":$success_json,\"reason\":\"$reason\",\"consecutive_low\":$consecutive,\"retry_total\":$retry_total,\"jitter\":$jitter_value,\"classification\":\"$classification_value\"}"
  fi
  printf '%s\n' "$line" >>"$file"
  ensure_nonsecret_file_mode "$file"
}

# Updates failure history for a country to discourage rapid retries
vpn_auto_reconnect_failure_history_update() {
  local country="$1"
  local timestamp="$2"
  if ! command -v jq >/dev/null 2>&1; then
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
  if ! command -v jq >/dev/null 2>&1; then
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
  if ! command -v jq >/dev/null 2>&1; then
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

# Ensures qBittorrent session cookie is recent to avoid stale auth errors
vpn_auto_reconnect_ensure_fresh_session() {
  local cookie
  cookie="$(vpn_auto_reconnect_cookie_file)"

  if [[ -f "$cookie" ]]; then
    local mtime
    mtime="$(stat -c '%Y' "$cookie" 2>/dev/null || echo 0)"
    if [[ "$mtime" =~ ^[0-9]+$ ]]; then
      local now
      now="$(date +%s)"
      local age=$((now - mtime))
      if ((age > 3600)); then
        rm -f "$cookie"
        return 1
      fi
    else
      rm -f "$cookie"
      return 1
    fi
  else
    return 1
  fi

  return 0
}

# Fetches current transfer metrics from qBittorrent API with auth retry logic
vpn_auto_reconnect_fetch_transfer_info() {
  local base="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
  local url="${base%/}/api/v2/transfer/info"
  local cookie
  cookie="$(vpn_auto_reconnect_cookie_file)"
  ensure_dir_mode "$(dirname -- "$cookie")" "$DATA_DIR_MODE"

  if ! vpn_auto_reconnect_ensure_fresh_session; then
    vpn_auto_reconnect_login_qbt || return 1
  fi

  local -a curl_cmd=(curl -fsS --max-time 10 -c "$cookie" -b "$cookie" "$url")
  local response=""
  if ! response="$("${curl_cmd[@]}" 2>/dev/null)"; then
    if vpn_auto_reconnect_login_qbt; then
      response="$("${curl_cmd[@]}" 2>/dev/null || printf '')"
    fi
  fi
  printf '%s' "$response"
}

# Logs into qBittorrent WebUI API storing session cookie for subsequent calls
vpn_auto_reconnect_login_qbt() {
  local base="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
  local url="${base%/}/api/v2/auth/login"
  local cookie
  cookie="$(vpn_auto_reconnect_cookie_file)"
  ensure_dir_mode "$(dirname -- "$cookie")" "$DATA_DIR_MODE"
  local user="${QBT_USER:-}"
  local pass="${QBT_PASS:-}"
  if [[ -z "$user" || -z "$pass" ]]; then
    return 1
  fi
  curl -fsS --max-time 10 -c "$cookie" --data-urlencode "username=${user}" --data-urlencode "password=${pass}" "$url" >/dev/null 2>&1
}

# Classifies torrent activity level to avoid reconnects during active transfers
vpn_auto_reconnect_detect_activity() {
  local base="${QBITTORRENT_ADDR:-http://127.0.0.1:8080}"
  local cookie
  cookie="$(vpn_auto_reconnect_cookie_file)"
  ensure_dir_mode "$(dirname -- "$cookie")" "$DATA_DIR_MODE"
  local url="${base%/}/api/v2/log/main?last_known_id=0&normal=1"
  local -a curl_cmd=(curl -fsS --max-time 10 -c "$cookie" -b "$cookie" "$url")
  local response
  if ! response="$("${curl_cmd[@]}" 2>/dev/null)"; then
    if vpn_auto_reconnect_login_qbt; then
      response="$("${curl_cmd[@]}" 2>/dev/null || printf '')"
    fi
  fi
  if [[ -z "$response" ]] || ! command -v jq >/dev/null 2>&1; then
    return 1
  fi
  local thirty=$((30 * 60))
  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  local latest
  latest="$(jq '[.[] | select(.message | test("webui|webapi"; "i")) | .timestamp] | max // 0' <<<"$response" 2>/dev/null || printf '0')"
  [[ "$latest" =~ ^[0-9]+$ ]] || latest=0
  if ((latest > 0 && now - latest <= thirty)); then
    vpn_auto_reconnect_record_activity "$(vpn_auto_reconnect_epoch_to_iso "$latest" || printf '')"
    return 0
  fi
  local dl_activity
  dl_activity="$(jq '[.[] | select(.message | test("torrent added"; "i")) | .timestamp] | max // 0' <<<"$response" 2>/dev/null || printf '0')"
  [[ "$dl_activity" =~ ^[0-9]+$ ]] || dl_activity=0
  if ((dl_activity > 0 && now - dl_activity <= thirty)); then
    vpn_auto_reconnect_record_activity "$(vpn_auto_reconnect_epoch_to_iso "$dl_activity" || printf '')"
    return 0
  fi
  return 1
}

# Determines if measured speeds exceed busy threshold
vpn_auto_reconnect_high_load_detected() {
  if ! command -v nproc >/dev/null 2>&1; then
    return 1
  fi
  local cores
  cores="$(nproc 2>/dev/null || printf '1')"
  [[ "$cores" =~ ^[0-9]+$ ]] || cores=1
  local load
  if ! load="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"; then
    return 1
  fi
  if [[ -z "$load" ]]; then
    return 1
  fi
  if [[ ! "$load" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    return 1
  fi
  # Compare float load vs integer core count without truncation
  if awk -v l="$load" -v c="$cores" 'BEGIN { exit (l >= c) ? 0 : 1 }'; then
    return 0
  fi
  return 1
}

# Chooses next ProtonVPN country based on rotation list and failure history
vpn_auto_reconnect_pick_country() {
  local -a countries
  mapfile -t countries < <(vpn_auto_reconnect_parse_countries)
  if ((${#countries[@]} == 0)); then
    return 1
  fi
  local cooldown
  cooldown="$(vpn_auto_reconnect_cooldown_seconds)"
  local max_index=${#countries[@]}
  local index="${VPN_AUTO_STATE_ROTATION_INDEX:-0}"
  if [[ ! "$index" =~ ^[0-9]+$ ]]; then
    index=0
  fi
  local attempts=0
  while ((attempts < max_index)); do
    local candidate_index=$(((index + attempts) % max_index))
    local candidate="${countries[$candidate_index]}"
    # Skip countries that recently failed within the cooldown window
    if ! vpn_auto_reconnect_failure_recent "$candidate" "$cooldown"; then
      VPN_AUTO_STATE_ROTATION_INDEX="$candidate_index"
      printf '%s\n' "$candidate"
      return 0
    fi
    ((attempts++))
  done
  # All candidates are cooling down; fall back to sequential rotation.
  local fallback_index=$(((index + 1) % max_index))
  VPN_AUTO_STATE_ROTATION_INDEX="$fallback_index"
  printf '%s\n' "${countries[$fallback_index]}"
  return 0
}

# Sleeps for random jitter window to desynchronize multi-host rotations
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
    log_warn "[vpn-auto] docker command missing; cannot restart Gluetun"
    return 1
  fi
  if ! docker inspect gluetun >/dev/null 2>&1; then
    log_warn "[vpn-auto] Gluetun container not found"
    return 1
  fi
  if ! docker restart gluetun >/dev/null 2>&1; then
    log_warn "[vpn-auto] Failed to restart Gluetun"
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
    log_warn "[vpn-auto] docker command missing; cannot confirm Gluetun health"
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
      log_warn "[vpn-auto] curl not available; skipping Gluetun API verification"
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
  log_warn "[vpn-auto] VPN health endpoint did not respond within ${timeout}s"
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

  if ! command -v jq >/dev/null 2>&1; then
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

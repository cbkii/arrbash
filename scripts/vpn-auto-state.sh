# shellcheck shell=bash
# Purpose: Manage VPN auto-reconnect state files, persistence, and ProtonVPN forwarding metadata.
# Inputs: Uses ARR_DOCKER_DIR, ARR_STACK_DIR, VPN state variables, and depends on scripts/common.sh helpers.
# Outputs: Reads/writes JSON state files, lock-protected PF data, and status summaries for monitoring.
# Exit codes: Functions return non-zero when state files cannot be read or written safely.
if [[ -n "${__VPN_AUTO_STATE_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_STATE_LOADED=1

_escape_json_string() {
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

# shellcheck shell=bash
# VPN auto-reconnect helpers sourced by stack components
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
VPN_AUTO_RECONNECT_JQ_AVAILABLE=-1
VPN_AUTO_RECONNECT_CURRENT_INTERVAL=0
VPN_AUTO_RECONNECT_IDLE_GRACE_SECONDS=1800
VPN_AUTO_RECONNECT_ACTIVITY_GRACE_SECONDS=1800
VPN_AUTO_RECONNECT_PF_SUCCESS_GRACE=86400
VPN_AUTO_RECONNECT_SEEDING_FLOOR_BYTES=4096
VPN_AUTO_RECONNECT_SUPPRESS_RETRY=0

# Resolves Gluetun root directory via shared helpers when available
vpn_auto_gluetun_root() {
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    arr_gluetun_dir
    return
  fi

  local docker_root="${ARR_DOCKER_DIR:-}"
  if [[ -z "$docker_root" ]]; then
    if declare -f arr_docker_data_root >/dev/null 2>&1; then
      docker_root="$(arr_docker_data_root)"
    fi
  fi

  if [[ -z "$docker_root" ]]; then
    return 1
  fi

  printf '%s/gluetun' "${docker_root%/}"
}

# Caches jq availability checks to avoid repeated command lookups
vpn_auto_has_jq() {
  if ((VPN_AUTO_RECONNECT_JQ_AVAILABLE == -1)); then
    if command -v jq >/dev/null 2>&1; then
      VPN_AUTO_RECONNECT_JQ_AVAILABLE=1
    else
      VPN_AUTO_RECONNECT_JQ_AVAILABLE=0
    fi
  fi

  ((VPN_AUTO_RECONNECT_JQ_AVAILABLE == 1))
}

# Resolves auto-reconnect working directory under dockarr
vpn_auto_reconnect_state_dir() {
  if declare -f arr_gluetun_auto_reconnect_dir >/dev/null 2>&1; then
    arr_gluetun_auto_reconnect_dir
    return
  fi

  local root=""
  root="$(vpn_auto_gluetun_root 2>/dev/null || printf '')"
  if [[ -z "$root" ]]; then
    return 1
  fi

  printf '%s/auto-reconnect' "$root"
}

# Helper: Returns path to a file under the auto-reconnect state directory
vpn_auto_reconnect_state_path() {
  local filename="$1"
  local dir
  dir="$(vpn_auto_reconnect_state_dir 2>/dev/null)" || return 1
  printf '%s/%s' "$dir" "$filename"
}

# Returns path to persisted state.json for reconnect worker
vpn_auto_reconnect_state_file() {
  vpn_auto_reconnect_state_path "state.json"
}

# Cookie jar used for qBittorrent API sessions
vpn_auto_reconnect_cookie_file() {
  vpn_auto_reconnect_state_path "session.cookie"
}

# History log tracking reconnect attempts and outcomes
vpn_auto_reconnect_history_file() {
  vpn_auto_reconnect_state_path "history.log"
}

# Path to human-readable status JSON stored alongside stack root
vpn_auto_reconnect_status_file() {
  local stack_dir="${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}"
  printf '%s/.vpn-auto-reconnect-status.json' "${stack_dir%/}"
}

if ! declare -f pf_state_lock_file >/dev/null 2>&1; then
  pf_state_lock_file() {
    local state_file=""
    if declare -f pf_state_path >/dev/null 2>&1; then
      state_file="$(pf_state_path)"
    else
      local pf_file="${PF_ASYNC_STATE_FILE:-pf-state.json}"
      local root=""
      root="$(vpn_auto_gluetun_root 2>/dev/null || printf '')"
      if [[ -n "$root" ]]; then
        state_file="${root}/${pf_file}"
      fi
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
  local pf_file="${PF_ASYNC_STATE_FILE:-pf-state.json}"
  local root=""
  root="$(vpn_auto_gluetun_root 2>/dev/null || printf '')"
  if [[ -z "$root" ]]; then
    return 1
  fi

  printf '%s/%s' "$root" "$pf_file"
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
    base_dir="$(vpn_auto_gluetun_root 2>/dev/null || printf '')"
    if [[ -z "$base_dir" ]]; then
      return 0
    fi
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
    if vpn_auto_has_jq; then
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
  if ! vpn_auto_has_jq; then
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
  if vpn_auto_has_jq; then
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
    local last_country_json
    last_country_json="\"$(_escape_json_string "${VPN_AUTO_STATE_LAST_COUNTRY:-}")\""

    local last_reconnect_raw="${VPN_AUTO_STATE_LAST_RECONNECT:-}"
    local last_reconnect_json="null"
    if [[ -n "$last_reconnect_raw" ]]; then
      last_reconnect_json="\"$(_escape_json_string "$last_reconnect_raw")\""
    fi

    local last_status_json
    last_status_json="\"$(_escape_json_string "${VPN_AUTO_STATE_LAST_STATUS:-}")\""

    local last_activity_raw="${VPN_AUTO_STATE_LAST_ACTIVITY:-}"
    local last_activity_json="null"
    if [[ -n "$last_activity_raw" ]]; then
      last_activity_json="\"$(_escape_json_string "$last_activity_raw")\""
    fi

    local last_low_raw="${VPN_AUTO_STATE_LAST_LOW:-}"
    local last_low_json="null"
    if [[ -n "$last_low_raw" ]]; then
      last_low_json="\"$(_escape_json_string "$last_low_raw")\""
    fi

    local classification_json
    classification_json="\"$(_escape_json_string "${VPN_AUTO_STATE_CLASSIFICATION:-monitoring}")\""

    local failure_history_value="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
    local failure_history_json
    local trimmed_failure
    trimmed_failure="$(printf '%s' "$failure_history_value" | LC_ALL=C sed '1s/^[[:space:]]*//' 2>/dev/null || printf '')"
    if [[ -z "$trimmed_failure" ]]; then
      failure_history_json='{}'
    elif [[ "$trimmed_failure" == \{* || "$trimmed_failure" == \[* ]]; then
      failure_history_json="$failure_history_value"
    else
      failure_history_json="\"$(_escape_json_string "$failure_history_value")\""
    fi

    json=$(
      cat <<JSON
{
  "version": ${VPN_AUTO_RECONNECT_STATE_VERSION},
  "updated": $(vpn_auto_reconnect_now_epoch),
  "consecutive_low": ${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0},
  "rotation_index": ${VPN_AUTO_STATE_ROTATION_INDEX:-0},
  "last_country": ${last_country_json},
  "last_reconnect": ${last_reconnect_json},
  "last_status": ${last_status_json},
  "last_activity": ${last_activity_json},
  "last_low": ${last_low_json},
  "cooldown_until": ${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0},
  "disabled_until": ${VPN_AUTO_STATE_DISABLED_UNTIL:-0},
  "auto_disabled": ${VPN_AUTO_STATE_AUTO_DISABLED:-0},
  "retry_backoff": ${VPN_AUTO_STATE_RETRY_BACKOFF:-5},
  "retry_total": ${VPN_AUTO_STATE_RETRY_TOTAL:-0},
  "next_decision_at": ${VPN_AUTO_STATE_NEXT_DECISION:-0},
  "rotation_day_epoch": ${VPN_AUTO_STATE_ROTATION_DAY_EPOCH:-0},
  "rotation_count_day": ${VPN_AUTO_STATE_ROTATION_COUNT_DAY:-0},
  "classification": ${classification_json},
  "jitter_applied": ${VPN_AUTO_STATE_JITTER_APPLIED:-0},
  "next_possible_action": ${VPN_AUTO_STATE_NEXT_ACTION:-0},
  "restart_failures": ${VPN_AUTO_STATE_RESTART_FAILURES:-0},
  "failure_history": ${failure_history_json}
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
  if vpn_auto_has_jq; then
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

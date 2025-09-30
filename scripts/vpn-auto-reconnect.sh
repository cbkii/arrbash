# shellcheck shell=bash
# VPN auto-reconnect helpers sourced by arrstack components

VPN_AUTO_RECONNECT_STATE_VERSION=1
VPN_AUTO_RECONNECT_CURL_WARNED=0

vpn_auto_reconnect_state_dir() {
  local base="${ARR_DOCKER_DIR:-}";
  if [[ -z "$base" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      base="${ARR_STACK_DIR%/}/docker-data"
    else
      base="${HOME:-.}/srv/docker-data"
    fi
  fi
  printf '%s/gluetun/auto-reconnect' "${base%/}"
}

vpn_auto_reconnect_state_file() {
  printf '%s/state.json' "$(vpn_auto_reconnect_state_dir)"
}

vpn_auto_reconnect_status_file() {
  local stack_dir="${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}"
  printf '%s/.vpn-auto-reconnect-status.json' "${stack_dir%/}"
}

vpn_auto_reconnect_cookie_file() {
  printf '%s/session.cookie' "$(vpn_auto_reconnect_state_dir)"
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

vpn_auto_reconnect_now_epoch() {
  date -u +%s
}

vpn_auto_reconnect_epoch_to_iso() {
  local epoch="$1"
  if [[ -z "$epoch" || ! "$epoch" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ'
}

vpn_auto_reconnect_iso_to_epoch() {
  local iso="$1"
  if [[ -z "$iso" ]]; then
    return 1
  fi
  date -u -d "$iso" '+%s' 2>/dev/null || return 1
}

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
  done < <(vpn_auto_reconnect_split_csv "$combined")
  printf '%s\n' "${ordered[@]}"
}

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
}

vpn_auto_reconnect_reset_state

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
  VPN_AUTO_STATE_CONSECUTIVE_LOW="$(jq -r '.consecutive_low // 0' <<<"$json" 2>/dev/null || printf '0')"
  VPN_AUTO_STATE_ROTATION_INDEX="$(jq -r '.rotation_index // 0' <<<"$json" 2>/dev/null || printf '0')"
  VPN_AUTO_STATE_LAST_COUNTRY="$(jq -r '.last_country // ""' <<<"$json" 2>/dev/null || printf '')"
  VPN_AUTO_STATE_LAST_RECONNECT="$(jq -r '.last_reconnect // ""' <<<"$json" 2>/dev/null || printf '')"
  VPN_AUTO_STATE_LAST_STATUS="$(jq -r '.last_status // ""' <<<"$json" 2>/dev/null || printf '')"
  VPN_AUTO_STATE_LAST_ACTIVITY="$(jq -r '.last_activity // ""' <<<"$json" 2>/dev/null || printf '')"
  VPN_AUTO_STATE_LAST_LOW="$(jq -r '.last_low // ""' <<<"$json" 2>/dev/null || printf '')"
  VPN_AUTO_STATE_FAILURE_HISTORY="$(jq -c '.failure_history // {}' <<<"$json" 2>/dev/null || printf '{}')"
  VPN_AUTO_STATE_COOLDOWN_UNTIL="$(jq -r '.cooldown_until // 0' <<<"$json" 2>/dev/null || printf '0')"
  VPN_AUTO_STATE_DISABLED_UNTIL="$(jq -r '.disabled_until // 0' <<<"$json" 2>/dev/null || printf '0')"
  VPN_AUTO_STATE_AUTO_DISABLED="$(jq -r '.auto_disabled // 0' <<<"$json" 2>/dev/null || printf '0')"
  VPN_AUTO_STATE_RETRY_BACKOFF="$(jq -r '.retry_backoff // 5' <<<"$json" 2>/dev/null || printf '5')"
  VPN_AUTO_STATE_RETRY_TOTAL="$(jq -r '.retry_total // 0' <<<"$json" 2>/dev/null || printf '0')"
}

vpn_auto_reconnect_write_state() {
  local file
  file="$(vpn_auto_reconnect_state_file)"
  local dir
  dir="$(dirname -- "$file")"
  ensure_dir_mode "$dir" "$DATA_DIR_MODE"
  local json
  if command -v jq >/dev/null 2>&1; then
    json="$(jq -nc \
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
      --argjson now "$(vpn_auto_reconnect_now_epoch)" \
      --argjson failure_history "${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}" \
      '{version:$version,updated:$now,consecutive_low:$consecutive_low,rotation_index:$rotation_index,last_country:$last_country,last_reconnect:($last_reconnect==""?null:$last_reconnect),last_status:$last_status,last_activity:($last_activity==""?null:$last_activity),last_low:($last_low==""?null:$last_low),cooldown_until:$cooldown_until,disabled_until:$disabled_until,auto_disabled:$auto_disabled,retry_backoff:$retry_backoff,retry_total:$retry_total,failure_history:$failure_history}'
    )"
  else
    json=$(cat <<JSON
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
  "failure_history": ${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}
}
JSON
)
  fi
  printf '%s\n' "$json" >"$file"
  ensure_secret_file_mode "$file"
}

vpn_auto_reconnect_write_status() {
  local status_file
  status_file="$(vpn_auto_reconnect_status_file)"
  local dir
  dir="$(dirname -- "$status_file")"
  ensure_dir "$dir"
  local now_iso
  now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local payload
  if command -v jq >/dev/null 2>&1; then
    payload="$(jq -nc \
      --arg timestamp "$now_iso" \
      --arg status "${1:-idle}" \
      --arg detail "${2:-}" \
      --argjson consecutive_low "${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0}" \
      --arg last_country "${VPN_AUTO_STATE_LAST_COUNTRY:-}" \
      --arg last_reconnect "${VPN_AUTO_STATE_LAST_RECONNECT:-}" \
      --arg last_activity "${VPN_AUTO_STATE_LAST_ACTIVITY:-}" \
      --argjson cooldown_until "${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0}" \
      --argjson disabled_until "${VPN_AUTO_STATE_DISABLED_UNTIL:-0}" \
      --argjson auto_disabled "${VPN_AUTO_STATE_AUTO_DISABLED:-0}" \
      '{timestamp:$timestamp,status:$status,detail:$detail,consecutive_low:$consecutive_low,last_country:$last_country,last_reconnect:$last_reconnect,last_activity:$last_activity,cooldown_until:$cooldown_until,disabled_until:$disabled_until,auto_disabled:$auto_disabled}'
    )"
  else
    payload=$(cat <<JSON
{
  "timestamp": "$now_iso",
  "status": "${1:-idle}",
  "detail": "${2:-}",
  "consecutive_low": ${VPN_AUTO_STATE_CONSECUTIVE_LOW:-0},
  "last_country": "${VPN_AUTO_STATE_LAST_COUNTRY:-}",
  "last_reconnect": "${VPN_AUTO_STATE_LAST_RECONNECT:-}",
  "last_activity": "${VPN_AUTO_STATE_LAST_ACTIVITY:-}",
  "cooldown_until": ${VPN_AUTO_STATE_COOLDOWN_UNTIL:-0},
  "disabled_until": ${VPN_AUTO_STATE_DISABLED_UNTIL:-0},
  "auto_disabled": ${VPN_AUTO_STATE_AUTO_DISABLED:-0}
}
JSON
)
  fi
  printf '%s\n' "$payload" >"$status_file"
  ensure_nonsecret_file_mode "$status_file"
}

vpn_auto_reconnect_is_enabled() {
  [[ "${VPN_AUTO_RECONNECT_ENABLED:-0}" == "1" ]]
}

vpn_auto_reconnect_load_env() {
  local env_file="${ARR_ENV_FILE:-}";
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

vpn_auto_reconnect_speed_threshold_bytes() {
  local kbps="${VPN_SPEED_THRESHOLD_KBPS:-12}"
  [[ "$kbps" =~ ^[0-9]+$ ]] || kbps=12
  if ((kbps <= 0)); then
    kbps=12
  fi
  printf '%s' $((kbps * 125))
}

vpn_auto_reconnect_check_interval_seconds() {
  local minutes="${VPN_CHECK_INTERVAL_MINUTES:-20}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=20
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' $((minutes * 60))
}

vpn_auto_reconnect_consecutive_required() {
  local count="${VPN_CONSECUTIVE_CHECKS:-3}"
  [[ "$count" =~ ^[0-9]+$ ]] || count=3
  if ((count <= 0)); then
    count=3
  fi
  printf '%s' "$count"
}

vpn_auto_reconnect_cooldown_seconds() {
  local minutes="${VPN_COOLDOWN_MINUTES:-60}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=60
  if ((minutes <= 0)); then
    minutes=60
  fi
  printf '%s' $((minutes * 60))
}

vpn_auto_reconnect_max_retry_minutes() {
  local minutes="${VPN_MAX_RETRY_MINUTES:-20}"
  [[ "$minutes" =~ ^[0-9]+$ ]] || minutes=20
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' "$minutes"
}

vpn_auto_reconnect_allowed_window_active() {
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
  ((now+=0)) || true
  ((start_hour+=0)) || true
  ((end_hour+=0)) || true
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

vpn_auto_reconnect_override_path() {
  printf '%s/.vpn-auto-reconnect-%s' "${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}" "$1"
}

vpn_auto_reconnect_manual_pause_active() {
  local file
  file="$(vpn_auto_reconnect_override_path pause)"
  [[ -f "$file" ]]
}

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

vpn_auto_reconnect_force_once_requested() {
  local file
  file="$(vpn_auto_reconnect_override_path once)"
  [[ -f "$file" ]]
}

vpn_auto_reconnect_consume_force_once_flag() {
  local file
  file="$(vpn_auto_reconnect_override_path once)"
  if [[ -f "$file" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}

vpn_auto_reconnect_record_activity() {
  local iso="$1"
  VPN_AUTO_STATE_LAST_ACTIVITY="$iso"
}

vpn_auto_reconnect_record_low() {
  local iso="$1"
  VPN_AUTO_STATE_LAST_LOW="$iso"
}

vpn_auto_reconnect_failure_history_update() {
  local country="$1"
  local timestamp="$2"
  if ! command -v jq >/dev/null 2>&1; then
    VPN_AUTO_STATE_FAILURE_HISTORY="{}"
    return
  fi
  local current
  current="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
  VPN_AUTO_STATE_FAILURE_HISTORY="$(jq --arg country "$country" --argjson ts "$timestamp" '.[$country]=$ts' <<<"$current" 2>/dev/null || printf '{}')"
}

vpn_auto_reconnect_failure_recent() {
  local country="$1"
  local cutoff="$2"
  if ! command -v jq >/dev/null 2>&1; then
    return 1
  fi
  local current
  current="${VPN_AUTO_STATE_FAILURE_HISTORY:-{}}"
  local ts
  ts="$(jq -r --arg country "$country" '.[$country] // 0' <<<"$current" 2>/dev/null || printf '0')"
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
  load=${load%%.*}
  if [[ -z "$load" ]]; then
    return 1
  fi
  if ((load >= cores)); then
    return 0
  fi
  return 1
}

vpn_auto_reconnect_pick_country() {
  local -a countries
  mapfile -t countries < <(vpn_auto_reconnect_parse_countries)
  if ((${#countries[@]} == 0)); then
    return 1
  fi
  local now
  now="$(vpn_auto_reconnect_now_epoch)"
  local cooldown
  cooldown="$(vpn_auto_reconnect_cooldown_seconds)"
  local max_index=${#countries[@]}
  local attempts=0
  local index="${VPN_AUTO_STATE_ROTATION_INDEX:-0}"
  if [[ ! "$index" =~ ^[0-9]+$ ]]; then
    index=0
  fi
  while ((attempts < max_index)); do
    local candidate_index=$(((index + attempts) % max_index))
    local candidate="${countries[$candidate_index]}"
    if vpn_auto_reconnect_failure_recent "$candidate" "$cooldown"; then
      VPN_AUTO_STATE_ROTATION_INDEX="$candidate_index"
      printf '%s\n' "$candidate"
      return 0
    fi
    ((attempts++))
  done
  VPN_AUTO_STATE_ROTATION_INDEX=$(((index + 1) % max_index))
  printf '%s\n' "${countries[$VPN_AUTO_STATE_ROTATION_INDEX]}"
  return 0
}

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

vpn_auto_reconnect_apply_country() {
  local country="$1"
  if [[ -z "$country" ]]; then
    return 1
  fi
  persist_env_var "SERVER_COUNTRIES" "$country"
  VPN_AUTO_STATE_LAST_COUNTRY="$country"
}

vpn_auto_reconnect_attempt() {
  local country="$1"
  local now
  now="$(vpn_auto_reconnect_now_epoch)"

  local min_interval=300
  if [[ -n "${VPN_AUTO_STATE_LAST_RECONNECT:-}" ]]; then
    local last_epoch
    last_epoch="$(vpn_auto_reconnect_iso_to_epoch "$VPN_AUTO_STATE_LAST_RECONNECT" || echo 0)"
    [[ "$last_epoch" =~ ^[0-9]+$ ]] || last_epoch=0
    if ((now - last_epoch < min_interval)); then
      local wait_time=$((min_interval - (now - last_epoch)))
      vpn_auto_reconnect_write_status "throttled" "Rate limit: wait ${wait_time}s before next attempt"
      return 1
    fi
  fi
  if ! vpn_auto_reconnect_apply_country "$country"; then
    vpn_auto_reconnect_write_status "error" "Failed to update SERVER_COUNTRIES"
    return 1
  fi
  if ! vpn_auto_reconnect_restart_gluetun; then
    vpn_auto_reconnect_failure_history_update "$country" "$now"
    vpn_auto_reconnect_write_status "error" "Gluetun restart failed"
    return 1
  fi
  if ! vpn_auto_reconnect_wait_for_health; then
    vpn_auto_reconnect_failure_history_update "$country" "$now"
    vpn_auto_reconnect_write_status "error" "VPN health check failed"
    return 1
  fi
  VPN_AUTO_STATE_LAST_RECONNECT="$(vpn_auto_reconnect_epoch_to_iso "$now" || printf '')"
  VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  VPN_AUTO_STATE_COOLDOWN_UNTIL=$((now + $(vpn_auto_reconnect_cooldown_seconds)))
  VPN_AUTO_STATE_RETRY_BACKOFF=5
  VPN_AUTO_STATE_RETRY_TOTAL=0
  VPN_AUTO_STATE_AUTO_DISABLED=0
  VPN_AUTO_STATE_LAST_STATUS="Reconnected to ${country}"
  vpn_auto_reconnect_write_status "reconnected" "Switched to ${country}"
  return 0
}

vpn_auto_reconnect_handle_retry_failure() {
  local backoff="${VPN_AUTO_STATE_RETRY_BACKOFF:-5}"
  [[ "$backoff" =~ ^[0-9]+$ ]] || backoff=5
  local total="${VPN_AUTO_STATE_RETRY_TOTAL:-0}"
  [[ "$total" =~ ^[0-9]+$ ]] || total=0
  total=$((total + backoff))
  VPN_AUTO_STATE_RETRY_TOTAL="$total"
  local max_minutes
  max_minutes="$(vpn_auto_reconnect_max_retry_minutes)"
  if ((backoff < max_minutes)); then
    local next=$((backoff * 2))
    if ((next > max_minutes)); then
      next=$max_minutes
    fi
    VPN_AUTO_STATE_RETRY_BACKOFF="$next"
  fi
  if ((total >= max_minutes)); then
    VPN_AUTO_STATE_AUTO_DISABLED=1
    VPN_AUTO_STATE_DISABLED_UNTIL=$(( $(vpn_auto_reconnect_now_epoch) + $(vpn_auto_reconnect_cooldown_seconds) ))
    VPN_AUTO_STATE_LAST_STATUS="Auto-disabled after retry budget exhausted"
    vpn_auto_reconnect_write_status "disabled" "Retry budget exceeded; touch .vpn-auto-reconnect-once to override"
  fi
}

vpn_auto_reconnect_should_attempt() {
  local force="${1:-0}"

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
    return 1
  fi

  if ((force == 0)) && vpn_auto_reconnect_allowed_window_active; then
    vpn_auto_reconnect_write_status "waiting" "Outside allowed window"
    return 1
  fi

  if ((force == 0)) && ((VPN_AUTO_STATE_COOLDOWN_UNTIL > now)); then
    vpn_auto_reconnect_write_status "cooldown" "Cooling down until $(vpn_auto_reconnect_epoch_to_iso "$VPN_AUTO_STATE_COOLDOWN_UNTIL" || printf '')"
    return 1
  fi

  return 0
}

vpn_auto_reconnect_process_once() {
  vpn_auto_reconnect_load_env
  vpn_auto_reconnect_load_state
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
    vpn_auto_reconnect_write_status "error" "Failed to query qBittorrent speeds"
    vpn_auto_reconnect_write_state
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    vpn_auto_reconnect_write_status "error" "jq is required"
    vpn_auto_reconnect_write_state
    return 1
  fi
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
  if ((total_speed < threshold)); then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=$((VPN_AUTO_STATE_CONSECUTIVE_LOW + 1))
    vpn_auto_reconnect_record_low "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  else
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
  fi
  local active=1
  if vpn_auto_reconnect_detect_activity; then
    active=0
  fi
  if ((dl_speed > 1048576 || up_speed > 1048576)); then
    active=0
  fi
  if vpn_auto_reconnect_high_load_detected; then
    active=0
  fi
  if ((active == 0)); then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=0
    vpn_auto_reconnect_write_status "busy" "User or system activity detected"
    vpn_auto_reconnect_write_state
    return 0
  fi
  local required
  required="$(vpn_auto_reconnect_consecutive_required)"
  if ((force)); then
    VPN_AUTO_STATE_CONSECUTIVE_LOW=$required
  fi
  if ((VPN_AUTO_STATE_CONSECUTIVE_LOW < required)); then
    VPN_AUTO_STATE_LAST_STATUS="$status_detail"
    vpn_auto_reconnect_write_status "monitoring" "$status_detail"
    vpn_auto_reconnect_write_state
    return 0
  fi
  local country
  if ! country="$(vpn_auto_reconnect_pick_country)"; then
    vpn_auto_reconnect_write_status "error" "No Proton countries available"
    vpn_auto_reconnect_write_state
    return 1
  fi
  if ! vpn_auto_reconnect_attempt "$country"; then
    vpn_auto_reconnect_handle_retry_failure
    vpn_auto_reconnect_write_state
    return 1
  fi
  vpn_auto_reconnect_write_state
  return 0
}

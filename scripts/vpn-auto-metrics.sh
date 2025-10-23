# shellcheck shell=bash
# Purpose: Gather qBittorrent metrics and activity signals driving VPN reconnect decisions.
# Inputs: Requires access to qBittorrent credentials, ARR_DOCKER_DIR, and docker CLI for container execs.
# Outputs: Updates runtime globals indicating transfer rates, authentication status, and seeding activity.
# Exit codes: Functions return non-zero when metric collection fails or qBittorrent authentication is denied.
if [[ -n "${__VPN_AUTO_METRICS_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_METRICS_LOADED=1

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
  local default_base="http://${LOCALHOST_IP:-127.0.0.1}:${QBT_INT_PORT:-8082}"
  local base="${QBITTORRENT_ADDR:-${default_base}}"
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
  local default_base="http://${LOCALHOST_IP:-127.0.0.1}:${QBT_INT_PORT:-8082}"
  local base="${QBITTORRENT_ADDR:-${default_base}}"
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
  local default_base="http://${LOCALHOST_IP:-127.0.0.1}:${QBT_INT_PORT:-8082}"
  local base="${QBITTORRENT_ADDR:-${default_base}}"
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
  if [[ -z "$response" ]] || ! vpn_auto_has_jq; then
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
    # shellcheck disable=SC2178,SC2128  # candidate comes from array indexing but is used as a scalar
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


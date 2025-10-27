# shellcheck shell=bash
# Purpose: Provide qBittorrent helpers for the VPN watchdog.
# Inputs: QBT_USER/QBT_PASS/QBT_INT_PORT, LOCALHOST_IP, ARR_DOCKER_DIR.
# Outputs: Functions to read or update the qBittorrent listen port.
# Exit codes: Helpers return non-zero when the WebUI API is unavailable.
#
# Historical issue: this module previously scraped transfer metrics, relied on mapfile,
# and broke under zsh. The refactor limits the surface to the port-alignment logic the
# watchdog needs after Gluetun recoveries.

if [[ -n "${__VPN_AUTO_METRICS_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_METRICS_LOADED=1

vpn_auto_qbt_base_url() {
  local default="http://${LOCALHOST_IP:-127.0.0.1}:${QBT_INT_PORT:-8082}"
  if [[ -n "${QBITTORRENT_ADDR:-}" ]]; then
    printf '%s\n' "${QBITTORRENT_ADDR%/}"
    return
  fi
  printf '%s\n' "${default%/}"
}

vpn_auto_qbt_cookie_file() {
  vpn_auto_cookie_file
}

vpn_auto_qbt_login() {
  local user="${QBT_USER:-}"
  local pass="${QBT_PASS:-}"
  local base
  base="$(vpn_auto_qbt_base_url)"
  local cookie
  cookie="$(vpn_auto_qbt_cookie_file 2>/dev/null || printf '')"
  if [[ -z "$cookie" ]]; then
    return 1
  fi
  ensure_dir_mode "$(dirname -- "$cookie")" "$DATA_DIR_MODE"
  if [[ -z "$user" || -z "$pass" ]]; then
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  curl -fsS --max-time 8 -c "$cookie" \
    --data-urlencode "username=${user}" \
    --data-urlencode "password=${pass}" \
    "${base}/api/v2/auth/login" >/dev/null 2>&1
}

vpn_auto_qbt_get_listen_port() {
  local base
  base="$(vpn_auto_qbt_base_url)"
  local cookie
  cookie="$(vpn_auto_qbt_cookie_file 2>/dev/null || printf '')"
  if [[ -z "$cookie" ]]; then
    return 1
  fi
  ensure_dir_mode "$(dirname -- "$cookie")" "$DATA_DIR_MODE"
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  local url="${base}/api/v2/app/preferences"
  local response
  if [[ -f "$cookie" ]]; then
    response="$(curl -fsS --max-time 8 -b "$cookie" "$url" 2>/dev/null || printf '')"
  fi
  if [[ -z "$response" ]]; then
    if vpn_auto_qbt_login; then
      response="$(curl -fsS --max-time 8 -b "$cookie" "$url" 2>/dev/null || printf '')"
    fi
  fi
  if [[ -z "$response" ]]; then
    return 1
  fi
  local listen port_random
  listen="$(vpn_auto_json_get_number "$response" listen_port)"
  port_random="$(vpn_auto_json_get_number "$response" random_port)"
  if [[ "$port_random" == "1" ]]; then
    return 1
  fi
  printf '%s' "$listen"
}

vpn_auto_qbt_sync_port() {
  local target="$1"
  if [[ -z "$target" || "$target" == "0" ]]; then
    return 1
  fi
  local hook
  hook="$(vpn_auto_pf_hook_path 2>/dev/null || printf '')"
  if [[ -z "$hook" || ! -x "$hook" ]]; then
    return 1
  fi
  "$hook" "$target"
}

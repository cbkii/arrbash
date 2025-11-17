# shellcheck shell=bash
# Purpose: Normalise configuration inputs for the VPN watchdog.
# Inputs: Environment variables sourced from ${ARR_STACK_DIR}/.env.
# Outputs: Helper functions returning intervals, grace periods, and feature toggles.
# Exit codes: Functions emit zero on success; helpers return sensible defaults when env values are missing.
#
# Historical issue: the previous module mixed qBittorrent throughput heuristics with VPN
# recovery settings and assumed Bash-only constructs. The refactored version focuses on
# Gluetun health parameters, keeps the interface zsh-safe, and avoids mutating .env files.

if [[ -n "${__VPN_AUTO_CONFIG_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_CONFIG_LOADED=1

vpn_auto_reconnect_load_env() {
  local env_file="${ARR_ENV_FILE:-}"
  if [[ -z "$env_file" ]]; then
    if declare -f arr_env_file >/dev/null 2>&1; then
      env_file="$(arr_env_file)"
    elif [[ -n "${ARR_STACK_DIR:-}" ]]; then
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

vpn_auto_reconnect_is_enabled() {
  [[ "${VPN_AUTO_RECONNECT_ENABLED:-1}" == "1" ]]
}

vpn_auto_reconnect_check_interval_seconds() {
  local minutes="${VPN_CHECK_INTERVAL_MINUTES:-20}"
  case "$minutes" in
    '' | *[!0-9]*) minutes=20 ;;
  esac
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' $((minutes * 60))
}

vpn_auto_reconnect_cooldown_seconds() {
  local minutes="${VPN_COOLDOWN_MINUTES:-15}"
  case "$minutes" in
    '' | *[!0-9]*) minutes=15 ;;
  esac
  if ((minutes <= 0)); then
    minutes=15
  fi
  printf '%s' $((minutes * 60))
}

vpn_auto_reconnect_retry_delay_seconds() {
  local seconds="${VPN_RETRY_DELAY_SECONDS:-120}"
  case "$seconds" in
    '' | *[!0-9]*) seconds=120 ;;
  esac
  if ((seconds <= 0)); then
    seconds=120
  fi
  printf '%s' "$seconds"
}

vpn_auto_wireguard_fallback_timeout_seconds() {
  local seconds="${WG_FALLBACK_TIMEOUT_SECONDS:-120}"
  case "$seconds" in
    '' | *[!0-9]*) seconds=120 ;;
  esac
  if ((seconds <= 0)); then
    seconds=120
  fi
  printf '%s' "$seconds"
}

vpn_auto_reconnect_pf_grace_seconds() {
  local seconds="${VPN_PORT_GRACE_SECONDS:-300}"
  case "$seconds" in
    '' | *[!0-9]*) seconds=300 ;;
  esac
  if ((seconds <= 0)); then
    seconds=300
  fi
  printf '%s' "$seconds"
}

vpn_auto_pf_required() {
  local provider="${VPN_SERVICE_PROVIDER:-protonvpn}"
  provider="$(printf '%s' "$provider" | tr '[:upper:]' '[:lower:]')"
  local vpn_type="${VPN_TYPE:-openvpn}"
  vpn_type="$(printf '%s' "$vpn_type" | tr '[:upper:]' '[:lower:]')"
  local pf="${VPN_PORT_FORWARDING:-on}"
  pf="$(printf '%s' "$pf" | tr '[:upper:]' '[:lower:]')"
  if [[ "$vpn_type" != "openvpn" ]]; then
    return 1
  fi
  case "$provider" in
    protonvpn) ;; # supported
    *) return 1 ;;
  esac
  case "$pf" in
    '' | off | false | 0 | disabled) return 1 ;;
  esac
  return 0
}

vpn_auto_control_endpoint() {
  local port="${GLUETUN_CONTROL_PORT:-8000}"
  local host="${LOCALHOST_IP:-127.0.0.1}"
  if [[ "$host" == *:* && "$host" != \[* ]]; then
    printf 'http://[%s]:%s' "$host" "$port"
  else
    printf 'http://%s:%s' "$host" "$port"
  fi
}

vpn_auto_api_key() {
  printf '%s' "${GLUETUN_API_KEY:-}"
}

vpn_auto_compose_available() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  if ! declare -f arr_resolve_compose_cmd >/dev/null 2>&1; then
    return 1
  fi
  arr_resolve_compose_cmd 0 >/dev/null 2>&1
}

vpn_auto_retry_budget_seconds() {
  local minutes="${VPN_MAX_RETRY_MINUTES:-20}"
  case "$minutes" in
    '' | *[!0-9]*) minutes=20 ;;
  esac
  if ((minutes <= 0)); then
    minutes=20
  fi
  printf '%s' $((minutes * 60))
}

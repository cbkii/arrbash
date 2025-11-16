#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

COMMON_LIB="${REPO_ROOT}/scripts/stack-common.sh"
NETWORK_LIB="${REPO_ROOT}/scripts/stack-network.sh"
if [[ -f "$COMMON_LIB" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "$COMMON_LIB"
fi
if [[ -f "$NETWORK_LIB" ]]; then
  # shellcheck source=scripts/stack-network.sh
  . "$NETWORK_LIB"
fi

if ! type -t validate_ipv4 >/dev/null 2>&1; then
  validate_ipv4() {
    local ip="${1:-}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a octets=()
    read -r -a octets <<<"$ip"
    local octet
    for octet in "${octets[@]}"; do
      [[ "$octet" =~ ^[0-9]+$ ]] || return 1
      if ((octet < 0 || octet > 255)); then
        return 1
      fi
    done
    return 0
  }
fi

if ! type -t is_private_ipv4 >/dev/null 2>&1; then
  is_private_ipv4() {
    local ip="${1:-}"
    validate_ipv4 "$ip" || return 1
    case "$ip" in
      10.*|127.*|192.168.*|169.254.*) return 0 ;;
      172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
      *) return 1 ;;
    esac
  }
fi

if ! type -t lan_ipv4_subnet_cidr >/dev/null 2>&1; then
  lan_ipv4_subnet_cidr() {
    local ip="${1:-}"
    validate_ipv4 "$ip" || return 1
    is_private_ipv4 "$ip" || return 1
    local IFS='.'
    local o1 o2 o3 _rest
    read -r o1 o2 o3 _rest <<<"$ip"
    printf '%s.%s.%s.0/24\n' "$o1" "$o2" "$o3"
  }
fi

if ! type -t normalize_csv >/dev/null 2>&1; then
  normalize_csv() {
    local input="${1:-}"
    input="${input//$'\r'/}"
    input="${input//$'\n'/,}"
    input="${input//$'\t'/,}"
    input="${input// /,}"
    local IFS=','
    local -a parts=()
    read -r -a parts <<<"$input"
    local -a cleaned=()
    local part trimmed
    for part in "${parts[@]}"; do
      trimmed="$(printf '%s' "$part" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      [[ -z "$trimmed" ]] && continue
      cleaned+=("$trimmed")
    done
    if ((${#cleaned[@]})); then
      (IFS=','; printf '%s\n' "${cleaned[*]}")
    else
      printf '%s\n' ""
    fi
  }
fi

if ! type -t sanitize_user >/dev/null 2>&1; then
  sanitize_user() {
    local input="${1:-}"
    local sanitized
    sanitized="${input,,}"
    sanitized="${sanitized//[^a-z0-9._-]/}"
    printf '%s\n' "$sanitized"
  }
fi

resolve_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    printf '%s\n' ""
    return 0
  fi
  if [[ "$path" == '-' ]]; then
    printf '%s\n' "$path"
    return 0
  fi
  if [[ "$path" != /* ]]; then
    local base="${PWD:-$(pwd)}"
    if command -v realpath >/dev/null 2>&1; then
      (
        cd "$base" 2>/dev/null || return 1
        realpath -m -- "$path"
      )
    else
      (
        cd "$base" 2>/dev/null || return 1
        printf '%s/%s\n' "$(pwd -P)" "$path"
      )
    fi
  else
    printf '%s\n' "$path"
  fi
}

TEMPLATE_ARG="${1:-}"
if [[ -z "$TEMPLATE_ARG" ]]; then
  TEMPLATE_ARG="${REPO_ROOT}/.env.template"
fi
OUT_ARG="${2:-}"
CONF_ARG="${3:-}"
DEFAULTS_ARG="${USERR_DEFAULTS:-}"
if [[ -z "$DEFAULTS_ARG" ]]; then
  DEFAULTS_ARG="${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
fi

TEMPLATE_PATH="$(resolve_path "$TEMPLATE_ARG")"
DEFAULTS_PATH="$(resolve_path "$DEFAULTS_ARG")"
CONF_PATH="${CONF_ARG:-${USERR_CONF:-${REPO_ROOT}/arrconf/userr.conf}}"
CONF_PATH="$(resolve_path "$CONF_PATH")"

if [[ ! -f "$TEMPLATE_PATH" ]]; then
  printf 'error: template not found: %s\n' "$TEMPLATE_PATH" >&2
  exit 1
fi

if ! command -v envsubst >/dev/null 2>&1; then
  printf 'error: envsubst not found. Install gettext-base (Debian/Ubuntu) or gettext.\n' >&2
  exit 1
fi

if [[ -f "$DEFAULTS_PATH" ]]; then
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "$DEFAULTS_PATH"
fi
if [[ -f "$CONF_PATH" ]]; then
  # shellcheck source=/dev/null
  . "$CONF_PATH"
fi

if command -v arr_set_docker_services_list >/dev/null 2>&1; then
  arr_set_docker_services_list
fi

filter_conditionals() {
  awk '
    function truthy(v) {
      return (v=="1" || v=="true" || v=="TRUE" || v=="yes" || v=="YES" || v=="on" || v=="ON")
    }
    /^[[:space:]]*#[[:space:]]*@if[[:space:]]+/ {
      level++
      var=$0
      sub(/^[[:space:]]*#[[:space:]]*@if[[:space:]]+/, "", var)
      sub(/[[:space:]].*$/, "", var)
      keep[level] = truthy(ENVIRON[var]) ? 1 : 0
      next
    }
    /^[[:space:]]*#[[:space:]]*@endif/ {
      if (level>0) { delete keep[level]; level-- }
      next
    }
    {
      skip=0
      for (i=1;i<=level;i++) {
        if (keep[i]==0) { skip=1; break }
      }
      if (!skip) {
        print
      }
    }
  '
}

# ---- Derived defaults ----
: "${STACK:=arr}"
: "${ARR_DATA_ROOT:=${HOME%/}/srv}"
: "${ARR_STACK_DIR:=${ARR_DATA_ROOT}/${STACK}}"
: "${ARR_ENV_FILE:=${ARR_STACK_DIR}/.env}"
: "${ARRCONF_DIR:=${ARR_STACK_DIR}/configs}"
: "${ARR_LOG_DIR:=${ARR_STACK_DIR}/logs}"
: "${ARR_INSTALL_LOG:=${ARR_LOG_DIR}/${STACK}-install.log}"
: "${ARR_USERCONF_PATH:=${ARRCONF_DIR}/userr.conf}"
: "${MUSIC_DIR:=${MEDIA_DIR}/Music}"

: "${QBT_INT_PORT:=8082}"
: "${QBT_PORT:=${QBT_INT_PORT}}"
: "${QBT_WEB_PORT:=8080}"
: "${SONARR_INT_PORT:=8989}"
: "${RADARR_INT_PORT:=7878}"
: "${LIDARR_INT_PORT:=8686}"
: "${PROWLARR_INT_PORT:=9696}"
: "${BAZARR_INT_PORT:=6767}"
: "${FLARR_INT_PORT:=8191}"
: "${SABNZBD_INT_PORT:=8080}"
: "${SABNZBD_PORT:=${SABNZBD_INT_PORT}}"
EXPOSE_DIRECT_PORTS="$(arr_normalize_bool "${EXPOSE_DIRECT_PORTS:-0}")"
SABNZBD_ENABLED="$(arr_normalize_bool "${SABNZBD_ENABLED:-0}")"
SABNZBD_USE_VPN="$(arr_normalize_bool "${SABNZBD_USE_VPN:-0}")"
VPN_AUTO_RECONNECT_ENABLED="$(arr_normalize_bool "${VPN_AUTO_RECONNECT_ENABLED:-0}")"
QBT_ENFORCE_WEBUI="$(arr_normalize_bool "${QBT_ENFORCE_WEBUI:-1}")"
ENABLE_CONFIGARR="$(arr_normalize_bool "${ENABLE_CONFIGARR:-1}")"
SPLIT_VPN="$(arr_normalize_bool "${SPLIT_VPN:-0}")"

: "${VPN_PORT_GUARD_POLL_SECONDS:=15}"

export EXPOSE_DIRECT_PORTS SABNZBD_ENABLED VPN_PORT_GUARD_POLL_SECONDS

if [[ -z "${SONARR_PORT:-}" ]]; then SONARR_PORT="$SONARR_INT_PORT"; fi
if [[ -z "${RADARR_PORT:-}" ]]; then RADARR_PORT="$RADARR_INT_PORT"; fi
if [[ -z "${LIDARR_PORT:-}" ]]; then LIDARR_PORT="$LIDARR_INT_PORT"; fi
if [[ -z "${PROWLARR_PORT:-}" ]]; then PROWLARR_PORT="$PROWLARR_INT_PORT"; fi
if [[ -z "${BAZARR_PORT:-}" ]]; then BAZARR_PORT="$BAZARR_INT_PORT"; fi
if [[ -z "${FLARR_PORT:-}" ]]; then FLARR_PORT="$FLARR_INT_PORT"; fi

if [[ -z "${QBT_AUTH_WHITELIST:-}" ]]; then
  QBT_AUTH_WHITELIST="127.0.0.1/32,::1/128"
fi
if declare -f lan_ipv4_subnet_cidr >/dev/null 2>&1; then
  if lan_private_subnet="$(lan_ipv4_subnet_cidr "${LAN_IP:-}" 2>/dev/null || true)"; then
    if [[ -n "$lan_private_subnet" ]]; then
      QBT_AUTH_WHITELIST+="${QBT_AUTH_WHITELIST:+,}${lan_private_subnet}"
    fi
  fi
fi
if declare -f normalize_csv >/dev/null 2>&1; then
  QBT_AUTH_WHITELIST="$(normalize_csv "$QBT_AUTH_WHITELIST")"
fi

dns_candidates=()
if declare -f collect_upstream_dns_servers >/dev/null 2>&1; then
  mapfile -t dns_candidates < <(collect_upstream_dns_servers 2>/dev/null || true)
fi
if declare -f arr_assign_upstream_dns_env >/dev/null 2>&1; then
  arr_assign_upstream_dns_env "${dns_candidates[@]}"
fi
: "${UPSTREAM_DNS_2_DISPLAY:=${UPSTREAM_DNS_2:-<unset>}}"

if [[ -z "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:-}" ]] && declare -f arr_derive_gluetun_firewall_outbound_subnets >/dev/null 2>&1; then
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(arr_derive_gluetun_firewall_outbound_subnets)"
fi
if [[ -z "${GLUETUN_FIREWALL_INPUT_PORTS:-}" ]] && declare -f arr_derive_gluetun_firewall_input_ports >/dev/null 2>&1; then
  GLUETUN_FIREWALL_INPUT_PORTS="$(arr_derive_gluetun_firewall_input_ports)"
fi
if declare -f normalize_csv >/dev/null 2>&1; then
  GLUETUN_FIREWALL_INPUT_PORTS="$(normalize_csv "${GLUETUN_FIREWALL_INPUT_PORTS:-}")"
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(normalize_csv "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:-}")"
fi
if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  COMPOSE_PROJECT_NAME="${STACK}"
fi
if [[ -z "${COMPOSE_PROFILES:-}" ]] && declare -f arr_derive_compose_profiles_csv >/dev/null 2>&1; then
  COMPOSE_PROFILES="$(arr_derive_compose_profiles_csv)"
fi
: "${COMPOSE_PROFILES:=ipdirect}"
export COMPOSE_PROFILES
: "${VPN_SERVICE_PROVIDER:=${VPN_SERVICE_PROVIDER:-protonvpn}}"
: "${VPN_TYPE:=${VPN_TYPE:-openvpn}}"
: "${WG_FALLBACK_TIMEOUT_SECONDS:=120}"
if [[ -z "${OPENVPN_USER:-}" ]] && declare -f arr_derive_openvpn_user >/dev/null 2>&1; then
  OPENVPN_USER="$(arr_derive_openvpn_user)"
fi
if [[ -z "${OPENVPN_PASSWORD:-}" ]] && declare -f arr_derive_openvpn_password >/dev/null 2>&1; then
  OPENVPN_PASSWORD="$(arr_derive_openvpn_password)"
fi
: "${OPENVPN_USER_ENFORCED:=${OPENVPN_USER:+1}}"

OUT_PATH="${OUT_ARG}"
if [[ -z "$OUT_PATH" ]]; then
  OUT_PATH="${ARR_ENV_FILE}"
fi
OUT_PATH="$(resolve_path "$OUT_PATH")"

if ! filter_tmp="$(mktemp 2>/dev/null)"; then
  die "Failed to allocate template filter scratch file"
fi
arr_register_temp_path "$filter_tmp"

if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    if [[ ! ${!key+x} ]]; then
      printf -v "$key" '%s' ""
    fi
    # shellcheck disable=SC2163
    export "$key"
  done < <(arr_collect_all_expected_env_keys)
fi

filter_conditionals <"$TEMPLATE_PATH" >"$filter_tmp"

VARS="$(grep -oE '\$\{[A-Z0-9_]+\}' "$filter_tmp" | sort -u | tr '\n' ' ')"

for placeholder in $VARS; do
  var_name="${placeholder:2:${#placeholder}-3}"
  if [[ -z "$var_name" ]]; then
    continue
  fi
  if [[ ! ${!var_name+x} ]]; then
    printf -v "$var_name" '%s' ""
  fi
  # shellcheck disable=SC2163
  export "$var_name"
done

if [[ "$OUT_PATH" == '-' ]]; then
  if [[ -n "$VARS" ]]; then
    envsubst "$VARS" <"$filter_tmp"
  else
    envsubst <"$filter_tmp"
  fi
  arr_cleanup_temp_path "$filter_tmp"
  printf 'Generated %s from %s using %s\n' "stdout" "$TEMPLATE_PATH" "${CONF_PATH:-<none>}" >&2
else
  mkdir -p "$(dirname -- "$OUT_PATH")"
  if [[ -n "$VARS" ]]; then
    envsubst "$VARS" <"$filter_tmp" >"$OUT_PATH"
  else
    envsubst <"$filter_tmp" >"$OUT_PATH"
  fi
  arr_cleanup_temp_path "$filter_tmp"
  chmod 600 "$OUT_PATH" 2>/dev/null || true
  printf 'Generated %s from %s using %s\n' "$OUT_PATH" "$TEMPLATE_PATH" "${CONF_PATH:-<none>}"
fi

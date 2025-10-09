#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

COMMON_LIB="${REPO_ROOT}/scripts/common.sh"
NETWORK_LIB="${REPO_ROOT}/scripts/network.sh"
if [[ -f "$COMMON_LIB" ]]; then
  # shellcheck source=scripts/common.sh
  . "$COMMON_LIB"
fi
if [[ -f "$NETWORK_LIB" ]]; then
  # shellcheck source=scripts/network.sh
  . "$NETWORK_LIB"
fi

resolve_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ "$path" != /* ]]; then
    printf '%s\n' "${REPO_ROOT}/${path}"
  else
    printf '%s\n' "$path"
  fi
}

TEMPLATE_ARG="${1:-.env.template}"
OUT_ARG="${2:-}"
CONF_ARG="${3:-}"
DEFAULTS_ARG="${USERR_DEFAULTS:-arrconf/userr.conf.defaults.sh}"

TEMPLATE_PATH="$(resolve_path "$TEMPLATE_ARG")"
DEFAULTS_PATH="$(resolve_path "$DEFAULTS_ARG")"
CONF_PATH="${CONF_ARG:-${USERR_CONF:-arrconf/userr.conf}}"
CONF_PATH="$(resolve_path "$CONF_PATH")"

if [[ ! -f "$TEMPLATE_PATH" ]]; then
  printf 'error: template not found: %s\n' "$TEMPLATE_PATH" >&2
  exit 1
fi

if ! command -v envsubst >/dev/null 2>&1; then
  printf 'error: envsubst not found (install gettext)\n' >&2
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

: "${QBT_INT_PORT:=8082}"
: "${QBT_PORT:=${QBT_INT_PORT}}"
: "${SONARR_INT_PORT:=8989}"
: "${RADARR_INT_PORT:=7878}"
: "${PROWLARR_INT_PORT:=9696}"
: "${BAZARR_INT_PORT:=6767}"
: "${FLARR_INT_PORT:=8191}"
: "${SABNZBD_INT_PORT:=8080}"
: "${SABNZBD_PORT:=${SABNZBD_INT_PORT}}"
: "${CADDY_HTTP_PORT:=80}"
: "${CADDY_HTTPS_PORT:=443}"
: "${CADDY_DOMAIN_SUFFIX:=${LAN_DOMAIN_SUFFIX:-home.arpa}}"

EXPOSE_DIRECT_PORTS="$(arr_normalize_bool "${EXPOSE_DIRECT_PORTS:-0}")"
ENABLE_CADDY="$(arr_normalize_bool "${ENABLE_CADDY:-0}")"
ENABLE_LOCAL_DNS="$(arr_normalize_bool "${ENABLE_LOCAL_DNS:-0}")"
SABNZBD_ENABLED="$(arr_normalize_bool "${SABNZBD_ENABLED:-0}")"
SABNZBD_USE_VPN="$(arr_normalize_bool "${SABNZBD_USE_VPN:-0}")"
PF_ASYNC_ENABLE="$(arr_normalize_bool "${PF_ASYNC_ENABLE:-1}")"
PF_ENABLE_CYCLE="$(arr_normalize_bool "${PF_ENABLE_CYCLE:-1}")"
GLUETUN_PF_STRICT="$(arr_normalize_bool "${GLUETUN_PF_STRICT:-0}")"
VPN_AUTO_RECONNECT_ENABLED="$(arr_normalize_bool "${VPN_AUTO_RECONNECT_ENABLED:-0}")"
QBT_ENFORCE_WEBUI="$(arr_normalize_bool "${QBT_ENFORCE_WEBUI:-1}")"
ENABLE_CONFIGARR="$(arr_normalize_bool "${ENABLE_CONFIGARR:-1}")"
SPLIT_VPN="$(arr_normalize_bool "${SPLIT_VPN:-0}")"

export ENABLE_CADDY EXPOSE_DIRECT_PORTS SABNZBD_ENABLED

if [[ -z "${SONARR_PORT:-}" ]]; then SONARR_PORT="$SONARR_INT_PORT"; fi
if [[ -z "${RADARR_PORT:-}" ]]; then RADARR_PORT="$RADARR_INT_PORT"; fi
if [[ -z "${PROWLARR_PORT:-}" ]]; then PROWLARR_PORT="$PROWLARR_INT_PORT"; fi
if [[ -z "${BAZARR_PORT:-}" ]]; then BAZARR_PORT="$BAZARR_INT_PORT"; fi
if [[ -z "${FLARR_PORT:-}" ]]; then FLARR_PORT="$FLARR_INT_PORT"; fi

if [[ -z "${QBT_AUTH_WHITELIST:-}" ]]; then
  QBT_AUTH_WHITELIST="127.0.0.1/32,::1/128"
fi
if lan_private_subnet="$(lan_ipv4_subnet_cidr "${LAN_IP:-}" 2>/dev/null || true)"; then
  if [[ -n "$lan_private_subnet" ]]; then
    QBT_AUTH_WHITELIST+="${QBT_AUTH_WHITELIST:+,}${lan_private_subnet}"
  fi
fi
QBT_AUTH_WHITELIST="$(normalize_csv "$QBT_AUTH_WHITELIST")"

dns_candidates=()
if declare -f collect_upstream_dns_servers >/dev/null 2>&1; then
  mapfile -t dns_candidates < <(collect_upstream_dns_servers 2>/dev/null || true)
fi
arr_assign_upstream_dns_env "${dns_candidates[@]}"
: "${UPSTREAM_DNS_2_DISPLAY:=${UPSTREAM_DNS_2:-<unset>}}"

if [[ -z "${DNS_HOST_ENTRY:-}" ]]; then
  DNS_HOST_ENTRY="$(arr_derive_dns_host_entry)"
fi
if [[ -z "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:-}" ]]; then
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(arr_derive_gluetun_firewall_outbound_subnets)"
fi
if [[ -z "${GLUETUN_FIREWALL_INPUT_PORTS:-}" ]]; then
  GLUETUN_FIREWALL_INPUT_PORTS="$(arr_derive_gluetun_firewall_input_ports)"
fi
if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  COMPOSE_PROJECT_NAME="${STACK}"
fi
if [[ -z "${COMPOSE_PROFILES:-}" ]]; then
  COMPOSE_PROFILES="$(arr_derive_compose_profiles_csv)"
fi
: "${VPN_SERVICE_PROVIDER:=${VPN_SERVICE_PROVIDER:-protonvpn}}"
: "${VPN_TYPE:=${VPN_TYPE:-openvpn}}"
if [[ -z "${OPENVPN_USER:-}" ]]; then
  OPENVPN_USER="$(arr_derive_openvpn_user)"
fi
if [[ -z "${OPENVPN_PASSWORD:-}" ]]; then
  OPENVPN_PASSWORD="$(arr_derive_openvpn_password)"
fi
: "${OPENVPN_USER_ENFORCED:=${OPENVPN_USER:+1}}"

CADDY_BASIC_AUTH_USER="$(sanitize_user "${CADDY_BASIC_AUTH_USER:-}")"

OUT_PATH="${OUT_ARG}" 
if [[ -z "$OUT_PATH" ]]; then
  OUT_PATH="${ARR_ENV_FILE}"
fi
OUT_PATH="$(resolve_path "$OUT_PATH")"

filter_tmp="$(mktemp)"
trap 'rm -f "$filter_tmp"' EXIT

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

mkdir -p "$(dirname -- "$OUT_PATH")"
if [[ -n "$VARS" ]]; then
  envsubst "$VARS" <"$filter_tmp" >"$OUT_PATH"
else
  envsubst <"$filter_tmp" >"$OUT_PATH"
fi
chmod 600 "$OUT_PATH" 2>/dev/null || true

printf 'Generated %s from %s using %s\n' "$OUT_PATH" "$TEMPLATE_PATH" "${CONF_PATH:-<none>}"

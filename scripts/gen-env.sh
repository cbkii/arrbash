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

norm_bool() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) printf '1\n' ;;
    *) printf '0\n' ;;
  esac
}

derive_dns_host_entry() {
  local ip="${LAN_IP:-}"
  if [[ -n "$ip" && "$ip" != "0.0.0.0" ]] && validate_ipv4 "$ip" && is_private_ipv4 "$ip"; then
    printf '%s\n' "$ip"
    return 0
  fi
  if command -v hostname >/dev/null 2>&1; then
    while IFS= read -r candidate; do
      [[ -z "$candidate" ]] && continue
      if validate_ipv4 "$candidate" && is_private_ipv4 "$candidate"; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done < <(hostname -I 2>/dev/null | tr ' ' '\n' | awk 'NF')
  fi
  printf '%s\n' "127.0.0.1"
}

derive_gluetun_firewall_outbound_subnets() {
  local ip="${LAN_IP:-}"
  local -a candidates=("192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")
  local cidr=""
  if [[ -n "$ip" ]]; then
    if cidr="$(lan_ipv4_subnet_cidr "$ip" 2>/dev/null || true)"; then
      if [[ -n "$cidr" ]]; then
        candidates=("$cidr" "${candidates[@]}")
      fi
    fi
  fi
  printf '%s\n' "${candidates[@]}" | LC_ALL=C sort -u | paste -sd, -
}

derive_gluetun_firewall_input_ports() {
  local split_mode="${SPLIT_VPN:-0}"
  local expose_direct="${EXPOSE_DIRECT_PORTS:-0}"
  local -a ports=()
  local port=""

  if [[ "$split_mode" != "1" && "${ENABLE_CADDY:-0}" == "1" ]]; then
    for port in "${CADDY_HTTP_PORT:-}" "${CADDY_HTTPS_PORT:-}"; do
      [[ -n "$port" ]] && ports+=("$port")
    done
  fi

  if [[ "$split_mode" == "1" ]]; then
    port="${QBT_PORT:-}"
    [[ -n "$port" ]] && ports+=("$port")
  elif [[ "$expose_direct" == "1" ]]; then
    for port in \
      "${QBT_PORT:-}" "${SONARR_PORT:-}" "${RADARR_PORT:-}" \
      "${PROWLARR_PORT:-}" "${BAZARR_PORT:-}" "${FLARR_PORT:-}"; do
      [[ -n "$port" ]] && ports+=("$port")
    done
    if [[ "${SABNZBD_ENABLED:-0}" == "1" && "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
      port="${SABNZBD_PORT:-}"
      [[ -n "$port" ]] && ports+=("$port")
    fi
  fi

  if ((${#ports[@]} == 0)); then
    printf '\n'
    return 0
  fi

  local -A seen=()
  local -a deduped=()
  for port in "${ports[@]}"; do
    if [[ -n "$port" && -z "${seen[$port]:-}" && "$port" =~ ^[0-9]+$ ]]; then
      seen["$port"]=1
      deduped+=("$port")
    fi
  done

  if ((${#deduped[@]} == 0)); then
    printf '\n'
    return 0
  fi

  IFS=, printf '%s\n' "${deduped[*]}"
}

derive_compose_profiles() {
  local -a profiles=(ipdirect)
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    profiles+=(proxy)
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    profiles+=(localdns)
  fi
  if ((${#profiles[@]} == 0)); then
    printf '\n'
    return 0
  fi
  local -A seen=()
  local -a deduped=()
  local profile
  for profile in "${profiles[@]}"; do
    if [[ -n "$profile" && -z "${seen[$profile]:-}" ]]; then
      seen["$profile"]=1
      deduped+=("$profile")
    fi
  done
  IFS=, printf '%s\n' "${deduped[*]}"
}

derive_openvpn_user() {
  if [[ ${OPENVPN_USER+x} ]]; then
    printf '%s\n' "${OPENVPN_USER}"
    return 0
  fi
  if [[ -n "${OPENVPN_USER_VALUE:-}" ]]; then
    printf '%s\n' "${OPENVPN_USER_VALUE}"
    return 0
  fi
  if [[ -n "${PROTON_USER_VALUE:-}" ]]; then
    printf '%s\n' "${PROTON_USER_VALUE%+pmp}+pmp"
    return 0
  fi
  printf '\n'
}

derive_openvpn_password() {
  if [[ ${OPENVPN_PASSWORD+x} ]]; then
    printf '%s\n' "${OPENVPN_PASSWORD}"
    return 0
  fi
  if [[ -n "${PROTON_PASS_VALUE:-}" ]]; then
    printf '%s\n' "${PROTON_PASS_VALUE}"
    return 0
  fi
  printf '\n'
}

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

EXPOSE_DIRECT_PORTS="$(norm_bool "${EXPOSE_DIRECT_PORTS:-0}")"
ENABLE_CADDY="$(norm_bool "${ENABLE_CADDY:-0}")"
ENABLE_LOCAL_DNS="$(norm_bool "${ENABLE_LOCAL_DNS:-0}")"
SABNZBD_ENABLED="$(norm_bool "${SABNZBD_ENABLED:-0}")"
SABNZBD_USE_VPN="$(norm_bool "${SABNZBD_USE_VPN:-0}")"
PF_ASYNC_ENABLE="$(norm_bool "${PF_ASYNC_ENABLE:-1}")"
PF_ENABLE_CYCLE="$(norm_bool "${PF_ENABLE_CYCLE:-1}")"
GLUETUN_PF_STRICT="$(norm_bool "${GLUETUN_PF_STRICT:-0}")"
VPN_AUTO_RECONNECT_ENABLED="$(norm_bool "${VPN_AUTO_RECONNECT_ENABLED:-0}")"
QBT_ENFORCE_WEBUI="$(norm_bool "${QBT_ENFORCE_WEBUI:-1}")"
ENABLE_CONFIGARR="$(norm_bool "${ENABLE_CONFIGARR:-1}")"
SPLIT_VPN="$(norm_bool "${SPLIT_VPN:-0}")"

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
if mapfile -t dns_candidates < <(collect_upstream_dns_servers 2>/dev/null || true); then
  if ((${#dns_candidates[@]} > 0)); then
    # shellcheck disable=SC2034  # exported for env template generation
    UPSTREAM_DNS_SERVERS="$(IFS=,; printf '%s' "${dns_candidates[*]}")"
    # shellcheck disable=SC2034  # exported for env template generation
    UPSTREAM_DNS_1="${dns_candidates[0]}"
    # shellcheck disable=SC2034  # exported for env template generation
    UPSTREAM_DNS_2="${dns_candidates[1]:-}"
  fi
fi
if [[ -z "${UPSTREAM_DNS_SERVERS:-}" && -z "${UPSTREAM_DNS_1:-}" && -z "${UPSTREAM_DNS_2:-}" ]]; then
  # shellcheck disable=SC2034  # exported for env template generation
  UPSTREAM_DNS_1="1.1.1.1"
  # shellcheck disable=SC2034  # exported for env template generation
  UPSTREAM_DNS_2="1.0.0.1"
  # shellcheck disable=SC2034  # exported for env template generation
  UPSTREAM_DNS_SERVERS="${UPSTREAM_DNS_1},${UPSTREAM_DNS_2}"
fi
: "${UPSTREAM_DNS_2_DISPLAY:=${UPSTREAM_DNS_2:-<unset>}}"

if [[ -z "${DNS_HOST_ENTRY:-}" ]]; then
  DNS_HOST_ENTRY="$(derive_dns_host_entry)"
fi
if [[ -z "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS:-}" ]]; then
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(derive_gluetun_firewall_outbound_subnets)"
fi
if [[ -z "${GLUETUN_FIREWALL_INPUT_PORTS:-}" ]]; then
  GLUETUN_FIREWALL_INPUT_PORTS="$(derive_gluetun_firewall_input_ports)"
fi
if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  COMPOSE_PROJECT_NAME="${STACK}"
fi
if [[ -z "${COMPOSE_PROFILES:-}" ]]; then
  COMPOSE_PROFILES="$(derive_compose_profiles)"
fi
: "${VPN_SERVICE_PROVIDER:=${VPN_SERVICE_PROVIDER:-protonvpn}}"
: "${VPN_TYPE:=${VPN_TYPE:-openvpn}}"
if [[ -z "${OPENVPN_USER:-}" ]]; then
  OPENVPN_USER="$(derive_openvpn_user)"
fi
if [[ -z "${OPENVPN_PASSWORD:-}" ]]; then
  OPENVPN_PASSWORD="$(derive_openvpn_password)"
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

filter_conditionals <"$TEMPLATE_PATH" >"$filter_tmp"

VARS="$(grep -oE '\$\{[A-Z0-9_]+\}' "$filter_tmp" | sort -u | tr '\n' ' ')"

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

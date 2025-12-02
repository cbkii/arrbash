#!/usr/bin/env bash
# Default configuration for ARR Stack
# This file is sourced *before* ${ARRCONF_DIR}/userr.conf.
# Keep assignments idempotent and avoid relying on side effects so overrides
# behave predictably when the user configuration runs afterwards.
# shellcheck disable=SC2250
# Override these in ${ARRCONF_DIR}/userr.conf (git-ignored; defaults to ${ARR_DATA_ROOT}/${STACK}configs/userr.conf where ARR_DATA_ROOT defaults to ~/srv).

# Base paths
STACK="${STACK:-arr}"
STACK_UPPER="${STACK_UPPER:-${STACK^^}}"
export STACK STACK_UPPER

if [[ -z "${ARR_DATA_ROOT:-}" ]]; then
  if [[ -n "${HOME:-}" ]]; then
    ARR_DATA_ROOT="${HOME%/}/srv"
  else
    ARR_DATA_ROOT="/srv/${STACK}"
  fi
fi

case "${ARR_DATA_ROOT}" in
  /) ;;
  */) ARR_DATA_ROOT="${ARR_DATA_ROOT%/}" ;;
esac
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_DATA_ROOT}/${STACK}}"
ARRCONF_DIR="${ARRCONF_DIR:-${ARR_STACK_DIR}configs}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_STACK_DIR}/dockarr}"
ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
ARR_USERCONF_PATH="${ARR_USERCONF_PATH:-${ARRCONF_DIR}/userr.conf}"
ARR_LOG_DIR="${ARR_LOG_DIR:-${ARR_STACK_DIR}/logs}"
ARR_INSTALL_LOG="${ARR_INSTALL_LOG:-${ARR_LOG_DIR}/${STACK}-install.log}"
ARR_COLOR_OUTPUT="${ARR_COLOR_OUTPUT:-1}"

# File/dir permissions (strict keeps secrets 600/700, collab enables group read/write 660/770)
if ! declare -f arr_var_is_readonly >/dev/null 2>&1 || ! arr_var_is_readonly ARR_PERMISSION_PROFILE; then
  ARR_PERMISSION_PROFILE="${ARR_PERMISSION_PROFILE:-strict}"
fi

# Download paths
DOWNLOADS_DIR="${DOWNLOADS_DIR:-${HOME}/Downloads}"
COMPLETED_DIR="${COMPLETED_DIR:-${DOWNLOADS_DIR}/completed}"

# Media library
MEDIA_DIR="${MEDIA_DIR:-${ARR_DATA_ROOT}/media}"
TV_DIR="${TV_DIR:-${MEDIA_DIR}/Shows}"
MOVIES_DIR="${MOVIES_DIR:-${MEDIA_DIR}/Movies}"
MUSIC_DIR="${MUSIC_DIR:-${MEDIA_DIR}/Music}"
SUBS_DIR="${SUBS_DIR:-${MEDIA_DIR}/subs}"

# Container identity (current user by default)
PUID="${PUID:-$(id -u)}"
PGID="${PGID:-$(id -g)}"

# Location
# Local timezone identifier (IANA tz database). Used for logs, scheduling, and backups.
TIMEZONE="${TIMEZONE:-Australia/Sydney}"
LAN_IP="${LAN_IP:-}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands,Singapore}"
SERVER_NAMES="${SERVER_NAMES:-}"
PVPN_ROTATE_COUNTRIES="${PVPN_ROTATE_COUNTRIES:-}"

# Helper utilities for defaults that may also be sourced by other scripts
if ! declare -f arr_trim_whitespace >/dev/null 2>&1; then
  arr_trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
  }
fi

if ! declare -f arr_parse_csv >/dev/null 2>&1; then
  arr_parse_csv() {
    local raw="$1"

    [[ -n "$raw" ]] || return 0

    printf '%s\n' "$raw" | awk -F',' '
      {
        for (i = 1; i <= NF; i++) {
          item = $i
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", item)
          if (length(item) > 0) {
            print item
          }
        }
      }
    '
  }
fi

if ! declare -f arr_join_by >/dev/null 2>&1; then
  arr_join_by() {
    local delimiter="$1"
    shift || true
    local first=1
    local piece
    for piece in "$@"; do
      if ((first)); then
        printf '%s' "$piece"
        first=0
      else
        printf '%s%s' "$delimiter" "$piece"
      fi
    done
  }
fi

if ! declare -f arr_defaults_fail >/dev/null 2>&1; then
  arr_defaults_fail() {
    local var_name="$1"
    local message="$2"
    local normalized=""
    local raw_value

    raw_value="${!var_name-}"
    raw_value="$(arr_trim_whitespace "${raw_value}")"

    case "$var_name" in
      VPN_PORT_GUARD_POLL_SECONDS)
        if [[ "$raw_value" =~ ^[1-9][0-9]*$ ]]; then
          normalized="$raw_value"
        else
          normalized="15"
        fi
        ;;
      VPN_PORT_GUARD_STATUS_TIMEOUT)
        if [[ "$raw_value" =~ ^[1-9][0-9]*$ ]]; then
          normalized="$raw_value"
        else
          normalized="90"
        fi
        ;;
      CONTROLLER_REQUIRE_PF)
        raw_value="${raw_value,,}"
        case "$raw_value" in
          1 | true | yes | on | required | strict)
            normalized="true"
            ;;
          '' | 0 | false | no | off | preferred)
            normalized="false"
            ;;
        esac
        ;;
    esac

    if [[ -z "$normalized" ]]; then
      printf 'arrconf: %s\n' "$message" >&2
      exit 1
    fi

    printf 'arrconf: %s; defaulting to %s\n' "$message" "$normalized" >&2
    printf -v "$var_name" '%s' "$normalized"
    export "${var_name?}"
  }
fi

ARR_DOCKER_SERVICES_DEFAULT=(
  gluetun
  vpn-port-guard
  qbittorrent
  sonarr
  radarr
  lidarr
  prowlarr
  bazarr
  flaresolverr
  sabnzbd
  configarr
)

# Ensure ARR_DOCKER_SERVICES is declared before length checks to avoid 'unbound variable' with set -u
if ! declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1; then
  ARR_DOCKER_SERVICES=()
fi

if ((${#ARR_DOCKER_SERVICES[@]} == 0)); then
  ARR_DOCKER_SERVICES=("${ARR_DOCKER_SERVICES_DEFAULT[@]}")
fi

arr_set_docker_services_list() {
  if declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1 && ((${#ARR_DOCKER_SERVICES[@]} > 0)); then
    # shellcheck disable=SC2034  # exported via .env generation
    ARR_DOCKER_SERVICES_LIST="$(arr_join_by ' ' "${ARR_DOCKER_SERVICES[@]}")"
    # shellcheck disable=SC2034  # exported via .env generation
    ARR_DOCKER_SERVICES_CSV="$(arr_join_by ',' "${ARR_DOCKER_SERVICES[@]}")"
  else
    # shellcheck disable=SC2034  # exported via .env generation
    ARR_DOCKER_SERVICES_LIST=""
    # shellcheck disable=SC2034  # exported via .env generation
    ARR_DOCKER_SERVICES_CSV=""
  fi
}

arr_set_docker_services_list

SPLIT_VPN="${SPLIT_VPN:-0}"
ENABLE_CONFIGARR="${ENABLE_CONFIGARR:-1}"

# Host port preflight behaviour: enforce (default), warn, skip, or fix (auto-remediate then warn)
ARR_PORT_CHECK_MODE="${ARR_PORT_CHECK_MODE:-enforce}"

# VPN type: openvpn (default) or wireguard (future feature).
# Only openvpn is fully supported at this time; wireguard support is planned but not yet reliable.
VPN_TYPE="${VPN_TYPE:-openvpn}"

# Gluetun control server
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

VPN_PORT_GUARD_POLL_SECONDS="${VPN_PORT_GUARD_POLL_SECONDS:-15}"
if [[ ! "${VPN_PORT_GUARD_POLL_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  arr_defaults_fail "VPN_PORT_GUARD_POLL_SECONDS" "VPN_PORT_GUARD_POLL_SECONDS must be a positive integer (got '${VPN_PORT_GUARD_POLL_SECONDS}')"
fi

VPN_PORT_GUARD_STATUS_TIMEOUT="${VPN_PORT_GUARD_STATUS_TIMEOUT:-90}"
if [[ ! "${VPN_PORT_GUARD_STATUS_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
  arr_defaults_fail "VPN_PORT_GUARD_STATUS_TIMEOUT" "VPN_PORT_GUARD_STATUS_TIMEOUT must be a positive integer (got '${VPN_PORT_GUARD_STATUS_TIMEOUT}')"
fi

if [[ -z "${CONTROLLER_REQUIRE_PF+x}" && -n "${CONTROLLER_REQUIRE_PORT_FORWARDING:-}" ]]; then
  CONTROLLER_REQUIRE_PF="${CONTROLLER_REQUIRE_PORT_FORWARDING}"
fi
CONTROLLER_REQUIRE_PF="${CONTROLLER_REQUIRE_PF:-false}"
case "${CONTROLLER_REQUIRE_PF,,}" in
  1 | true | yes | on | required | strict)
    CONTROLLER_REQUIRE_PF="true"
    ;;
  '' | 0 | false | no | off | preferred)
    CONTROLLER_REQUIRE_PF="false"
    ;;
  *)
    arr_defaults_fail "CONTROLLER_REQUIRE_PF" "CONTROLLER_REQUIRE_PF must be 'true' or 'false' (got '${CONTROLLER_REQUIRE_PF}')"
    ;;
esac

# VPN auto-reconnect tuning
VPN_AUTO_RECONNECT_ENABLED="${VPN_AUTO_RECONNECT_ENABLED:-0}"
VPN_SPEED_THRESHOLD_KBPS="${VPN_SPEED_THRESHOLD_KBPS:-12}"
VPN_CHECK_INTERVAL_MINUTES="${VPN_CHECK_INTERVAL_MINUTES:-20}"
VPN_CONSECUTIVE_CHECKS="${VPN_CONSECUTIVE_CHECKS:-3}"
VPN_ALLOWED_HOURS_START="${VPN_ALLOWED_HOURS_START:-}"
VPN_ALLOWED_HOURS_END="${VPN_ALLOWED_HOURS_END:-}"
VPN_COOLDOWN_MINUTES="${VPN_COOLDOWN_MINUTES:-60}"
VPN_MAX_RETRY_MINUTES="${VPN_MAX_RETRY_MINUTES:-20}"
VPN_ROTATION_MAX_PER_DAY="${VPN_ROTATION_MAX_PER_DAY:-6}"
VPN_ROTATION_JITTER_SECONDS="${VPN_ROTATION_JITTER_SECONDS:-0}"

# Service ports
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_CONTROL_BIND="${GLUETUN_CONTROL_BIND:-all}"
case "${GLUETUN_CONTROL_BIND,,}" in
  all | any | 0.0.0.0 | '')
    GLUETUN_CONTROL_BIND="all"
    ;;
  loopback | localhost | 127.0.0.1)
    GLUETUN_CONTROL_BIND="loopback"
    ;;
  *)
    arr_defaults_fail "GLUETUN_CONTROL_BIND" "GLUETUN_CONTROL_BIND must be 'all' or 'loopback' (got '${GLUETUN_CONTROL_BIND}')"
    ;;
esac
GLUETUN_CONNECTIVITY_PROBE_URLS="${GLUETUN_CONNECTIVITY_PROBE_URLS:-https://api.ipify.org,https://ipconfig.io/ip,https://1.1.1.1/cdn-cgi/trace}"
GLUETUN_API_TIMEOUT="${GLUETUN_API_TIMEOUT:-10}"
GLUETUN_API_RETRY_COUNT="${GLUETUN_API_RETRY_COUNT:-3}"
GLUETUN_API_RETRY_DELAY="${GLUETUN_API_RETRY_DELAY:-2}"
GLUETUN_API_MAX_RETRY_DELAY="${GLUETUN_API_MAX_RETRY_DELAY:-8}"

QBT_INT_PORT="${QBT_INT_PORT:-8080}"
QBT_PORT="${QBT_PORT:-${QBT_INT_PORT:-8080}}"
QBT_WEB_PORT="${QBT_WEB_PORT:-8080}"
QBT_BIND_ADDR="${QBT_BIND_ADDR:-0.0.0.0}"
QBT_ENFORCE_WEBUI="${QBT_ENFORCE_WEBUI:-1}"
QBT_API_TIMEOUT="${QBT_API_TIMEOUT:-10}"
QBT_API_RETRY_COUNT="${QBT_API_RETRY_COUNT:-3}"
QBT_API_RETRY_DELAY="${QBT_API_RETRY_DELAY:-2}"

SONARR_INT_PORT="${SONARR_INT_PORT:-8989}"
SONARR_PORT="${SONARR_PORT:-${SONARR_INT_PORT:-8989}}"

RADARR_INT_PORT="${RADARR_INT_PORT:-7878}"
RADARR_PORT="${RADARR_PORT:-${RADARR_INT_PORT:-7878}}"

LIDARR_INT_PORT="${LIDARR_INT_PORT:-8686}"
LIDARR_PORT="${LIDARR_PORT:-${LIDARR_INT_PORT:-8686}}"

PROWLARR_INT_PORT="${PROWLARR_INT_PORT:-9696}"
PROWLARR_PORT="${PROWLARR_PORT:-${PROWLARR_INT_PORT:-9696}}"

BAZARR_INT_PORT="${BAZARR_INT_PORT:-6767}"
BAZARR_PORT="${BAZARR_PORT:-${BAZARR_INT_PORT:-6767}}"

FLARR_INT_PORT="${FLARR_INT_PORT:-8191}"
FLARR_PORT="${FLARR_PORT:-${FLARR_INT_PORT:-8191}}"

SABNZBD_INT_PORT="${SABNZBD_INT_PORT:-8081}"
SABNZBD_PORT="${SABNZBD_PORT:-${SABNZBD_INT_PORT:-8081}}"

# SABnzbd integration
SABNZBD_ENABLED="${SABNZBD_ENABLED:-0}"
SABNZBD_USE_VPN="${SABNZBD_USE_VPN:-0}"
SABNZBD_HOST="${SABNZBD_HOST:-${LOCALHOST_IP}}"
SABNZBD_API_KEY="${SABNZBD_API_KEY:-}"
SABNZBD_CATEGORY="${SABNZBD_CATEGORY:-${STACK}}"
SABNZBD_TIMEOUT="${SABNZBD_TIMEOUT:-15}"
ARRBASH_USENET_CLIENT="${ARRBASH_USENET_CLIENT:-sabnzbd}"

# Expose application ports directly on the host
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS:-1}"

# qBittorrent credentials - these are applied via API on first install when set to non-default values.
# After changing password in WebUI, update QBT_PASS here or in .env to match.
QBT_USER="${QBT_USER:-admin}"
QBT_PASS="${QBT_PASS:-adminadmin}"
if [[ -z "${QBT_DOCKER_MODS+x}" ]]; then
  QBT_DOCKER_MODS="ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest"
fi

# Comma-separated CIDR list that can bypass the qBittorrent WebUI login.
# Docker bridge subnet (172.17.0.0/16,::ffff:172.28.0.1/128) is included by default because qBittorrent runs behind Gluetun (network_mode: service:gluetun), which masks client IPs.
QBT_AUTH_WHITELIST="${QBT_AUTH_WHITELIST:-127.0.0.1/32,::1/128,172.17.0.0/16,::ffff:172.28.0.1/128}"

# Security: set to 1 to include LAN_IP/24 CIDR in qBittorrent WebUI auth whitelist
# WARNING: This allows any host on your LAN to access qBittorrent WebUI without credentials
QBT_AUTH_WHITELIST_INCLUDE_LAN="${QBT_AUTH_WHITELIST_INCLUDE_LAN:-0}"

# Images
GLUETUN_IMAGE="${GLUETUN_IMAGE:-qmcgaw/gluetun:v3.40.0}"
QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE:-lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415}"
SONARR_IMAGE="${SONARR_IMAGE:-lscr.io/linuxserver/sonarr:4.0.15.2941-ls291}"
RADARR_IMAGE="${RADARR_IMAGE:-lscr.io/linuxserver/radarr:5.27.5.10198-ls283}"
LIDARR_IMAGE="${LIDARR_IMAGE:-lscr.io/linuxserver/lidarr:latest}"
PROWLARR_IMAGE="${PROWLARR_IMAGE:-lscr.io/linuxserver/prowlarr:latest}"
BAZARR_IMAGE="${BAZARR_IMAGE:-lscr.io/linuxserver/bazarr:latest}"
FLARR_IMAGE="${FLARR_IMAGE:-ghcr.io/flaresolverr/flaresolverr:v3.3.21}"
SABNZBD_IMAGE="${SABNZBD_IMAGE:-lscr.io/linuxserver/sabnzbd:latest}"
CONFIGARR_IMAGE="${CONFIGARR_IMAGE:-ghcr.io/raydak-labs/configarr:latest}"
#
# ConfigArr quality/profile defaults
ARR_VIDEO_MIN_RES="${ARR_VIDEO_MIN_RES:-720p}"
ARR_VIDEO_MAX_RES="${ARR_VIDEO_MAX_RES:-1080p}"
ARR_EP_MIN_MB="${ARR_EP_MIN_MB:-250}"
ARR_EP_MAX_GB="${ARR_EP_MAX_GB:-5}"
ARR_TV_RUNTIME_MIN="${ARR_TV_RUNTIME_MIN:-45}"
ARR_SEASON_MAX_GB="${ARR_SEASON_MAX_GB:-30}"
ARR_LANG_PRIMARY="${ARR_LANG_PRIMARY:-en}"
ARR_ENGLISH_ONLY="${ARR_ENGLISH_ONLY:-1}"
ARR_DISCOURAGE_MULTI="${ARR_DISCOURAGE_MULTI:-1}"
ARR_PENALIZE_HD_X265="${ARR_PENALIZE_HD_X265:-1}"
ARR_STRICT_JUNK_BLOCK="${ARR_STRICT_JUNK_BLOCK:-1}"
ARR_JUNK_NEGATIVE_SCORE="${ARR_JUNK_NEGATIVE_SCORE:--1000}"
ARR_X265_HD_NEGATIVE_SCORE="${ARR_X265_HD_NEGATIVE_SCORE:--200}"
ARR_MULTI_NEGATIVE_SCORE="${ARR_MULTI_NEGATIVE_SCORE:--50}"
ARR_ENGLISH_POSITIVE_SCORE="${ARR_ENGLISH_POSITIVE_SCORE:-50}"
SONARR_TRASH_TEMPLATE="${SONARR_TRASH_TEMPLATE:-sonarr-v4-quality-profile-web-1080p}"
RADARR_TRASH_TEMPLATE="${RADARR_TRASH_TEMPLATE:-radarr-v5-quality-profile-hd-bluray-web}"
ARR_MBMIN_DECIMALS="${ARR_MBMIN_DECIMALS:-1}"
#
# Behaviour flags
ASSUME_YES="${ASSUME_YES:-0}"
FORCE_ROTATE_API_KEY="${FORCE_ROTATE_API_KEY:-0}"
REFRESH_ALIASES="${REFRESH_ALIASES:-0}"

# -----------------------------------------------------------------------------
# User configuration example template
# -----------------------------------------------------------------------------

ARR_USERCONF_TEMPLATE_VARS=(
  STACK
  ARR_DATA_ROOT
  ARR_USERCONF_PATH
  DOWNLOADS_DIR
  COMPLETED_DIR
  MEDIA_DIR
  MUSIC_DIR
  TV_DIR
  MOVIES_DIR
  SUBS_DIR
  ARR_LOG_DIR
  ARR_INSTALL_LOG
  ARR_COLOR_OUTPUT
  TIMEZONE
  SERVER_COUNTRIES
  SERVER_NAMES
  PVPN_ROTATE_COUNTRIES
  GLUETUN_CONTROL_PORT
  GLUETUN_CONTROL_BIND
  GLUETUN_CONNECTIVITY_PROBE_URLS
  GLUETUN_API_TIMEOUT
  GLUETUN_API_RETRY_COUNT
  GLUETUN_API_RETRY_DELAY
  GLUETUN_API_MAX_RETRY_DELAY
  SPLIT_VPN
  ENABLE_CONFIGARR
  ARR_PORT_CHECK_MODE
  VPN_TYPE
  EXPOSE_DIRECT_PORTS
  VPN_PORT_GUARD_POLL_SECONDS
  VPN_PORT_GUARD_STATUS_TIMEOUT
  CONTROLLER_REQUIRE_PF
  QBT_DOCKER_MODS
  QBT_AUTH_WHITELIST
  QBT_AUTH_WHITELIST_INCLUDE_LAN
  QBT_INT_PORT
  QBT_PORT
  QBT_WEB_PORT
  QBT_BIND_ADDR
  QBT_ENFORCE_WEBUI
  QBT_API_TIMEOUT
  QBT_API_RETRY_COUNT
  QBT_API_RETRY_DELAY
  SONARR_INT_PORT
  SONARR_PORT
  RADARR_INT_PORT
  RADARR_PORT
  LIDARR_INT_PORT
  LIDARR_PORT
  PROWLARR_INT_PORT
  PROWLARR_PORT
  BAZARR_INT_PORT
  BAZARR_PORT
  FLARR_INT_PORT
  FLARR_PORT
  SABNZBD_INT_PORT
  SABNZBD_PORT
  SABNZBD_ENABLED
  SABNZBD_USE_VPN
  SABNZBD_HOST
  SABNZBD_API_KEY
  SABNZBD_CATEGORY
  SABNZBD_TIMEOUT
  ARRBASH_USENET_CLIENT
  VPN_AUTO_RECONNECT_ENABLED
  VPN_SPEED_THRESHOLD_KBPS
  VPN_CHECK_INTERVAL_MINUTES
  VPN_CONSECUTIVE_CHECKS
  VPN_ALLOWED_HOURS_START
  VPN_ALLOWED_HOURS_END
  VPN_COOLDOWN_MINUTES
  VPN_MAX_RETRY_MINUTES
  VPN_ROTATION_MAX_PER_DAY
  VPN_ROTATION_JITTER_SECONDS
  GLUETUN_IMAGE
  QBITTORRENT_IMAGE
  SONARR_IMAGE
  RADARR_IMAGE
  LIDARR_IMAGE
  PROWLARR_IMAGE
  BAZARR_IMAGE
  FLARR_IMAGE
  SABNZBD_IMAGE
  CONFIGARR_IMAGE
  ARR_VIDEO_MIN_RES
  ARR_VIDEO_MAX_RES
  ARR_EP_MIN_MB
  ARR_EP_MAX_GB
  ARR_TV_RUNTIME_MIN
  ARR_SEASON_MAX_GB
  ARR_LANG_PRIMARY
  ARR_ENGLISH_ONLY
  ARR_DISCOURAGE_MULTI
  ARR_PENALIZE_HD_X265
  ARR_STRICT_JUNK_BLOCK
  ARR_JUNK_NEGATIVE_SCORE
  ARR_X265_HD_NEGATIVE_SCORE
  ARR_MULTI_NEGATIVE_SCORE
  ARR_ENGLISH_POSITIVE_SCORE
  SONARR_TRASH_TEMPLATE
  RADARR_TRASH_TEMPLATE
  ARR_MBMIN_DECIMALS
)

ARR_USERCONF_IMPLICIT_VARS=(
  ARRCONF_DIR
  ARR_STACK_DIR
  ARR_ENV_FILE
  ARR_DOCKER_DIR
  ARR_PERMISSION_PROFILE
  DOWNLOADS_DIR
  COMPLETED_DIR
  MEDIA_DIR
  MUSIC_DIR
  TV_DIR
  MOVIES_DIR
  SUBS_DIR
  LAN_IP
  LOCALHOST_IP
  PUID
  PGID
  QBT_USER
  QBT_PASS
  GLUETUN_API_KEY
  SABNZBD_API_KEY
)

# Derived (non-user) environment keys prepared for .env generation; kept here
# so tooling can validate compose interpolation without needing .env.example.
ARR_DERIVED_ENV_VARS=(
  ARR_DOCKER_SERVICES_LIST
  ARR_DOCKER_SERVICES_CSV
  OPENVPN_USER
  OPENVPN_PASSWORD
  OPENVPN_USER_ENFORCED
  COMPOSE_PROJECT_NAME
  COMPOSE_PROFILES
  VPN_SERVICE_PROVIDER
  GLUETUN_API_KEY
  GLUETUN_FIREWALL_INPUT_PORTS
  GLUETUN_FIREWALL_OUTBOUND_SUBNETS
)

arr_export_userconf_template_vars() {
  local var=""
  local value=""

  for var in "${ARR_USERCONF_TEMPLATE_VARS[@]}"; do
    case "$var" in
      STACK)
        value="${STACK}"
        ;;
      ARR_USERCONF_PATH)
        # shellcheck disable=SC2016  # keep literal reference for template output
        value='${ARRCONF_DIR}/userr.conf'
        ;;
      ARR_LOG_DIR)
        # shellcheck disable=SC2016  # keep literal reference for template output
        value='${ARR_STACK_DIR}/logs'
        ;;
      ARR_INSTALL_LOG)
        # shellcheck disable=SC2016  # keep literal reference for template output
        value='${ARR_LOG_DIR}/${STACK}-install.log'
        ;;
      *)
        value="${!var-}"
        ;;
    esac
    export "${var}=${value}"
  done
}

arr_userconf_envsubst_spec() {
  local var=""
  local spec=""

  for var in "${ARR_USERCONF_TEMPLATE_VARS[@]}"; do
    # shellcheck disable=SC2178,SC2179  # spec is intentionally a scalar string passed to envsubst
    spec+=" \${${var}}"
  done

  printf '%s\n' "${spec# }"
}

arr_collect_all_expected_env_keys() {
  local -A seen=()
  local -a ordered=()
  local var=""

  for var in "${ARR_USERCONF_TEMPLATE_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  for var in "${ARR_USERCONF_IMPLICIT_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  for var in "${ARR_DERIVED_ENV_VARS[@]:-}"; do
    if [[ -n "$var" && -z "${seen[$var]:-}" ]]; then
      ordered+=("$var")
      seen["$var"]=1
    fi
  done

  printf '%s\n' "${ordered[@]}"
}

arr_render_userconf_template() {
  cat <<'EOF'
#!/usr/bin/env bash
# shellcheck disable=SC2034
# Keep arrconf/userr.conf.example in sync with any changes made here.
# Make ONE copy named 'userr.conf', and edit as needed (default: '${ARR_DATA_ROOT}/${STACK}configs/userr.conf', must use path at most 4 deep below '$ARR_DATA_ROOT').
# Values here override the defaults from arrconf/userr.conf.defaults.sh, which loads first.

# --- Stack paths ---
STACK="${STACK}"                    # Project identifier used for directories, logs, and labels
ARR_DATA_ROOT="${HOME}/srv"           # Default data root (matches historical ~/srv layout)
ARRCONF_DIR="${ARR_DATA_ROOT}/${STACK}configs"  # Directory for secrets and config overrides
ARR_STACK_DIR="${ARR_DATA_ROOT}/${STACK}"  # Location for docker-compose.yml, scripts, and aliases
ARR_ENV_FILE="${ARR_STACK_DIR}/.env"  # Path to the generated .env secrets file
ARR_DOCKER_DIR="${ARR_STACK_DIR}/dockarr"  # Docker volumes and persistent data storage
ARR_USERCONF_PATH="${ARRCONF_DIR}/userr.conf"  # Optional: relocate this file outside ${ARR_DATA_ROOT}

# --- Logging and output ---
ARR_LOG_DIR="${ARR_LOG_DIR}"           # Directory for runtime/service logs (default: ${ARR_LOG_DIR})
ARR_INSTALL_LOG="${ARR_INSTALL_LOG}"   # Installer run log location (default: ${ARR_INSTALL_LOG})
ARR_COLOR_OUTPUT="${ARR_COLOR_OUTPUT}"       # 1 keeps colorful CLI output, set 0 to disable ANSI colors

# --- Permissions ---
ARR_PERMISSION_PROFILE="strict"        # strict keeps secrets 600/700, collab enables group read/write (660/770)

# --- Downloads and media ---
DOWNLOADS_DIR="${HOME}/Downloads"      # Active qBittorrent download folder
COMPLETED_DIR="${DOWNLOADS_DIR}/completed"  # Destination for completed downloads
MEDIA_DIR="${ARR_DATA_ROOT}/media"            # Root of the media library share under ARR_DATA_ROOT
TV_DIR="${MEDIA_DIR}/Shows"            # Sonarr TV library path
MOVIES_DIR="${MEDIA_DIR}/Movies"       # Radarr movie library path
# SUBS_DIR="${MEDIA_DIR}/subs"         # Optional Bazarr subtitles directory

# --- User identity ---
PUID="$(id -u)"                        # Numeric user ID containers should run as
PGID="$(id -g)"                        # Numeric group ID with write access (match your media group when using collab)
TIMEZONE="${TIMEZONE}"            # Timezone for container logs and schedules (default: ${TIMEZONE})

# --- Networking ---
LAN_IP=""                              # Bind services to one LAN IP (set a DHCP reservation or static IP before install)
LOCALHOST_IP="127.0.0.1"               # Loopback used by the Gluetun control API
SERVER_COUNTRIES="${SERVER_COUNTRIES}"              # ProtonVPN exit country list (default: ${SERVER_COUNTRIES})
# SERVER_NAMES=""                          # Optionally pin Proton server hostnames (comma-separated) when Gluetun should stick to a specific server
PVPN_ROTATE_COUNTRIES="${PVPN_ROTATE_COUNTRIES}"  # Optional rotation order for arr.vpn switch (default: empty/disabled)
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT}"            # Host port that exposes the Gluetun control API (default: ${GLUETUN_CONTROL_PORT})
GLUETUN_CONTROL_BIND="${GLUETUN_CONTROL_BIND}"          # all binds 0.0.0.0 inside the container; set loopback to restrict to 127.0.0.1
# SPLIT_VPN=1 → Only qbittorrent behind VPN; other services run outside it.
SPLIT_VPN="${SPLIT_VPN}"
# VPN protocol: openvpn (default) is fully supported; wireguard is a future feature.
VPN_TYPE="${VPN_TYPE}"
ENABLE_CONFIGARR="${ENABLE_CONFIGARR}"             # Configarr one-shot sync for TRaSH-Guides profiles (set 0 to omit the container)
ARR_PORT_CHECK_MODE="${ARR_PORT_CHECK_MODE}"     # enforce (default) fails on conflicts, warn logs & continues, skip disables port probing, fix auto-clears blockers
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS}"                # Keep 1 so WebUIs publish on http://${LAN_IP}:PORT (requires LAN_IP set to your private IPv4)

# --- VPN port guard ---
VPN_PORT_GUARD_POLL_SECONDS="${VPN_PORT_GUARD_POLL_SECONDS}"   # Poll interval (positive integer seconds, default: ${VPN_PORT_GUARD_POLL_SECONDS})
VPN_PORT_GUARD_STATUS_TIMEOUT="${VPN_PORT_GUARD_STATUS_TIMEOUT}"   # Max seconds to wait for vpn-port-guard status file at startup (default: ${VPN_PORT_GUARD_STATUS_TIMEOUT})
CONTROLLER_REQUIRE_PF="${CONTROLLER_REQUIRE_PF}"               # true pauses until Proton forwards a port, false lets torrents run without (default: ${CONTROLLER_REQUIRE_PF})
# Example overrides:
# VPN_PORT_GUARD_POLL_SECONDS=10
# VPN_PORT_GUARD_STATUS_TIMEOUT=120
# CONTROLLER_REQUIRE_PF=true

# --- Credentials ---
QBT_USER="admin"                       # Initial qBittorrent username (change after first login)
QBT_PASS="adminadmin"                  # qBittorrent password (applied via API on first install; update here after changing in WebUI)
GLUETUN_API_KEY=""                     # Pre-seed a Gluetun API key or leave empty to auto-generate
QBT_DOCKER_MODS="${QBT_DOCKER_MODS}"  # Vuetorrent WebUI mod (set empty to disable)
QBT_AUTH_WHITELIST="${QBT_AUTH_WHITELIST}"  # CIDRs allowed to bypass the qBittorrent login prompt (included Docker's default bridge is 172.17.0.0/16 --note RFC1918 private range 172.16.0.0/12)
QBT_AUTH_WHITELIST_INCLUDE_LAN="${QBT_AUTH_WHITELIST_INCLUDE_LAN}"  # Set to 1 to auto-add LAN_IP/24 to whitelist (SECURITY WARNING: allows any LAN host to access qBittorrent without credentials)

# --- SABnzbd (Usenet downloader) ---
SABNZBD_ENABLED="${SABNZBD_ENABLED}"             # 1 enables SABnzbd container/helper integration (default: ${SABNZBD_ENABLED})
SABNZBD_USE_VPN="${SABNZBD_USE_VPN}"             # 1 routes SABnzbd through Gluetun (default: ${SABNZBD_USE_VPN})
SABNZBD_HOST="${SABNZBD_HOST}"           # Host used by sab-helper (default: ${SABNZBD_HOST})
SABNZBD_API_KEY="${SABNZBD_API_KEY:-REPLACE_WITH_SABNZBD_API_KEY}"             # Hydrated automatically from sabnzbd.ini when available
SABNZBD_CATEGORY="${SABNZBD_CATEGORY}"           # Category applied to helper-submitted jobs (default: ${SABNZBD_CATEGORY})
SABNZBD_TIMEOUT="${SABNZBD_TIMEOUT}"             # Helper API timeout in seconds (default: ${SABNZBD_TIMEOUT})
ARRBASH_USENET_CLIENT="${ARRBASH_USENET_CLIENT}" # Active Usenet client label (future abstraction)

# --- Service ports ---
QBT_INT_PORT="${QBT_INT_PORT}"             # Internal qBittorrent WebUI port; match the container WEBUI_PORT env if you change it
QBT_PORT="${QBT_PORT}"              # qBittorrent WebUI port exposed on the LAN (default: ${QBT_PORT})
QBT_BIND_ADDR="${QBT_BIND_ADDR}"          # Address qBittorrent binds inside the container (default: ${QBT_BIND_ADDR})
QBT_ENFORCE_WEBUI="${QBT_ENFORCE_WEBUI}"  # 1 keeps the WebUI bind/port enforced at startup and during health checks (default: ${QBT_ENFORCE_WEBUI})
SONARR_PORT="${SONARR_PORT}"                     # Sonarr WebUI port exposed on the LAN (default: ${SONARR_PORT})
RADARR_PORT="${RADARR_PORT}"                     # Radarr WebUI port exposed on the LAN (default: ${RADARR_PORT})
PROWLARR_PORT="${PROWLARR_PORT}"                   # Prowlarr WebUI port exposed on the LAN (default: ${PROWLARR_PORT})
BAZARR_PORT="${BAZARR_PORT}"                     # Bazarr WebUI port exposed on the LAN (default: ${BAZARR_PORT})
FLARR_PORT="${FLARR_PORT}"               # FlareSolverr service port exposed on the LAN (default: ${FLARR_PORT})
SABNZBD_INT_PORT="${SABNZBD_INT_PORT}"           # Internal SABnzbd WebUI port; match the container PORT env if you change it
SABNZBD_PORT="${SABNZBD_PORT}"                 # Host port for SAB WebUI when direct (default: ${SABNZBD_PORT})

# --- VPN auto-reconnect (optional) ---
VPN_AUTO_RECONNECT_ENABLED="${VPN_AUTO_RECONNECT_ENABLED}"    # 1 enables the background monitor (default: ${VPN_AUTO_RECONNECT_ENABLED})
VPN_SPEED_THRESHOLD_KBPS="${VPN_SPEED_THRESHOLD_KBPS}"        # Combined kbps threshold before reconnect attempts (default: ${VPN_SPEED_THRESHOLD_KBPS})
VPN_CHECK_INTERVAL_MINUTES="${VPN_CHECK_INTERVAL_MINUTES}"    # Minutes between throughput samples (default: ${VPN_CHECK_INTERVAL_MINUTES})
VPN_CONSECUTIVE_CHECKS="${VPN_CONSECUTIVE_CHECKS}"            # Consecutive low samples required before reconnecting (default: ${VPN_CONSECUTIVE_CHECKS})
VPN_ALLOWED_HOURS_START="${VPN_ALLOWED_HOURS_START}"          # Optional rotation window start hour (default: none)
VPN_ALLOWED_HOURS_END="${VPN_ALLOWED_HOURS_END}"              # Optional rotation window end hour (default: none)
VPN_COOLDOWN_MINUTES="${VPN_COOLDOWN_MINUTES}"                # Cooldown after successful reconnects (default: ${VPN_COOLDOWN_MINUTES})
VPN_MAX_RETRY_MINUTES="${VPN_MAX_RETRY_MINUTES}"              # Retry budget before auto-disabling (default: ${VPN_MAX_RETRY_MINUTES})

# --- Container images (advanced) ---
# GLUETUN_IMAGE="${GLUETUN_IMAGE}"                     # Override the Gluetun container tag
# QBITTORRENT_IMAGE="${QBITTORRENT_IMAGE}"  # Override the qBittorrent container tag
# SONARR_IMAGE="${SONARR_IMAGE}"         # Override the Sonarr container tag
# RADARR_IMAGE="${RADARR_IMAGE}"        # Override the Radarr container tag
# PROWLARR_IMAGE="${PROWLARR_IMAGE}"                # Override the Prowlarr container tag
# BAZARR_IMAGE="${BAZARR_IMAGE}"                    # Override the Bazarr container tag
# FLARR_IMAGE="${FLARR_IMAGE}"      # Override the FlareSolverr container tag
# SABNZBD_IMAGE="${SABNZBD_IMAGE}"                    # Override the SABnzbd container tag
# CONFIGARR_IMAGE="${CONFIGARR_IMAGE}"            # Override the Configarr container tag

# --- ConfigArr quality/profile defaults ---
ARR_VIDEO_MIN_RES="${ARR_VIDEO_MIN_RES}"         # Minimum allowed resolution (default: ${ARR_VIDEO_MIN_RES})
ARR_VIDEO_MAX_RES="${ARR_VIDEO_MAX_RES}"         # Maximum allowed resolution (default: ${ARR_VIDEO_MAX_RES})
ARR_EP_MIN_MB="${ARR_EP_MIN_MB}"                 # Minimum episode size in MB (default: ${ARR_EP_MIN_MB})
ARR_EP_MAX_GB="${ARR_EP_MAX_GB}"                 # Maximum episode size in GB (default: ${ARR_EP_MAX_GB})
ARR_TV_RUNTIME_MIN="${ARR_TV_RUNTIME_MIN}"       # Minimum runtime to treat content as standard TV (default: ${ARR_TV_RUNTIME_MIN})
ARR_SEASON_MAX_GB="${ARR_SEASON_MAX_GB}"         # Cap on total season size in GB (default: ${ARR_SEASON_MAX_GB})
ARR_LANG_PRIMARY="${ARR_LANG_PRIMARY}"           # Preferred audio/subtitle language (default: ${ARR_LANG_PRIMARY})
ARR_ENGLISH_ONLY="${ARR_ENGLISH_ONLY}"           # 1 prefers English-only releases (default: ${ARR_ENGLISH_ONLY})
ARR_DISCOURAGE_MULTI="${ARR_DISCOURAGE_MULTI}"   # 1 penalises multi-audio releases (default: ${ARR_DISCOURAGE_MULTI})
ARR_PENALIZE_HD_X265="${ARR_PENALIZE_HD_X265}"   # 1 lowers HD x265 release scores (default: ${ARR_PENALIZE_HD_X265})
ARR_STRICT_JUNK_BLOCK="${ARR_STRICT_JUNK_BLOCK}" # 1 fully blocks junk releases (default: ${ARR_STRICT_JUNK_BLOCK})
ARR_JUNK_NEGATIVE_SCORE="${ARR_JUNK_NEGATIVE_SCORE}"         # Score applied to junk terms (default: ${ARR_JUNK_NEGATIVE_SCORE})
ARR_X265_HD_NEGATIVE_SCORE="${ARR_X265_HD_NEGATIVE_SCORE}"   # Score penalty for HD x265 (default: ${ARR_X265_HD_NEGATIVE_SCORE})
ARR_MULTI_NEGATIVE_SCORE="${ARR_MULTI_NEGATIVE_SCORE}"       # Score penalty for multi-audio releases (default: ${ARR_MULTI_NEGATIVE_SCORE})
ARR_ENGLISH_POSITIVE_SCORE="${ARR_ENGLISH_POSITIVE_SCORE}"   # Score bonus for English releases (default: ${ARR_ENGLISH_POSITIVE_SCORE})
SONARR_TRASH_TEMPLATE="${SONARR_TRASH_TEMPLATE}" # TRaSH template slug ConfigArr applies to Sonarr (default: ${SONARR_TRASH_TEMPLATE})
RADARR_TRASH_TEMPLATE="${RADARR_TRASH_TEMPLATE}" # TRaSH template slug ConfigArr applies to Radarr (default: ${RADARR_TRASH_TEMPLATE})
ARR_MBMIN_DECIMALS="${ARR_MBMIN_DECIMALS}"       # Decimals precision for minimum size rules (default: ${ARR_MBMIN_DECIMALS})

# --- Behaviour toggles ---
# ASSUME_YES="0"                         # Skip confirmation prompts when scripting installs
# FORCE_ROTATE_API_KEY="0"               # Force regeneration of the Gluetun API key on next run
# REFRESH_ALIASES="0"                     # Regenerate helper aliases without running the installer
EOF
}

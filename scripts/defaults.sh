# shellcheck shell=bash

if ! declare -f arrstack_var_is_readonly >/dev/null 2>&1; then
  arrstack_var_is_readonly() {
    local var="$1"
    local declaration=""

    if ! declaration=$(declare -p "$var" 2>/dev/null); then
      return 1
    fi

    case $declaration in
      declare\ -r*)
        return 0
        ;;
    esac

    return 1
  }
fi

arrstack_setup_defaults() {
  local previous_stack_dir="${ARR_STACK_DIR:-}"
  if [[ -z "${ARR_DOCKER_DIR}" && -d "${HOME}/srv/docker-data" ]]; then
    ARR_DOCKER_DIR="${HOME}/srv/docker-data"
    ARR_STACK_DIR="${ARR_STACK_DIR:-${PWD}/arrstack}"
  fi

  if [[ -n "${previous_stack_dir}" && "${previous_stack_dir}" != "${ARR_STACK_DIR}" ]]; then
    local previous_env_file="${previous_stack_dir}/.env"
    if [[ "${ARR_ENV_FILE:-}" == "${previous_env_file}" ]]; then
      ARR_ENV_FILE="${ARR_STACK_DIR}/.env"
    fi
  fi
  ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"

  if [[ -n "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX#.}"
  fi

  LOCAL_DNS_SERVICE_ENABLED=0
  : "$LOCAL_DNS_SERVICE_ENABLED" # referenced by other modules after defaults load

  if [[ -z "${QBT_DOCKER_MODS+x}" ]]; then
    QBT_DOCKER_MODS="ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest"
  fi

  VUETORRENT_MANUAL_ROOT="/config/vuetorrent"
  VUETORRENT_LSIO_ROOT="/vuetorrent"
  if [[ -n "${QBT_DOCKER_MODS}" ]]; then
    # shellcheck disable=SC2034
    VUETORRENT_MODE="lsio-mod"
    # shellcheck disable=SC2034
    VUETORRENT_ROOT="${VUETORRENT_LSIO_ROOT}"
  else
    # shellcheck disable=SC2034
    VUETORRENT_MODE="manual"
    # shellcheck disable=SC2034
    VUETORRENT_ROOT="${VUETORRENT_MANUAL_ROOT}"
  fi
  # shellcheck disable=SC2034
  VUETORRENT_ALT_ENABLED=1
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_MESSAGE=""
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_LEVEL="msg"
  # shellcheck disable=SC2034
  VUETORRENT_VERSION=""

  if [[ -n "${CADDY_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${CADDY_DOMAIN_SUFFIX#.}"
  fi

  if [[ -z "${CADDY_DOMAIN_SUFFIX:-}" && -n "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    CADDY_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}"
  fi

  ARR_DOMAIN_SUFFIX_CLEAN="${CADDY_DOMAIN_SUFFIX#.}"
  export ARR_DOMAIN_SUFFIX_CLEAN

  export CADDY_DOMAIN_SUFFIX
  export LAN_DOMAIN_SUFFIX

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0
  : "$PROTON_USER_VALUE" "$PROTON_PASS_VALUE" "$OPENVPN_USER_VALUE" "$PROTON_USER_PMP_ADDED"

  DOCKER_COMPOSE_CMD=()
  ARRSTACK_LOCKFILE=""
  LOG_FILE=""
  : "${DOCKER_COMPOSE_CMD[*]}" "$ARRSTACK_LOCKFILE" "$LOG_FILE"

  local requested_permission_profile="${ARR_PERMISSION_PROFILE:-}"
  local permission_profile="${requested_permission_profile:-strict}"
  SECRET_FILE_MODE=600
  LOCK_FILE_MODE=644
  NONSECRET_FILE_MODE=600
  DATA_DIR_MODE=700
  local collab_initial_umask="0007"

  case "${permission_profile}" in
    collab|collaborative)
      if [[ "${requested_permission_profile}" == "collaborative" ]]; then
        warn "ARR_PERMISSION_PROFILE='collaborative' is deprecated; use 'collab' instead"
        requested_permission_profile="collab"
      fi
      permission_profile="collab"
      umask "$collab_initial_umask"
      SECRET_FILE_MODE=600
      NONSECRET_FILE_MODE=660
      DATA_DIR_MODE=770
      ;;
    strict)
      umask 0077
      ;;
    *)
      warn "Unknown ARR_PERMISSION_PROFILE='${requested_permission_profile}' - defaulting to strict"
      permission_profile="strict"
      umask 0077
      ;;
  esac

  if arrstack_var_is_readonly ARR_PERMISSION_PROFILE; then
    if [[ "${ARR_PERMISSION_PROFILE:-}" != "${permission_profile}" ]]; then
      die "ARR_PERMISSION_PROFILE is read-only with value '${ARR_PERMISSION_PROFILE:-}', expected '${permission_profile}'"
    fi
  else
    ARR_PERMISSION_PROFILE="${permission_profile}"
  fi

  COLLAB_GROUP_WRITE_ENABLED=0
  COLLAB_GROUP_WRITE_DISABLED_REASON=""

  if [[ "${permission_profile}" == "collab" ]]; then
    if [[ "${PGID:-}" == "0" ]]; then
      COLLAB_GROUP_WRITE_DISABLED_REASON="PGID=0 uses the root group; refusing to enable group write."
      COLLAB_GROUP_WRITE_ENABLED=0
      warn "Collaborative profile detected with PGID=0; keeping historical 0027 umask and 750/640 modes to avoid root-group write access."
      umask 0027
      NONSECRET_FILE_MODE=640
      DATA_DIR_MODE=750
    else
      COLLAB_GROUP_WRITE_ENABLED=1
    fi
  fi

  if [[ -n "${ARR_SECRET_FILE_MODE_OVERRIDE:-}" ]]; then
    if [[ "${ARR_SECRET_FILE_MODE_OVERRIDE}" =~ ^[0-7]{3,4}$ ]]; then
      SECRET_FILE_MODE="${ARR_SECRET_FILE_MODE_OVERRIDE}"
    else
      warn "Ignoring ARR_SECRET_FILE_MODE_OVERRIDE='${ARR_SECRET_FILE_MODE_OVERRIDE}' (must be octal like 600)"
    fi
  fi

  if [[ -n "${ARR_NONSECRET_FILE_MODE_OVERRIDE:-}" ]]; then
    if [[ "${ARR_NONSECRET_FILE_MODE_OVERRIDE}" =~ ^[0-7]{3,4}$ ]]; then
      NONSECRET_FILE_MODE="${ARR_NONSECRET_FILE_MODE_OVERRIDE}"
    else
      warn "Ignoring ARR_NONSECRET_FILE_MODE_OVERRIDE='${ARR_NONSECRET_FILE_MODE_OVERRIDE}' (must be octal like 660)"
    fi
  fi

  if [[ -n "${ARR_DATA_DIR_MODE_OVERRIDE:-}" ]]; then
    if [[ "${ARR_DATA_DIR_MODE_OVERRIDE}" =~ ^[0-7]{3,4}$ ]]; then
      DATA_DIR_MODE="${ARR_DATA_DIR_MODE_OVERRIDE}"
    else
      warn "Ignoring ARR_DATA_DIR_MODE_OVERRIDE='${ARR_DATA_DIR_MODE_OVERRIDE}' (must be octal like 770)"
    fi
  fi

  if [[ -n "${ARR_UMASK_OVERRIDE:-}" ]]; then
    if [[ "${ARR_UMASK_OVERRIDE}" =~ ^0?[0-7]{3,4}$ ]]; then
      umask "${ARR_UMASK_OVERRIDE}"
    else
      warn "Ignoring ARR_UMASK_OVERRIDE='${ARR_UMASK_OVERRIDE}' (must be octal like 0007)"
    fi
  fi

  : "$SECRET_FILE_MODE" "$LOCK_FILE_MODE" "$NONSECRET_FILE_MODE" "$DATA_DIR_MODE" \
    "$COLLAB_GROUP_WRITE_ENABLED" "$COLLAB_GROUP_WRITE_DISABLED_REASON"
  readonly ARR_PERMISSION_PROFILE SECRET_FILE_MODE LOCK_FILE_MODE NONSECRET_FILE_MODE DATA_DIR_MODE

  COLLAB_PERMISSION_WARNINGS=""
  COLLAB_CREATED_MEDIA_DIRS=""
  : "$COLLAB_PERMISSION_WARNINGS" "$COLLAB_CREATED_MEDIA_DIRS"

  ARR_DOCKER_SERVICES=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr configarr caddy local_dns)
  : "${ARR_DOCKER_SERVICES[*]}"
  readonly -a ARR_DOCKER_SERVICES

  CYAN='\033[0;36m'
  YELLOW='\033[0;33m'
  RESET='\033[0m'
  : "$CYAN" "$YELLOW" "$RESET"
}

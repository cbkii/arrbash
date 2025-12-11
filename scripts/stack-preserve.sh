# shellcheck shell=bash
# shellcheck disable=SC2034,SC2128,SC2178

if ! declare -f arr_date_local >/dev/null 2>&1; then
  __arr_time_guard_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="${REPO_ROOT:-$(cd "${__arr_time_guard_dir}/.." && pwd)}"
  if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
    # shellcheck source=scripts/stack-common.sh
    . "${REPO_ROOT}/scripts/stack-common.sh"
  fi
  unset __arr_time_guard_dir
fi

# Collects status notes for summary output when values are preserved
arr_record_preserve_note() {
  local note="$1"

  if [[ -z "$note" ]]; then
    return 0
  fi

  if [[ -z "${ARR_PRESERVE_NOTES:-}" ]]; then
    ARR_PRESERVE_NOTES="$note"
  else
    ARR_PRESERVE_NOTES="$(printf '%s\n%s' "${ARR_PRESERVE_NOTES}" "$note")"
  fi
}

# Minimum length for SABnzbd API keys is 16 characters (see SABnzbd documentation)
SABNZBD_API_KEY_MIN_LENGTH="16"

# Hydrates SABNZBD_API_KEY from sabnzbd.ini when available so reruns keep API access
hydrate_sab_api_key_from_config() {
  if [[ "${SABNZBD_ENABLED:-0}" != "1" ]]; then
    return 0
  fi

  local config_dir
  config_dir="$(arr_docker_data_root)/sab/config"
  local ini_path="${config_dir}/sabnzbd.ini"

  if [[ -d "$config_dir" && "${ARR_SAB_CONFIG_PRESERVED:-0}" != "1" ]]; then
    ARR_SAB_CONFIG_PRESERVED=1
    arr_record_preserve_note "Preserved existing SABnzbd config at ${config_dir}" || true
  fi

  if [[ ! -f "$ini_path" ]]; then
    return 0
  fi

  local api_key_line="" api_key_value=""
  local pattern='^[[:space:]]*api_key[[:space:]]*='
  api_key_line="$(grep -iE "$pattern" "$ini_path" | head -n1 || printf '')"

  if [[ -z "$api_key_line" ]]; then
    return 0
  fi

  api_key_value="${api_key_line#*=}"
  api_key_value="${api_key_value#"${api_key_value%%[![:space:]]*}"}"
  api_key_value="${api_key_value%"${api_key_value##*[![:space:]]}"}"

  if [[ -z "$api_key_value" ]]; then
    return 0
  fi

  if [[ ${#api_key_value} -lt ${SABNZBD_API_KEY_MIN_LENGTH} ]]; then
    warn "Detected SABnzbd API key seems too short, ignoring: ${#api_key_value} chars"
    return 0
  fi

  local current_value="${SABNZBD_API_KEY:-}" placeholder=0
  if [[ -z "$current_value" ]]; then
    placeholder=1
  else
    local upper="${current_value^^}"
    if [[ "$upper" == REPLACE_WITH_* ]]; then
      placeholder=1
    fi
  fi

  if ((placeholder)) && [[ "$current_value" != "$api_key_value" ]]; then
    if [[ -z "${ARR_SAB_INI_BACKUP:-}" ]]; then
      local timestamp backup_path
      timestamp="$(arr_date_local '+%Y%m%d-%H%M%S')"
      backup_path="${ini_path}.bak.${timestamp}"
      if cp -a "$ini_path" "$backup_path" 2>/dev/null; then
        ARR_SAB_INI_BACKUP="$backup_path"
        arr_record_preserve_note "Backed up sabnzbd.ini to ${backup_path##*/}"
      fi
    fi

    SABNZBD_API_KEY="$api_key_value"
    arr_record_preserve_note "Hydrated SABnzbd API key from sabnzbd.ini"
    ARR_SAB_API_KEY_SOURCE="hydrated"
  fi

  return 0
}

# Captures an existing qBittorrent WebUI host port from .env so we only migrate
# when explicitly requested.
hydrate_qbt_host_port_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  local existing_host_port=""
  existing_host_port="$(get_env_kv "QBT_PORT" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

  if [[ -n "$existing_host_port" ]]; then
    local trimmed="${existing_host_port//[[:space:]]/}"
    if [[ "$trimmed" =~ ^[0-9]+$ ]]; then
      ARR_QBT_HOST_PORT_ENV="$trimmed"
    fi
  fi
}

# Reads qBittorrent's configured WebUI port so compose generation honors
# existing deployments that override the default port.
hydrate_qbt_webui_port_from_config() {
  local docker_root
  docker_root="$(arr_docker_data_root)"
  if declare -f arr_qbt_migrate_legacy_conf >/dev/null 2>&1; then
    arr_qbt_migrate_legacy_conf "$docker_root"
  fi

  local candidate=""
  candidate="$(arr_qbt_conf_path "$docker_root")"

  if [[ ! -f "$candidate" ]]; then
    return 0
  fi

  local configured_port=""
  configured_port="$(arr_read_sensitive_file "$candidate" \
    | grep -E '^WebUI(\\\\|\\\\\\\\)Port=' \
    | tail -n1 \
    | cut -d= -f2 \
    | tr -d '[:space:]' || printf '')"

  if [[ -n "$configured_port" && "$configured_port" =~ ^[0-9]+$ ]]; then
    ARR_QBT_INT_PORT_CONFIG="$configured_port"
  fi
}

# Pulls existing qBittorrent credentials from .env to avoid unintended resets
hydrate_user_credentials_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  local default_user="admin"
  local default_pass="adminadmin"

  local existing_user=""
  local existing_pass=""

  # Read from .env first
  existing_user="$(get_env_kv "QBT_USER" "$ARR_ENV_FILE" 2>/dev/null || printf '')"
  existing_pass="$(get_env_kv "QBT_PASS" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

  # Hydrate username if .env has a value and userr.conf hasn't overridden it
  if [[ -n "$existing_user" ]]; then
    if [[ -z "${QBT_USER:-}" || "${QBT_USER}" == "$default_user" ]]; then
      QBT_USER="$existing_user"
      arr_record_preserve_note "Preserved qBittorrent username from existing .env"
    fi
  fi

  # Hydrate password if .env has a value and userr.conf hasn't overridden it
  if [[ -n "$existing_pass" ]]; then
    if [[ -z "${QBT_PASS:-}" || "${QBT_PASS}" == "$default_pass" ]]; then
      QBT_PASS="$existing_pass"
      arr_record_preserve_note "Preserved qBittorrent password from existing .env"
    fi
  fi
}

# Generic hydration function for values from .env file
# Takes an associative array of variable names and their defaults
# Centralizes the common logic used by all hydration functions
hydrate_values_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  local -n vars_ref="$1"
  local var_name default_value current_value existing_value

  for var_name in "${!vars_ref[@]}"; do
    default_value="${vars_ref[$var_name]}"
    current_value="${!var_name:-}"

    # Skip if user has already set a non-default value in userr.conf
    # This checks if the current value is explicitly set and differs from default
    if [[ -n "$current_value" && "$current_value" != "$default_value" ]]; then
      continue
    fi

    # Read from .env first
    existing_value="$(get_env_kv "$var_name" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

    # If .env has a value, use it (regardless of whether it matches the default)
    if [[ -n "$existing_value" ]]; then
      printf -v "$var_name" '%s' "$existing_value"
      arr_record_preserve_note "Preserved ${var_name} from existing .env"
    fi
  done
}

# Pulls existing qBittorrent WebUI auth whitelist from .env to preserve user settings
hydrate_qbt_auth_whitelist_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  # Use evaluated default that matches userr.conf.defaults.sh
  local default_whitelist="${QBT_AUTH_WHITELIST:-127.0.0.1/32,::1/128,172.17.0.0/16,::ffff:172.28.0.1/128}"
  local current_whitelist="${QBT_AUTH_WHITELIST:-}"

  # Skip if user has already set a non-default whitelist in userr.conf
  if [[ -n "$current_whitelist" && "$current_whitelist" != "$default_whitelist" ]]; then
    return 0
  fi

  # Read from .env first
  local existing_whitelist=""
  existing_whitelist="$(get_env_kv "QBT_AUTH_WHITELIST" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

  # If .env has a value, use it (regardless of whether it matches the default)
  if [[ -n "$existing_whitelist" ]]; then
    QBT_AUTH_WHITELIST="$existing_whitelist"
    arr_record_preserve_note "Preserved qBittorrent WebUI whitelist from existing .env"
  fi
}

# Hydrates GLUETUN_API_KEY from .env when available so reruns preserve API access
hydrate_gluetun_api_key_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  # Skip if FORCE_ROTATE_API_KEY is set
  if [[ "${FORCE_ROTATE_API_KEY:-0}" == "1" ]]; then
    return 0
  fi

  # Skip if user has already set a non-empty key in userr.conf
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    return 0
  fi

  local existing_key=""
  existing_key="$(get_env_kv "GLUETUN_API_KEY" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

  if [[ -n "$existing_key" ]]; then
    GLUETUN_API_KEY="$existing_key"
    arr_record_preserve_note "Preserved Gluetun API key from existing .env"
  fi
}

# Hydrates service ports from .env to preserve user customizations
hydrate_service_ports_from_env_file() {
  local -A port_vars=(
    ["SONARR_PORT"]="${SONARR_INT_PORT:-8989}"
    ["RADARR_PORT"]="${RADARR_INT_PORT:-7878}"
    ["LIDARR_PORT"]="${LIDARR_INT_PORT:-8686}"
    ["PROWLARR_PORT"]="${PROWLARR_INT_PORT:-9696}"
    ["BAZARR_PORT"]="${BAZARR_INT_PORT:-6767}"
    ["FLARR_PORT"]="${FLARR_INT_PORT:-8191}"
    ["SABNZBD_PORT"]="${SABNZBD_INT_PORT:-8081}"
  )

  hydrate_values_from_env_file port_vars
}

# Hydrates VPN settings from .env to preserve user's server selections
hydrate_vpn_settings_from_env_file() {
  local -A vpn_vars=(
    ["SERVER_COUNTRIES"]="Netherlands,Singapore"
    ["SERVER_NAMES"]=""
    ["PVPN_ROTATE_COUNTRIES"]=""
  )

  hydrate_values_from_env_file vpn_vars
}

# Hydrates network settings from .env to preserve custom network configs
hydrate_network_settings_from_env_file() {
  local -A network_vars=(
    ["LAN_IP"]=""
    ["GLUETUN_CONTROL_PORT"]="8000"
    ["GLUETUN_CONTROL_BIND"]="all"
  )

  hydrate_values_from_env_file network_vars
}

# Hydrates container image versions from .env to prevent unwanted upgrades
hydrate_image_versions_from_env_file() {
  local -A image_vars=(
    ["GLUETUN_IMAGE"]="qmcgaw/gluetun:v3.40.0"
    ["QBITTORRENT_IMAGE"]="lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415"
    ["SONARR_IMAGE"]="lscr.io/linuxserver/sonarr:4.0.15.2941-ls291"
    ["RADARR_IMAGE"]="lscr.io/linuxserver/radarr:5.27.5.10198-ls283"
    ["LIDARR_IMAGE"]="lscr.io/linuxserver/lidarr:latest"
    ["PROWLARR_IMAGE"]="lscr.io/linuxserver/prowlarr:latest"
    ["BAZARR_IMAGE"]="lscr.io/linuxserver/bazarr:latest"
    ["FLARR_IMAGE"]="ghcr.io/flaresolverr/flaresolverr:v3.3.21"
    ["SABNZBD_IMAGE"]="lscr.io/linuxserver/sabnzbd:latest"
    ["CONFIGARR_IMAGE"]="ghcr.io/raydak-labs/configarr:latest"
  )

  hydrate_values_from_env_file image_vars
}

# Hydrates ConfigArr quality/profile settings from .env to preserve user preferences
hydrate_configarr_settings_from_env_file() {
  local -A configarr_vars=(
    ["ARR_VIDEO_MIN_RES"]="720p"
    ["ARR_VIDEO_MAX_RES"]="1080p"
    ["ARR_EP_MIN_MB"]="250"
    ["ARR_EP_MAX_GB"]="5"
    ["ARR_TV_RUNTIME_MIN"]="45"
    ["ARR_SEASON_MAX_GB"]="30"
    ["ARR_LANG_PRIMARY"]="en"
    ["ARR_ENGLISH_ONLY"]="1"
    ["ARR_DISCOURAGE_MULTI"]="1"
    ["ARR_PENALIZE_HD_X265"]="1"
    ["ARR_STRICT_JUNK_BLOCK"]="1"
    ["ARR_JUNK_NEGATIVE_SCORE"]="-1000"
    ["ARR_X265_HD_NEGATIVE_SCORE"]="-200"
    ["ARR_MULTI_NEGATIVE_SCORE"]="-50"
    ["ARR_ENGLISH_POSITIVE_SCORE"]="50"
    ["SONARR_TRASH_TEMPLATE"]="sonarr-v4-quality-profile-web-1080p"
    ["RADARR_TRASH_TEMPLATE"]="radarr-v5-quality-profile-hd-bluray-web"
    ["ARR_MBMIN_DECIMALS"]="1"
  )

  hydrate_values_from_env_file configarr_vars
}

# Hydrates VPN auto-reconnect settings from .env to preserve tuning
hydrate_vpn_auto_reconnect_from_env_file() {
  local -A vpn_auto_vars=(
    ["VPN_AUTO_RECONNECT_ENABLED"]="0"
    ["VPN_SPEED_THRESHOLD_KBPS"]="12"
    ["VPN_CHECK_INTERVAL_MINUTES"]="20"
    ["VPN_CONSECUTIVE_CHECKS"]="3"
    ["VPN_ALLOWED_HOURS_START"]=""
    ["VPN_ALLOWED_HOURS_END"]=""
    ["VPN_COOLDOWN_MINUTES"]="60"
    ["VPN_MAX_RETRY_MINUTES"]="20"
    ["VPN_ROTATION_MAX_PER_DAY"]="6"
    ["VPN_ROTATION_JITTER_SECONDS"]="0"
  )

  hydrate_values_from_env_file vpn_auto_vars
}

# Hydrates Gluetun API settings from .env to preserve custom timeouts and retry configs
hydrate_gluetun_api_settings_from_env_file() {
  local -A gluetun_api_vars=(
    ["GLUETUN_API_TIMEOUT"]="10"
    ["GLUETUN_API_RETRY_COUNT"]="3"
    ["GLUETUN_API_RETRY_DELAY"]="2"
    ["GLUETUN_API_MAX_RETRY_DELAY"]="8"
    ["GLUETUN_CONNECTIVITY_PROBE_URLS"]="https://api.ipify.org,https://ipconfig.io/ip,https://1.1.1.1/cdn-cgi/trace"
  )

  hydrate_values_from_env_file gluetun_api_vars
}

# Hydrates qBittorrent API settings from .env to preserve custom timeouts and retry configs
hydrate_qbt_api_settings_from_env_file() {
  local -A qbt_api_vars=(
    ["QBT_API_TIMEOUT"]="10"
    ["QBT_API_RETRY_COUNT"]="3"
    ["QBT_API_RETRY_DELAY"]="2"
  )

  hydrate_values_from_env_file qbt_api_vars
}

# Hydrates SABnzbd settings from .env to preserve user configurations
hydrate_sabnzbd_settings_from_env_file() {
  local -A sab_vars=(
    ["SABNZBD_ENABLED"]="0"
    ["SABNZBD_USE_VPN"]="0"
    ["SABNZBD_HOST"]="${LOCALHOST_IP}"
    ["SABNZBD_CATEGORY"]="${STACK}"
    ["SABNZBD_TIMEOUT"]="15"
  )

  hydrate_values_from_env_file sab_vars
}

# Creates timestamped backup of critical configuration files before modifications
# Returns 0 on success, non-zero if backup fails
# Exports ARR_BACKUP_DIR with the backup location
arr_backup_critical_files() {
  local timestamp
  timestamp="$(arr_date_local '+%Y%m%d-%H%M%S')"

  local backup_root="${ARR_STACK_DIR}/.backups"
  local backup_dir="${backup_root}/${timestamp}"

  # Create backup directory
  if ! mkdir -p "${backup_dir}" 2>/dev/null; then
    warn "Failed to create backup directory: ${backup_dir}"
    return 1
  fi

  # Ensure backup directory has secure permissions
  chmod 700 "${backup_dir}" 2>/dev/null || true

  local backed_up_count=0
  local docker_root
  docker_root="$(arr_docker_data_root)"

  # Backup .env file
  local env_file="${ARR_STACK_DIR}/.env"
  if [[ -f "${env_file}" ]]; then
    if cp -a "${env_file}" "${backup_dir}/.env" 2>/dev/null; then
      chmod 600 "${backup_dir}/.env" 2>/dev/null || true
      ((backed_up_count++))
    else
      warn "Failed to backup .env file"
    fi
  fi

  # Backup docker-compose.yml
  local compose_file="${ARR_STACK_DIR}/docker-compose.yml"
  if [[ -f "${compose_file}" ]]; then
    if cp -a "${compose_file}" "${backup_dir}/docker-compose.yml" 2>/dev/null; then
      chmod 600 "${backup_dir}/docker-compose.yml" 2>/dev/null || true
      ((backed_up_count++))
    else
      warn "Failed to backup docker-compose.yml"
    fi
  fi

  # Backup qBittorrent config
  local qbt_conf
  qbt_conf="$(arr_qbt_conf_path "${docker_root}")"
  if [[ -f "${qbt_conf}" ]]; then
    local qbt_backup_dir="${backup_dir}/qbittorrent"
    if mkdir -p "${qbt_backup_dir}" 2>/dev/null; then
      chmod 700 "${qbt_backup_dir}" 2>/dev/null || true
      if cp -a "${qbt_conf}" "${qbt_backup_dir}/qBittorrent.conf" 2>/dev/null; then
        chmod 600 "${qbt_backup_dir}/qBittorrent.conf" 2>/dev/null || true
        ((backed_up_count++))
      else
        warn "Failed to backup qBittorrent.conf"
      fi
    fi
  fi

  # Backup Gluetun auth config
  local gluetun_auth_config="${docker_root}/gluetun/auth/config.toml"
  if [[ -f "${gluetun_auth_config}" ]]; then
    local gluetun_backup_dir="${backup_dir}/gluetun"
    if mkdir -p "${gluetun_backup_dir}" 2>/dev/null; then
      chmod 700 "${gluetun_backup_dir}" 2>/dev/null || true
      if cp -a "${gluetun_auth_config}" "${gluetun_backup_dir}/config.toml" 2>/dev/null; then
        chmod 600 "${gluetun_backup_dir}/config.toml" 2>/dev/null || true
        ((backed_up_count++))
      else
        warn "Failed to backup Gluetun auth config"
      fi
    fi
  fi

  if ((backed_up_count > 0)); then
    ARR_BACKUP_DIR="${backup_dir}"
    export ARR_BACKUP_DIR
    msg "📦 Backup created at: ${backup_dir}"
    msg "   Backed up ${backed_up_count} file(s)"
    return 0
  else
    warn "No files were backed up"
    # Clean up empty backup directory tree (may have subdirectories)
    rm -rf "${backup_dir}" 2>/dev/null || true
    return 1
  fi
}

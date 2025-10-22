# shellcheck shell=bash

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
      timestamp="$(date +%Y%m%d-%H%M%S)"
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
  local config_dir
  config_dir="$(arr_docker_data_root)/qbittorrent"
  local primary_conf="${config_dir}/qBittorrent.conf"
  local legacy_conf="${config_dir}/qBittorrent/qBittorrent.conf"
  local candidate=""

  if [[ -f "$primary_conf" ]]; then
    candidate="$primary_conf"
  elif [[ -f "$legacy_conf" ]]; then
    candidate="$legacy_conf"
  else
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

  existing_user="$(get_env_kv "QBT_USER" "$ARR_ENV_FILE" 2>/dev/null || printf '')"
  existing_pass="$(get_env_kv "QBT_PASS" "$ARR_ENV_FILE" 2>/dev/null || printf '')"

  if [[ -n "$existing_user" && "$existing_user" != "$default_user" ]]; then
    if [[ -z "${QBT_USER:-}" || "${QBT_USER}" == "$default_user" ]]; then
      QBT_USER="$existing_user"
      arr_record_preserve_note "Preserved qBittorrent username from existing .env"
    fi
  fi

  if [[ -n "$existing_pass" && "$existing_pass" != "$default_pass" ]]; then
    if [[ -z "${QBT_PASS:-}" || "${QBT_PASS}" == "$default_pass" ]]; then
      QBT_PASS="$existing_pass"
      arr_record_preserve_note "Preserved qBittorrent password from existing .env"
    fi
  fi
}

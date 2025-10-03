# shellcheck shell=bash

# Collects status notes for summary output when values are preserved
arrstack_record_preserve_note() {
  local note="$1"

  if [[ -z "$note" ]]; then
    return 0
  fi

  if [[ -z "${ARRSTACK_PRESERVE_NOTES:-}" ]]; then
    ARRSTACK_PRESERVE_NOTES="$note"
  else
    ARRSTACK_PRESERVE_NOTES="$(printf '%s\n%s' "${ARRSTACK_PRESERVE_NOTES}" "$note")"
  fi
}

# Hydrates SABNZBD_API_KEY from sabnzbd.ini when available so reruns keep API access
hydrate_sab_api_key_from_config() {
  if [[ "${SABNZBD_ENABLED:-0}" != "1" ]]; then
    return 0
  fi

  local config_dir="${ARR_DOCKER_DIR:-${ARR_STACK_DIR}/docker-data}/sab/config"
  local ini_path="${config_dir}/sabnzbd.ini"

  if [[ ! -f "$ini_path" ]]; then
    return 0
  fi

  if [[ -z "${ARRSTACK_SAB_INI_BACKUP:-}" ]]; then
    local timestamp backup_path
    timestamp="$(date +%Y%m%d-%H%M%S)"
    backup_path="${ini_path}.bak.${timestamp}"
    if cp -a "$ini_path" "$backup_path" 2>/dev/null; then
      ARRSTACK_SAB_INI_BACKUP="$backup_path"
      arrstack_record_preserve_note "Backed up sabnzbd.ini to ${backup_path##*/}"
    fi
  fi

  local api_key_line api_key_value
  api_key_line="$(grep -i '^[[:space:]]*api_key[[:space:]]*=' "$ini_path" | tail -n1 || printf '')"
  if [[ -z "$api_key_line" ]]; then
    return 0
  fi

  api_key_value="${api_key_line#*=}"
  api_key_value="${api_key_value#${api_key_value%%[![:space:]]*}}"
  api_key_value="${api_key_value%${api_key_value##*[![:space:]]}}"

  if [[ -z "$api_key_value" ]]; then
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
    SABNZBD_API_KEY="$api_key_value"
    arrstack_record_preserve_note "Hydrated SABnzbd API key from sabnzbd.ini"
  fi

  return 0
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
      arrstack_record_preserve_note "Preserved qBittorrent username from existing .env"
    fi
  fi

  if [[ -n "$existing_pass" && "$existing_pass" != "$default_pass" ]]; then
    if [[ -z "${QBT_PASS:-}" || "${QBT_PASS}" == "$default_pass" ]]; then
      QBT_PASS="$existing_pass"
      arrstack_record_preserve_note "Preserved qBittorrent password from existing .env"
    fi
  fi
}

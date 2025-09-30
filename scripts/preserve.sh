# shellcheck shell=bash

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

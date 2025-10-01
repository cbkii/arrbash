# shellcheck shell=bash
# shellcheck disable=SC2034

# Extracts API key from an Arr config.xml, tolerating partially initialised files
arrstack_detect_api_key_from_config() {
  local config_path="$1"

  if [[ -z "$config_path" || ! -f "$config_path" ]]; then
    return 1
  fi

  local api_key=""

  if have_command python3; then
    api_key="$(
      python3 <<'PY'
import sys
import xml.etree.ElementTree as ET

path = sys.argv[1]
try:
    tree = ET.parse(path)
except Exception:
    sys.exit(1)
root = tree.getroot()
for element in root.iter():
    if element.tag and element.tag.lower() == "apikey":
        value = (element.text or "").strip()
        if value:
            print(value)
            sys.exit(0)
sys.exit(1)
PY
      "$config_path" 2>/dev/null || true
    )"
  fi

  if [[ -z "$api_key" ]]; then
    api_key="$(sed -n 's:.*<ApiKey>\([^<]*\)</ApiKey>.*:\1:p' "$config_path" | head -n1 | tr -d '\r\n' || true)"
    api_key="${api_key//$'\t'/}"
    api_key="${api_key#"${api_key%%[![:space:]]*}"}"
    api_key="${api_key%"${api_key##*[![:space:]]}"}"
  fi

  if [[ -n "$api_key" && ${#api_key} -ge 10 ]]; then
    printf '%s\n' "$api_key"
    return 0
  fi

  return 1
}

# Writes or refreshes a Configarr secret entry while respecting placeholders and force flag
arrstack_update_secret_line() {
  local secrets_file="$1"
  local secret_key="$2"
  local new_value="$3"
  local force_input="${4:-}"

  if [[ -z "$force_input" ]]; then
    force_input="${FORCE_SYNC_API_KEYS:-0}"
  fi

  local force_update=0
  if [[ "$force_input" == "1" ]]; then
    force_update=1
  fi

  if [[ -z "$secrets_file" || -z "$secret_key" || -z "$new_value" ]]; then
    return 1
  fi

  if [[ ${#new_value} -lt 10 ]]; then
    printf 'skipped\n'
    return 1
  fi

  if [[ ! -f "$secrets_file" ]]; then
    printf '%s: "%s"\n' "$secret_key" "$new_value" >"$secrets_file"
    ensure_secret_file_mode "$secrets_file"
    printf 'created\n'
    return 0
  fi

  ensure_secret_file_mode "$secrets_file"

  local existing_line
  existing_line="$(grep -n -m1 "^${secret_key}:" "$secrets_file" 2>/dev/null || true)"

  if [[ -z "$existing_line" ]]; then
    printf '%s: "%s"\n' "$secret_key" "$new_value" >>"$secrets_file"
    ensure_secret_file_mode "$secrets_file"
    printf 'appended\n'
    return 0
  fi

  local line_no="${existing_line%%:*}"
  local raw_value="${existing_line#*:}"

  raw_value="${raw_value#"${raw_value%%[![:space:]]*}"}"
  raw_value="${raw_value%%#*}"
  raw_value="${raw_value%"${raw_value##*[![:space:]]}"}"
  raw_value="${raw_value%$'\r'}"

  local unquoted_value="$raw_value"
  if [[ ${#unquoted_value} -ge 2 ]]; then
    if [[ ${unquoted_value:0:1} == '"' && ${unquoted_value: -1} == '"' ]]; then
      unquoted_value="${unquoted_value:1:${#unquoted_value}-2}"
    elif [[ ${unquoted_value:0:1} == "'" && ${unquoted_value: -1} == "'" ]]; then
      unquoted_value="${unquoted_value:1:${#unquoted_value}-2}"
    fi
  fi

  if [[ "$unquoted_value" == "$new_value" ]]; then
    printf 'unchanged\n'
    return 0
  fi

  local placeholder=0
  if [[ -z "$unquoted_value" ]]; then
    placeholder=1
  else
    local upper_value
    upper_value="${unquoted_value^^}"
    if [[ "$upper_value" == REPLACE_WITH_* ]]; then
      placeholder=1
    elif [[ "$upper_value" == 'NULL' || "$upper_value" == '~' ]]; then
      placeholder=1
    fi
  fi

  local should_update=$((placeholder == 1 || force_update == 1))

  if ((should_update == 0)); then
    printf 'unchanged\n'
    return 0
  fi

  local escaped
  escaped="$(escape_sed_replacement "\"${new_value}\"")"
  portable_sed "${line_no}s|^${secret_key}:.*|${secret_key}: ${escaped}|" "$secrets_file"
  ensure_secret_file_mode "$secrets_file"
  printf 'updated\n'
  return 0
}

# Pulls Sonarr/Radarr/Prowlarr API keys into secrets.yml, tracking sync status for summary output
arrstack_sync_arr_api_keys() {
  local force_sync="${1:-${FORCE_SYNC_API_KEYS:-0}}"

  API_KEYS_SYNCED_STATUS=""
  API_KEYS_SYNCED_MESSAGE=""
  API_KEYS_SYNCED_DETAILS=""
  API_KEYS_SYNCED_PLACEHOLDERS=0

  if [[ "${ENABLE_CONFIGARR:-0}" != "1" ]]; then
    API_KEYS_SYNCED_STATUS="skipped"
    API_KEYS_SYNCED_MESSAGE="Configarr disabled; API key sync skipped."
    return 0
  fi

  local secrets_file="${ARR_DOCKER_DIR}/configarr/secrets.yml"
  if [[ ! -f "$secrets_file" ]]; then
    API_KEYS_SYNCED_STATUS="pending"
    API_KEYS_SYNCED_MESSAGE="Configarr secrets.yml missing; run installer to regenerate Configarr assets."
    API_KEYS_SYNCED_PLACEHOLDERS=1
    return 0
  fi

  ensure_secret_file_mode "$secrets_file"

  local -A service_labels=(
    [sonarr]="Sonarr"
    [radarr]="Radarr"
    [prowlarr]="Prowlarr"
  )
  local -A config_paths=(
    [sonarr]="${ARR_DOCKER_DIR}/sonarr/config.xml"
    [radarr]="${ARR_DOCKER_DIR}/radarr/config.xml"
    [prowlarr]="${ARR_DOCKER_DIR}/prowlarr/config.xml"
  )
  local -A secret_keys=(
    [sonarr]="SONARR_API_KEY"
    [radarr]="RADARR_API_KEY"
    [prowlarr]="PROWLARR_API_KEY"
  )

  local -A status_map=()
  local details=""
  local updated_count=0
  local pending_count=0
  local ready_count=0

  local service
  # Walk each Arr app to reflect current API key into secrets.yml
  for service in sonarr radarr prowlarr; do
    local label="${service_labels[$service]}"
    local config_path="${config_paths[$service]}"
    local secret_key="${secret_keys[$service]}"

    if [[ ! -f "$config_path" ]]; then
      status_map[$service]="pending"
      pending_count=$((pending_count + 1))
      API_KEYS_SYNCED_PLACEHOLDERS=1
      details+="${label}: config.xml not found yet (start the container, then rerun sync)."$'\n'
      continue
    fi

    local api_key=""
    if ! api_key="$(arrstack_detect_api_key_from_config "$config_path" 2>/dev/null)"; then
      status_map[$service]="pending"
      pending_count=$((pending_count + 1))
      API_KEYS_SYNCED_PLACEHOLDERS=1
      details+="${label}: API key unavailable in config.xml (service may still be initialising)."$'\n'
      continue
    fi

    local result=""
    if result="$(arrstack_update_secret_line "$secrets_file" "$secret_key" "$api_key" "$force_sync" 2>/dev/null)"; then
      case "$result" in
        updated | created | appended)
          status_map[$service]="updated"
          updated_count=$((updated_count + 1))
          details+="${label}: synced API key from config.xml."$'\n'
          ;;
        unchanged)
          status_map[$service]="unchanged"
          ready_count=$((ready_count + 1))
          details+="${label}: API key already populated; nothing to do."$'\n'
          ;;
        *)
          status_map[$service]="pending"
          pending_count=$((pending_count + 1))
          API_KEYS_SYNCED_PLACEHOLDERS=1
          details+="${label}: could not update secrets.yml automatically; edit manually."$'\n'
          ;;
      esac
    else
      status_map[$service]="pending"
      pending_count=$((pending_count + 1))
      API_KEYS_SYNCED_PLACEHOLDERS=1
      details+="${label}: failed to update secrets.yml automatically; edit manually."$'\n'
    fi
  done

  local -a parts=()
  for service in sonarr radarr prowlarr; do
    local label="${service_labels[$service]}"
    local status="${status_map[$service]:-skipped}"
    parts+=("${label}=${status}")
  done

  API_KEYS_SYNCED_MESSAGE="Configarr API key sync: ${parts[*]}"
  API_KEYS_SYNCED_DETAILS="${details%$'\n'}"

  if ((updated_count > 0)); then
    API_KEYS_SYNCED_STATUS="updated"
  elif ((pending_count > 0)); then
    API_KEYS_SYNCED_STATUS="pending"
  else
    API_KEYS_SYNCED_STATUS="unchanged"
  fi

  if grep -Fq 'REPLACE_WITH_' "$secrets_file" 2>/dev/null; then
    API_KEYS_SYNCED_PLACEHOLDERS=1
  fi

  return 0
}

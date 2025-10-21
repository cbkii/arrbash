# shellcheck shell=bash
# Generates a bcrypt hash for Caddy credentials, preferring local openssl before docker fallback
caddy_bcrypt() {
  local plaintext="${1-}"

  if [[ -z "$plaintext" ]]; then
    return 1
  fi

  local hash_output=""

  if command -v openssl >/dev/null 2>&1; then
    hash_output="$(
      printf '%s\n' "$plaintext" \
        | openssl passwd -bcrypt -stdin 2>/dev/null
    )" || true

    if [[ -n "$hash_output" ]]; then
      printf '%s\n' "$hash_output"
      return 0
    fi
  fi

  docker run --rm "${CADDY_IMAGE}" caddy hash-password --algorithm bcrypt --plaintext "$plaintext" 2>/dev/null
}

# Records newly created media directories for later collab warnings
arr_track_created_media_dir() {
  local dir="$1"

  if [[ -z "$dir" ]]; then
    return 0
  fi

  if [[ -z "${COLLAB_CREATED_MEDIA_DIRS:-}" ]]; then
    COLLAB_CREATED_MEDIA_DIRS="$dir"
  else
    local padded=$'\n'"${COLLAB_CREATED_MEDIA_DIRS}"$'\n'
    local needle=$'\n'"${dir}"$'\n'
    if [[ "$padded" != *"${needle}"* ]]; then
      COLLAB_CREATED_MEDIA_DIRS+=$'\n'"${dir}"
    fi
  fi
}

# Emits a one-time warning when collab profile cannot grant group write
arr_report_collab_skip() {
  if [[ -n "${COLLAB_GROUP_WRITE_DISABLED_REASON:-}" ]]; then
    arr_append_collab_warning "${COLLAB_GROUP_WRITE_DISABLED_REASON}"
  fi
}

arr_prompt_direct_port_exposure() {
  local lan_ip="$1"
  local ip_hint="$lan_ip"

  if [[ -z "$ip_hint" || "$ip_hint" == "0.0.0.0" ]] || ! validate_ipv4 "$ip_hint"; then
    local detected_ip=""
    detected_ip="$(hostname -I 2>/dev/null | awk 'NF {print $1}' | tr -d '\n')"
    if [[ -z "$detected_ip" ]] || [[ "$detected_ip" == "0.0.0.0" ]] || ! validate_ipv4 "$detected_ip"; then
      ip_hint="127.0.0.1"
    else
      ip_hint="$detected_ip"
    fi
  fi

  msg "EXPOSE_DIRECT_PORTS=1 will publish the following LAN URLs:"
  printf '  %-11s → http://%s:%s\n' "qBittorrent" "$ip_hint" "$QBT_PORT"
  printf '  %-11s → http://%s:%s\n' "Sonarr" "$ip_hint" "$SONARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Radarr" "$ip_hint" "$RADARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Prowlarr" "$ip_hint" "$PROWLARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Bazarr" "$ip_hint" "$BAZARR_PORT"
  printf '  %-11s → http://%s:%s\n' "FlareSolverr" "$ip_hint" "$FLARR_PORT"

  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    msg "ASSUME_YES=1; continuing without additional confirmation."
    return 0
  fi

  printf 'Expose these ports on the LAN? [y/N]: '
  local response=""
  if ! read -r response; then
    warn "Could not read confirmation response; disabling EXPOSE_DIRECT_PORTS for safety."
    EXPOSE_DIRECT_PORTS=0
    return 0
  fi

  case "${response,,}" in
    y | yes)
      msg "Continuing with EXPOSE_DIRECT_PORTS=1."
      ;;
    *)
      warn "Disabling EXPOSE_DIRECT_PORTS for this run; rerun with --yes to skip the prompt."
      EXPOSE_DIRECT_PORTS=0
      ;;
  esac
}


# Creates stack/data/media directories and reconciles permissions per profile
mkdirs() {
  step "📂 Creating directories"
  ensure_dir_mode "$ARR_STACK_DIR" 755

  ensure_dir_mode "$ARR_DOCKER_DIR" "$DATA_DIR_MODE"

  local service
  for service in "${ARR_DOCKER_SERVICES[@]}"; do
    if [[ "$service" == "local_dns" && "${ENABLE_LOCAL_DNS:-0}" != "1" ]]; then
      continue
    fi
    if [[ "$service" == "caddy" && "${ENABLE_CADDY:-0}" != "1" ]]; then
      continue
    fi
    if [[ "$service" == "sabnzbd" && "${SABNZBD_ENABLED:-0}" != "1" ]]; then
      continue
    fi
    ensure_dir_mode "${ARR_DOCKER_DIR}/${service}" "$DATA_DIR_MODE"
  done

  local collab_enabled=0
  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && "${COLLAB_GROUP_WRITE_ENABLED:-0}" == "1" ]]; then
    collab_enabled=1
  elif [[ "${ARR_PERMISSION_PROFILE}" == "collab" ]]; then
    arr_report_collab_skip
  fi

  local -a collab_setup_dirs=("$DOWNLOADS_DIR" "$COMPLETED_DIR") collab_setup_labels=("Downloads" "Completed")
  local idx
  for idx in "${!collab_setup_dirs[@]}"; do
    local dir="${collab_setup_dirs[$idx]}"
    local label="${collab_setup_labels[$idx]}"
    ensure_dir "$dir"
    if ((collab_enabled)) && [[ -d "$dir" ]]; then
      chmod "$DATA_DIR_MODE" "$dir" 2>/dev/null || true
      if ! arr_is_group_writable "$dir"; then
        arr_warn_collab_once "${label} directory not group-writable and could not apply ${DATA_DIR_MODE} (collab) — fix manually: ${dir}"
      fi
    fi
  done

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  if [[ -d "$ARRCONF_DIR" ]]; then
    ensure_dir_mode "$ARRCONF_DIR" 700
    if [[ -f "${ARRCONF_DIR}/proton.auth" ]]; then
      ensure_secret_file_mode "${ARRCONF_DIR}/proton.auth"
    fi
  fi

  manage_media_dir() {
    local dir="$1"
    local label="$2"
    [[ -z "$dir" ]] && return 0

    if [[ ! -d "$dir" ]]; then
      warn "${label} directory does not exist: ${dir}"
      warn "Creating it now (may fail if parent directory is missing)"
      if mkdir -p "$dir" 2>/dev/null; then
        arr_track_created_media_dir "$dir"
      else
        warn "Could not create ${label} directory"
        return 0
      fi
    fi

    if ((collab_enabled)) && [[ -d "$dir" ]]; then
      chmod "$DATA_DIR_MODE" "$dir" 2>/dev/null || true
      if ! arr_is_group_writable "$dir"; then
        arr_warn_collab_once "${label} directory not group-writable and could not apply ${DATA_DIR_MODE} (collab) — fix manually: ${dir}"
      fi
    fi
  }

  manage_media_dir "$TV_DIR" "TV"
  manage_media_dir "$MOVIES_DIR" "Movies"

  if [[ -n "${SUBS_DIR:-}" ]]; then
    manage_media_dir "$SUBS_DIR" "Subtitles"
  fi

  if [[ -n "${PUID:-}" && -n "${PGID:-}" ]]; then
    local ownership_marker="${ARR_DOCKER_DIR}/.${STACK}-owner"
    local desired_owner="${PUID}:${PGID}"
    local current_owner=""

    if [[ -f "$ownership_marker" ]]; then
      current_owner="$(<"$ownership_marker")"
    fi

    if [[ "$current_owner" != "$desired_owner" ]]; then
      if chown -R "${desired_owner}" "$ARR_DOCKER_DIR" 2>/dev/null; then
        printf '%s\n' "$desired_owner" >"$ownership_marker" 2>/dev/null || true
      else
        warn "Could not update ownership on $ARR_DOCKER_DIR"
      fi
    fi
  fi
}

# Produces an alphanumeric token using the strongest available entropy source
safe_random_alnum() {
  local len="${1:-64}"
  if [[ ! "$len" =~ ^[0-9]+$ || "$len" -le 0 ]]; then
    len=64
  fi
  local output=""
  local chunk=""
  local need=0
  while ((${#output} < len)); do
    need=$((len - ${#output}))
    if command -v openssl >/dev/null 2>&1; then
      chunk="$(openssl rand -base64 $((need * 2)) 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$need")"
    elif [[ -r /dev/urandom ]]; then
      chunk="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$need")"
    else
      chunk="$(printf '%s' "$RANDOM$RANDOM$RANDOM" | tr -dc 'A-Za-z0-9' | head -c "$need")"
    fi
    if [[ -z "$chunk" ]]; then
      continue
    fi
    output+="$chunk"
  done
  printf '%s\n' "${output:0:len}"
}

# Ensures GLUETUN_API_KEY exists, rotating auth config when forced or missing
generate_api_key() {
  step "🔐 Generating API key"

  if [[ -f "$ARR_ENV_FILE" ]] && [[ "$FORCE_ROTATE_API_KEY" != "1" ]]; then
    local existing
    existing="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [[ -n "$existing" ]]; then
      existing="$(unescape_env_value_from_compose "$existing")"
      GLUETUN_API_KEY="$existing"
      msg "Using existing API key"
      return
    fi
  fi

  GLUETUN_API_KEY="$(safe_random_alnum 64)"
  msg "Generated new API key"

  if gluetun_version_requires_auth_config 2>/dev/null; then
    local auth_config="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
    if [[ -f "$auth_config" ]]; then
      rm -f "$auth_config"
      msg "Removed existing auth config for key rotation"
    fi
  fi
}

# Reloads persisted Caddy credentials so manual changes survive re-runs
hydrate_caddy_auth_from_env_file() {
  if [[ -z "${ARR_ENV_FILE:-}" || ! -f "$ARR_ENV_FILE" ]]; then
    return 0
  fi

  if [[ -z "${CADDY_BASIC_AUTH_USER:-}" || "${CADDY_BASIC_AUTH_USER}" == "user" ]]; then
    local hydrated_user=""
    if hydrated_user="$(get_env_kv "CADDY_BASIC_AUTH_USER" "$ARR_ENV_FILE" 2>/dev/null)"; then
      if [[ -n "$hydrated_user" ]]; then
        CADDY_BASIC_AUTH_USER="$hydrated_user"
      fi
    fi
  fi

  if [[ -z "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
    local hydrated_hash=""
    if hydrated_hash="$(get_env_kv "CADDY_BASIC_AUTH_HASH" "$ARR_ENV_FILE" 2>/dev/null)"; then
      if [[ -n "$hydrated_hash" ]]; then
        CADDY_BASIC_AUTH_HASH="$hydrated_hash"
      fi
    fi
  fi
}

arr_prune_compose_backups() {
  local prefix="$1"

  local nullglob_was_set=0
  if shopt -q nullglob; then
    nullglob_was_set=1
  fi
  shopt -s nullglob

  local -a backups=("${prefix}".*)

  if ((nullglob_was_set == 0)); then
    shopt -u nullglob
  fi

  if ((${#backups[@]} <= 3)); then
    return 0
  fi

  local -a sorted_backups=()
  mapfile -t sorted_backups < <(printf '%s\n' "${backups[@]}" | sort -r)

  local idx
  for idx in "${!sorted_backups[@]}"; do
    if ((idx >= 3)); then
      rm -f -- "${sorted_backups[$idx]}" 2>/dev/null || true
    fi
  done
}

arr_safe_compose_write() {
  local target="$1"
  local tmp="$2"
  local backup_prefix="${target}.backup"
  local backup_created=""

  if [[ -f "${backup_prefix}" ]]; then
    local legacy_name
    legacy_name="${backup_prefix}.$(date +%Y%m%d%H%M%S%N).legacy"
    if ! mv "${backup_prefix}" "${legacy_name}" 2>/dev/null; then
      rm -f "${backup_prefix}" 2>/dev/null || true
    fi
  fi

  if [[ -f "$target" ]]; then
    local timestamp
    timestamp="$(date +%Y%m%d%H%M%S%N)"
    backup_created="${backup_prefix}.${timestamp}"
    if [[ -e "$backup_created" ]]; then
      backup_created+=".${RANDOM}"
    fi
    if ! cp -f "$target" "$backup_created" 2>/dev/null; then
      warn "Failed to create compose backup at ${backup_created}"
      return 1
    fi
    arr_prune_compose_backups "$backup_prefix"
  fi

  if mv "$tmp" "$target"; then
    return 0
  fi

  warn "Failed to activate ${target}; attempting to restore previous version"

  if [[ -n "$backup_created" && -f "$backup_created" ]]; then
    cp -f "$backup_created" "$target" 2>/dev/null || true
  fi
  return 1
}

detect_compose_cmd() {
  local compose_cmd=""

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1 || docker compose -v >/dev/null 2>&1; then
      compose_cmd="docker compose"
    fi
  fi

  if [[ -z "$compose_cmd" ]] && command -v docker-compose >/dev/null 2>&1; then
    if docker-compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1; then
      compose_cmd="docker-compose"
    fi
  fi

  if [[ -z "$compose_cmd" ]]; then
    warn "Docker Compose not detected; skipping syntax validation."
    return 1
  fi

  printf '%s\n' "$compose_cmd"
}

arr_compose_trim_log() {
  local log_file="$1"
  local max_bytes=$((666 * 1024))

  if [[ -z "$log_file" || ! -f "$log_file" ]]; then
    return 0
  fi

  local size=0
  size="$(wc -c <"$log_file" 2>/dev/null || printf '0')"
  if ((size <= max_bytes)); then
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${log_file}.trim.XXXXXX")"; then
    return 0
  fi

  if ! tail -c "$max_bytes" "$log_file" >"$tmp" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null || true
    return 0
  fi

  local first_line=""
  first_line="$(head -n 1 "$tmp" 2>/dev/null || printf '')"
  if [[ -n "$first_line" && ! "$first_line" =~ ^\[[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}\] ]]; then
    local tmp2=""
    if tmp2="$(arr_mktemp_file "${log_file}.trimline.XXXXXX")"; then
      if tail -n +2 "$tmp" >"$tmp2" 2>/dev/null; then
        mv "$tmp2" "$tmp" 2>/dev/null || rm -f "$tmp2" 2>/dev/null || true
      else
        rm -f "$tmp2" 2>/dev/null || true
      fi
    fi
  fi

  mv "$tmp" "$log_file" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

arr_compose_prepare_log_file() {
  local log_file="$1"

  if [[ -z "$log_file" ]]; then
    return 1
  fi

  : >"$log_file" 2>/dev/null || return 1
  return 0
}

arr_compose_log_message() {
  local log_file="$1"
  shift
  if [[ -z "$log_file" || $# -eq 0 ]]; then
    return 0
  fi

  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$log_file" 2>/dev/null || true
  arr_compose_trim_log "$log_file"
}

arr_compose_log_offending_lines() {
  local log_file="$1"
  local source_file="$2"
  local lint_output="$3"

  if [[ -z "$log_file" || -z "$source_file" || -z "$lint_output" ]]; then
    return 0
  fi

  if [[ ! -f "$source_file" ]]; then
    arr_compose_log_message "$log_file" "Unable to display offending lines; ${source_file} missing"
    return 0
  fi

  local -A seen_lines=()
  local lint_line=""
  while IFS= read -r lint_line; do
    if [[ "$lint_line" =~ :([0-9]+):([0-9]+): ]]; then
      local line_no="${BASH_REMATCH[1]}"
      if [[ -n "${seen_lines["$line_no"]:-}" ]]; then
        continue
      fi

      local offending_line=""
      offending_line="$(sed -n "${line_no}p" "$source_file" 2>/dev/null || printf '')"
      if [[ -n "$offending_line" ]]; then
        arr_compose_log_message "$log_file" "Line ${line_no}: ${offending_line}"
      else
        arr_compose_log_message "$log_file" "Line ${line_no}: <unavailable>"
      fi

      seen_lines["$line_no"]=1
    fi
  done <<<"$lint_output"
}

arr_compose_save_artifact() {
  local staging="$1"
  local log_file="$2"
  local label="$3"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  local log_dir="${log_file%/*}"
  if [[ "$log_dir" == "$log_file" ]]; then
    log_dir="."
  fi

  ensure_dir "$log_dir"

  local timestamp="$(date '+%Y%m%d_%H%M%S')"
  local sha_segment="unknown"
  if [[ -f "$staging" ]]; then
    sha_segment="$(sha256sum "$staging" 2>/dev/null | awk '{print substr($1,1,8)}')"
  fi

  local artifact="${log_dir}/compose-repair-${timestamp}-${sha_segment}"
  if [[ -n "$label" ]]; then
    artifact+="-${label}"
  fi
  artifact+=".yml.bak"

  if cp -f "$staging" "$artifact" 2>/dev/null; then
    arr_compose_log_message "$log_file" "Saved ${label:-snapshot} copy at ${artifact}"
    printf '%s\n' "$artifact"
    return 0
  fi

  return 1
}

arr_compose_run_yq_roundtrip() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  ARR_COMPOSE_YQ_CHANGED=0

  if ! command -v yq >/dev/null 2>&1; then
    arr_compose_log_message "$log_file" "yq not available; skipping canonicalization"
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.yq.XXXXXX")"; then
    arr_compose_log_message "$log_file" "Unable to allocate temporary file for yq canonicalization"
    return 1
  fi

  local sha_before=""
  sha_before="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"

  if yq eval --no-colors --indent 2 '.' "$staging" >"$tmp" 2>>"$log_file"; then
    if cmp -s "$staging" "$tmp" 2>/dev/null; then
      rm -f "$tmp" 2>/dev/null || true
      arr_compose_log_message "$log_file" "yq canonicalization produced no structural changes"
      return 0
    fi

    if mv "$tmp" "$staging" 2>/dev/null; then
      local sha_after=""
      sha_after="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"
      arr_compose_log_message "$log_file" "yq canonicalization updated compose (sha ${sha_before:0:8} → ${sha_after:0:8})"
      ARR_COMPOSE_YQ_CHANGED=1
      return 0
    fi

    rm -f "$tmp" 2>/dev/null || true
    arr_compose_log_message "$log_file" "Failed to promote yq canonicalization result"
    return 1
  fi

  arr_compose_log_message "$log_file" "Primary yq canonicalization failed; attempting fallback yq -i '.'"
  rm -f "$tmp" 2>/dev/null || true

  local yq_output=""
  local yq_status=0
  yq_output="$(yq eval --inplace '.' "$staging" 2>&1)" || yq_status=$?
  if ((yq_status != 0)); then
    arr_compose_log_message "$log_file" "Fallback yq canonicalization failed"
    if [[ -n "$yq_output" ]]; then
      printf '%s\n' "$yq_output" >>"$log_file" 2>/dev/null || true
    fi
    return 1
  fi

  if [[ -n "$yq_output" ]]; then
    printf '%s\n' "$yq_output" >>"$log_file" 2>/dev/null || true
  fi

  local sha_after=""
  sha_after="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"
  arr_compose_log_message "$log_file" "Fallback yq canonicalization updated compose (sha ${sha_before:0:8} → ${sha_after:0:8})"
  ARR_COMPOSE_YQ_CHANGED=1
  return 0
}

arr_compose_validate_with_compose() {
  local staging="$1"
  local log_file="$2"
  local compose_cmd_raw="$3"
  local context="$4"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  if [[ -z "$compose_cmd_raw" ]]; then
    arr_compose_log_message "$log_file" "Compose validation skipped (${context:-autorepair}; compose command unavailable)"
    return 0
  fi

  local -a compose_cmd=()
  read -r -a compose_cmd <<<"$compose_cmd_raw"
  if ((${#compose_cmd[@]} == 0)); then
    arr_compose_log_message "$log_file" "Compose validation skipped (${context:-autorepair}; compose command unavailable)"
    return 0
  fi

  local compose_output=""
  local compose_status=0
  compose_output="$("${compose_cmd[@]}" -f "$staging" config --quiet 2>&1)" || compose_status=$?

  if ((compose_status != 0)); then
    arr_compose_log_message "$log_file" "Compose validation failed during ${context:-autorepair}"
    if [[ -n "$compose_output" ]]; then
      printf '%s\n' "$compose_output" >>"$log_file" 2>/dev/null || true
    fi
    return 1
  fi

  if [[ -n "$compose_output" ]]; then
    printf '%s\n' "$compose_output" >>"$log_file" 2>/dev/null || true
  fi

  arr_compose_log_message "$log_file" "Compose validation succeeded during ${context:-autorepair} via ${compose_cmd[*]} config --quiet"
  return 0
}

arr_compose_replace_line() {
  local target="$1"
  local line_no="$2"
  local new_content="$3"

  if [[ -z "$target" || -z "$line_no" || -z "$new_content" ]]; then
    return 1
  fi

  if [[ ! -f "$target" ]]; then
    return 1
  fi

  if [[ ! "$line_no" =~ ^[0-9]+$ || "$line_no" -le 0 ]]; then
    return 1
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${target}.repline.XXXXXX")"; then
    return 1
  fi

  export REPLACEMENT_CONTENT="$new_content"
  if awk -v target_line="$line_no" '
    BEGIN {status=1}
    {
      if (NR == target_line) {
        print ENVIRON["REPLACEMENT_CONTENT"];
        status=0;
      } else {
        print $0;
      }
    }
    END {exit status}
  ' "$target" >"$tmp" 2>/dev/null; then
    unset REPLACEMENT_CONTENT
    if mv "$tmp" "$target" 2>/dev/null; then
      return 0
    fi
  fi

  rm -f "$tmp" 2>/dev/null || true
  return 1
}

arr_compose_attempt_yaml_fixes() {
  local staging="$1"
  local log_file="$2"
  local lint_output="$3"

  if [[ -z "$staging" || -z "$log_file" || -z "$lint_output" ]]; then
    printf 'changed=0\n'
    printf 'rerun=0\n'
    return 0
  fi

  local -A colon_targets=()
  local -A blank_targets=()

  local lint_line=""
  while IFS= read -r lint_line; do
    if [[ "$lint_line" =~ ^[^:]+:([0-9]+):[0-9]+:[[:space:]]*(.*)$ ]]; then
      local line_no="${BASH_REMATCH[1]}"
      local message="${BASH_REMATCH[2]}"
      if [[ "$message" == *"could not find expected ':'"* ]]; then
        colon_targets["$line_no"]=1
      elif [[ "$message" == *"(empty-lines)"* && "$message" == *"too many blank lines"* ]]; then
        blank_targets["$line_no"]=1
      fi
    fi
  done <<<"$lint_output"

  local needs_rerun=0
  local changed=0
  local -a summary_lines=()

  local -a sorted_colon_lines=()
  mapfile -t sorted_colon_lines < <(printf '%s\n' "${!colon_targets[@]}" | sort -n)

  local line_no=""
  for line_no in "${sorted_colon_lines[@]}"; do
    local offending_line=""
    offending_line="$(sed -n "${line_no}p" "$staging" 2>/dev/null || printf '')"

    if [[ -z "$offending_line" ]]; then
      arr_compose_log_message "$log_file" "Unable to inspect line ${line_no} for missing colon repair"
      continue
    fi

    if [[ "$offending_line" == *":"* ]]; then
      arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: existing ':' makes lint output ambiguous (${offending_line})"
      continue
    fi

    local new_line=""
    if [[ "$offending_line" =~ ^([[:space:]]*-[[:space:]]*)([A-Za-z0-9_.-]+)[[:space:]]+([^[:space:]].*)$ ]]; then
      local prefix="${BASH_REMATCH[1]}"
      local key="${BASH_REMATCH[2]}"
      local value="${BASH_REMATCH[3]}"
      local value_token="${value%%[[:space:]]*}"
      if [[ "$value" == *":"* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value contains ':' (${value})"
        continue
      fi
      if [[ "$value" == *'${'* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value contains placeholder syntax (${value})"
        continue
      fi
      if [[ -n "$value_token" && "${value_token:0:1}" == "#" ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value begins with comment (${value})"
        continue
      fi
      case "$value_token" in
        '|'|'|-'|'|+'|'>'|'>-'|'>+')
          arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value is a block scalar indicator (${value})"
          continue
          ;;
      esac
      new_line="${prefix}${key}: ${value}"
    elif [[ "$offending_line" =~ ^([[:space:]]*)([A-Za-z0-9_.-]+)[[:space:]]+([^[:space:]].*)$ ]]; then
      local indent="${BASH_REMATCH[1]}"
      local key="${BASH_REMATCH[2]}"
      local value="${BASH_REMATCH[3]}"
      local value_token="${value%%[[:space:]]*}"
      if [[ "$value" == *":"* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value contains ':' (${value})"
        continue
      fi
      if [[ "$value" == *'${'* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value contains placeholder syntax (${value})"
        continue
      fi
      if [[ -n "$value_token" && "${value_token:0:1}" == "#" ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value begins with comment (${value})"
        continue
      fi
      case "$value_token" in
        '|'|'|-'|'|+'|'>'|'>-'|'>+')
          arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value is a block scalar indicator (${value})"
          continue
          ;;
      esac
      new_line="${indent}${key}: ${value}"
    else
      arr_compose_log_message "$log_file" "Unable to derive safe colon fix for line ${line_no}: ${offending_line}"
      continue
    fi

    arr_compose_log_message "$log_file" "Attempting colon repair on line ${line_no}:"
    arr_compose_log_message "$log_file" "  before: ${offending_line}"
    arr_compose_log_message "$log_file" "  after:  ${new_line}"

    if arr_compose_replace_line "$staging" "$line_no" "$new_line"; then
      summary_lines+=("corrected missing ':' on line ${line_no}")
      needs_rerun=1
      changed=1
    else
      arr_compose_log_message "$log_file" "Failed to rewrite line ${line_no} for colon repair"
    fi
  done

  if ((${#blank_targets[@]} > 0)); then
    local removed=0
    local -a sorted_blank_lines=()
    mapfile -t sorted_blank_lines < <(printf '%s\n' "${!blank_targets[@]}" | sort -nr)
    for line_no in "${sorted_blank_lines[@]}"; do
      local blank_line=""
      blank_line="$(sed -n "${line_no}p" "$staging" 2>/dev/null || printf '')"
      if [[ -n "${blank_line//[[:space:]]/}" ]]; then
        continue
      fi
      arr_compose_log_message "$log_file" "Removing yamllint empty-line violation at ${line_no}"
      if sed -i "${line_no}d" "$staging" 2>>"$log_file"; then
        ((removed++))
        needs_rerun=1
        changed=1
      else
        arr_compose_log_message "$log_file" "Failed to remove blank line at ${line_no}"
      fi
    done

    if ((removed > 0)); then
      summary_lines+=("removed ${removed} empty-line violation(s)")
    fi
  fi

  printf 'changed=%d\n' "$changed"
  printf 'rerun=%d\n' "$needs_rerun"
  if ((${#summary_lines[@]} > 0)); then
    printf '%s\n' "${summary_lines[@]}"
  fi
}

arr_compose_ensure_document_start() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || ! -f "$staging" ]]; then
    return 1
  fi

  local first_content_line=""
  while IFS= read -r line; do
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    first_content_line="$line"
    break
  done <"$staging"

  if [[ "$first_content_line" =~ ^[[:space:]]*---[[:space:]]*$ ]]; then
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.docstart.XXXXXX")"; then
    return 1
  fi

  local inserted=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if ((inserted == 0)); then
      if [[ -n "${line//[[:space:]]/}" && ! "$line" =~ ^[[:space:]]*# ]]; then
        printf '---\n' >>"$tmp"
        inserted=1
      fi
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$staging"

  if ((inserted == 0)); then
    printf '---\n' >>"$tmp"
  fi

  if mv "$tmp" "$staging" 2>/dev/null; then
    arr_compose_log_message "$log_file" "Inserted YAML document start delimiter"
    printf '%s' "inserted YAML document start delimiter"
    return 0
  fi

  rm -f "$tmp" 2>/dev/null || true
  return 1
}

arr_compose_collapse_blank_runs() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || ! -f "$staging" ]]; then
    return 1
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.noblanks.XXXXXX")"; then
    return 1
  fi

  if awk 'BEGIN {blank=0} {
    if ($0 ~ /^[[:space:]]*$/) {
      blank++;
    } else {
      blank=0;
    }
    if (blank <= 1) {
      print $0;
    }
  } END {exit 0}' "$staging" >"$tmp" 2>/dev/null; then
    if ! cmp -s "$staging" "$tmp" 2>/dev/null; then
      if mv "$tmp" "$staging" 2>/dev/null; then
        arr_compose_log_message "$log_file" "Collapsed consecutive blank lines"
        printf '%s' "collapsed consecutive blank lines"
        return 0
      fi
    else
      rm -f "$tmp" 2>/dev/null || true
      return 0
    fi
  fi

  rm -f "$tmp" 2>/dev/null || true
  return 1
}

arr_compose_autorepair() {
  local staging="$1"
  local log_file="$2"
  local compose_cmd_raw="${3-}"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  arr_compose_log_message "$log_file" "=== compose autorepair start ==="

  local snapshot_path=""
  snapshot_path="$(arr_compose_save_artifact "$staging" "$log_file" "snapshot" 2>/dev/null || printf '')"
  if [[ -z "$snapshot_path" ]]; then
    arr_compose_log_message "$log_file" "Warning: unable to persist initial snapshot; reverting will rely on staging copy"
  fi

  local -a summary=()
  local validation_needed=0
  local yq_summary_added=0

  if LC_ALL=C grep -q $'\r' "$staging" 2>/dev/null; then
    local crlf_samples=""
    crlf_samples="$(LC_ALL=C grep -n $'\r$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$crlf_samples" ]]; then
      arr_compose_log_message "$log_file" "CRLF-terminated lines before fix (first 3):"
      printf '%s\n' "$crlf_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i 's/\r$//' "$staging" 2>>"$log_file"; then
      summary+=("normalized CRLF line endings")
      arr_compose_log_message "$log_file" "Normalized CRLF line endings"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to normalize CRLF line endings"
    fi
  fi

  if LC_ALL=C grep -q $'\t' "$staging" 2>/dev/null; then
    local tab_samples=""
    tab_samples="$(LC_ALL=C grep -n $'\t' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$tab_samples" ]]; then
      arr_compose_log_message "$log_file" "Tab characters before fix (first 3):"
      printf '%s\n' "$tab_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i $'s/\t/  /g' "$staging" 2>>"$log_file"; then
      summary+=("replaced tabs with spaces")
      arr_compose_log_message "$log_file" "Replaced hard tabs with two spaces"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to replace hard tabs"
    fi
  fi

  if LC_ALL=C grep -q '[[:space:]]$' "$staging" 2>/dev/null; then
    local trailing_samples=""
    trailing_samples="$(LC_ALL=C grep -n '[[:space:]]$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$trailing_samples" ]]; then
      arr_compose_log_message "$log_file" "Trailing whitespace before fix (first 3):"
      printf '%s\n' "$trailing_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i 's/[[:space:]]\+$//' "$staging" 2>>"$log_file"; then
      summary+=("stripped trailing whitespace")
      arr_compose_log_message "$log_file" "Stripped trailing whitespace"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to strip trailing whitespace"
    fi
  fi

  local doc_start_summary=""
  if doc_start_summary="$(arr_compose_ensure_document_start "$staging" "$log_file" 2>/dev/null)"; then
    if [[ -n "$doc_start_summary" ]]; then
      summary+=("$doc_start_summary")
      validation_needed=1
    fi
  else
    arr_compose_log_message "$log_file" "Failed to ensure YAML document start"
  fi

  local blank_summary=""
  if blank_summary="$(arr_compose_collapse_blank_runs "$staging" "$log_file" 2>/dev/null)"; then
    if [[ -n "$blank_summary" ]]; then
      summary+=("$blank_summary")
      validation_needed=1
    fi
  else
    arr_compose_log_message "$log_file" "Failed to collapse blank line runs"
  fi

  if LC_ALL=C grep -q '^[[:space:]]*\\[[:space:]]*$' "$staging" 2>/dev/null; then
    local slash_samples=""
    slash_samples="$(LC_ALL=C grep -n '^[[:space:]]*\\[[:space:]]*$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$slash_samples" ]]; then
      arr_compose_log_message "$log_file" "Standalone backslash lines before fix (first 3):"
      printf '%s\n' "$slash_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i '/^[[:space:]]*\\[[:space:]]*$/d' "$staging" 2>>"$log_file"; then
      summary+=("removed stray backslash lines")
      arr_compose_log_message "$log_file" "Removed stray standalone backslash lines"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to remove stray backslash lines"
    fi
  fi

  local last_char=""
  if [[ -s "$staging" ]]; then
    last_char="$(tail -c1 "$staging" 2>/dev/null || printf '')"
  fi
  if [[ -z "$last_char" || "$last_char" != $'\n' ]]; then
    if printf '\n' >>"$staging" 2>>"$log_file"; then
      summary+=("ensured trailing newline")
      arr_compose_log_message "$log_file" "Ensured file ends with newline"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to append trailing newline"
    fi
  fi

  if ((validation_needed)); then
    if ! arr_compose_run_yq_roundtrip "$staging" "$log_file"; then
      arr_compose_save_artifact "$staging" "$log_file" "failed"
      if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
        cp -f "$snapshot_path" "$staging" 2>/dev/null || true
        arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yq failure"
      fi
      printf '%s\n' "auto-repair aborted: yq canonicalization failed"
      return 1
    fi
    if ((ARR_COMPOSE_YQ_CHANGED)) && ((yq_summary_added == 0)); then
      summary+=("normalized YAML with yq")
      yq_summary_added=1
    fi
    if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "formatting"; then
      arr_compose_save_artifact "$staging" "$log_file" "failed"
      if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
        cp -f "$snapshot_path" "$staging" 2>/dev/null || true
        arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after compose validation failure"
      fi
      printf '%s\n' "auto-repair aborted: compose validation failed"
      return 1
    fi
    validation_needed=0
  fi

  if command -v yamllint >/dev/null 2>&1; then
    local lint_output=""
    local lint_status=0
    local -a yamllint_cmd=(
      yamllint
      --config-data
      '{extends: default, rules: {line-length: {max: 140, level: warning}}}'
    )

    lint_output="$("${yamllint_cmd[@]}" "$staging" 2>&1)" || lint_status=$?

    if ((lint_status == 0)); then
      if [[ -n "$lint_output" ]]; then
        arr_compose_log_message "$log_file" $'yamllint reported warnings:'
        printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
        arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
      else
        arr_compose_log_message "$log_file" "yamllint completed without issues"
      fi
    else
      arr_compose_log_message "$log_file" $'yamllint reported issues:'
      printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
      arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
    fi

    if ((lint_status != 0)); then
      local fix_output=""
      local fix_changed=0
      local lint_needs_rerun=0
      fix_output="$(arr_compose_attempt_yaml_fixes "$staging" "$log_file" "$lint_output" 2>/dev/null)"
      local fix_line=""
      while IFS= read -r fix_line; do
        if [[ "$fix_line" =~ ^changed=([01])$ ]]; then
          fix_changed="${BASH_REMATCH[1]}"
        elif [[ "$fix_line" =~ ^rerun=([01])$ ]]; then
          lint_needs_rerun="${BASH_REMATCH[1]}"
        elif [[ -n "$fix_line" ]]; then
          summary+=("$fix_line")
        fi
      done <<<"$fix_output"

      if ((fix_changed)); then
        if ! arr_compose_run_yq_roundtrip "$staging" "$log_file"; then
          arr_compose_save_artifact "$staging" "$log_file" "failed"
          if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
            cp -f "$snapshot_path" "$staging" 2>/dev/null || true
            arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yq failure"
          fi
          printf '%s\n' "auto-repair aborted: yq canonicalization failed"
          return 1
        fi
        if ((ARR_COMPOSE_YQ_CHANGED)) && ((yq_summary_added == 0)); then
          summary+=("normalized YAML with yq")
          yq_summary_added=1
        fi
        if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "yamllint repair"; then
          arr_compose_save_artifact "$staging" "$log_file" "failed"
          if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
            cp -f "$snapshot_path" "$staging" 2>/dev/null || true
            arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after compose validation failure"
          fi
          printf '%s\n' "auto-repair aborted: compose validation failed"
          return 1
        fi
      fi

      if ((lint_needs_rerun)); then
        arr_compose_log_message "$log_file" "Re-running yamllint after autorepair fixes"
        lint_status=0
        lint_output="$("${yamllint_cmd[@]}" "$staging" 2>&1)" || lint_status=$?

        if ((lint_status == 0)); then
          if [[ -n "$lint_output" ]]; then
            arr_compose_log_message "$log_file" $'yamllint reported warnings after autorepair:'
            printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
            arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
          else
            arr_compose_log_message "$log_file" "yamllint completed without issues after autorepair"
          fi
        else
          arr_compose_log_message "$log_file" $'yamllint reported issues after autorepair:'
          printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
          arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
        fi
      fi

      if ((lint_status != 0)); then
        arr_compose_save_artifact "$staging" "$log_file" "failed"
        if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
          cp -f "$snapshot_path" "$staging" 2>/dev/null || true
          arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yamllint failure"
        fi
        printf '%s\n' "auto-repair aborted: yamllint errors remain"
        return 1
      fi
    fi
  else
    arr_compose_log_message "$log_file" "yamllint not available; skipping linting"
  fi

  arr_compose_log_message "$log_file" "Auto-repair completed successfully"
  printf '%s\n' "${summary[@]}"
  return 0
}

arr_compose_autorepair_and_validate() {
  local staging="$1"
  local target="$2"

  if [[ -z "$staging" || ! -f "$staging" || -z "$target" ]]; then
    warn "compose autorepair requires staging and target paths"
    return 1
  fi

  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir_mode "$log_dir" "$DATA_DIR_MODE"

  local log_file="${log_dir}/compose-repair.log"

  if ! arr_compose_prepare_log_file "$log_file"; then
    warn "Unable to prepare compose repair log at ${log_file}"
  fi

  local compose_cmd_raw=""
  local compose_detect_status=0
  compose_cmd_raw="$(detect_compose_cmd)" || compose_detect_status=$?
  if ((compose_detect_status != 0)); then
    compose_cmd_raw=""
  fi

  local summary_output=""
  local autorepair_status=0
  summary_output="$(arr_compose_autorepair "$staging" "$log_file" "$compose_cmd_raw" 2>/dev/null)" || autorepair_status=$?
  local -a summary_lines=()
  if [[ -n "$summary_output" ]]; then
    mapfile -t summary_lines <<<"$summary_output"
  fi

  if ((autorepair_status != 0)); then
    warn "Compose auto-repair failed; see ${log_file}"
    return 1
  fi

  local -a compose_cmd=()
  if [[ -z "$compose_cmd_raw" ]]; then
    arr_compose_log_message "$log_file" "Docker Compose unavailable; validation skipped"
    summary_lines+=("validation skipped (compose command unavailable)")
  else
    read -r -a compose_cmd <<<"$compose_cmd_raw"
    if ((${#compose_cmd[@]} > 0)); then
      if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "final validation"; then
        warn "Docker Compose validation failed; see ${log_file}"
        return 1
      fi
      summary_lines+=("validated with ${compose_cmd[*]} config --quiet")
    fi
  fi

  if ! arr_safe_compose_write "$target" "$staging"; then
    arr_compose_log_message "$log_file" "Failed to install compose file at ${target}"
    warn "Failed to install ${target}"
    return 1
  fi

  ensure_nonsecret_file_mode "$target"
  arr_compose_log_message "$log_file" "Installed compose file at ${target}"

  local summary_message=""
  local applied_count="${#summary_lines[@]}"
  if ((applied_count > 0)); then
    summary_message="$(printf '%s, ' "${summary_lines[@]}")"
    summary_message="${summary_message%, }"
  fi

  if ((applied_count > 0)); then
    arr_compose_log_message "$log_file" "Summary: ${summary_message}"
    msg "compose auto-repair: applied ${applied_count} change(s); see ${log_file}"
  else
    msg "compose auto-repair: no changes required; see ${log_file}"
  fi

  return 0
}

arr_validate_compose_prerequisites() {
  local -a errors=()

  if [[ -z "${PUID:-}" ]]; then
    errors+=("PUID not set")
  fi
  if [[ -z "${PGID:-}" ]]; then
    errors+=("PGID not set")
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" || "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      errors+=("LAN_IP required for split/direct mode")
    fi
  fi

  if ((${#errors[@]} == 0)); then
    return 0
  fi

  warn "Compose prerequisites failed:"
  local err
  for err in "${errors[@]}"; do
    warn "  - ${err}"
  done
  return 1
}
# Prepares derived networking, VPN, and credential values for .env generation
prepare_env_context() {
  step "📝 Preparing environment values"

  hydrate_caddy_auth_from_env_file
  hydrate_user_credentials_from_env_file
  hydrate_sab_api_key_from_config
  hydrate_qbt_host_port_from_env_file
  hydrate_qbt_webui_port_from_config

  CADDY_BASIC_AUTH_USER="$(sanitize_user "$CADDY_BASIC_AUTH_USER")"

  local direct_ports_raw="${EXPOSE_DIRECT_PORTS:-0}"
  EXPOSE_DIRECT_PORTS="$(arr_normalize_bool "$direct_ports_raw")"
  local split_vpn_raw="${SPLIT_VPN:-0}"
  local split_vpn="$(arr_normalize_bool "$split_vpn_raw")"
  case "$split_vpn_raw" in
    ''|0|1|true|TRUE|false|FALSE|yes|YES|no|NO|on|ON|off|OFF) ;;
    *)
      warn "Invalid SPLIT_VPN=${split_vpn_raw}; defaulting to 0 (full tunnel)."
      split_vpn=0
      ;;
  esac
  SPLIT_VPN="$split_vpn"

  ENABLE_CADDY="$(arr_normalize_bool "${ENABLE_CADDY:-0}")"
  ENABLE_LOCAL_DNS="$(arr_normalize_bool "${ENABLE_LOCAL_DNS:-0}")"

  local direct_ports_requested="${EXPOSE_DIRECT_PORTS}"
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  if ((split_vpn == 1)); then
    if [[ "${ENABLE_CADDY:-0}" -ne 0 ]]; then
      warn "SPLIT_VPN=1: disabling Caddy (unsupported in split mode)"
    fi
    ENABLE_CADDY=0
    if [[ "${ENABLE_LOCAL_DNS:-0}" -ne 0 ]]; then
      warn "SPLIT_VPN=1: disabling Local DNS (unsupported in split mode)"
    fi
    ENABLE_LOCAL_DNS=0
  fi

  local user_supplied_lan_ip="${LAN_IP:-}"
  if [[ -n "$user_supplied_lan_ip" ]]; then
    if ! validate_ipv4 "$user_supplied_lan_ip"; then
      die "Invalid LAN_IP provided (${user_supplied_lan_ip}). Fix ${userconf_path} or unset to auto-detect."
    fi
    LAN_IP="$user_supplied_lan_ip"
    msg "Using configured LAN_IP: $LAN_IP"
  else
    if detected_ip="$(detect_lan_ip 2>/dev/null)"; then
      LAN_IP="$detected_ip"
      msg "Auto-detected LAN_IP: $LAN_IP"
    else
      LAN_IP="0.0.0.0"
      warn "LAN_IP could not be detected automatically; set it in ${userconf_path} so services bind to the correct interface."
      warn "Determine the address with: hostname -I | awk \"{print \\\$1}\""
    fi
  fi

  local -a lan_requirements=()
  if ((direct_ports_requested == 1)); then
    lan_requirements+=("EXPOSE_DIRECT_PORTS=1")
  fi
  if ((split_vpn == 1)); then
    lan_requirements+=("SPLIT_VPN=1")
  fi
  if ((${#lan_requirements[@]} > 0)); then
    local requirement_msg="${lan_requirements[0]}"
    if ((${#lan_requirements[@]} == 2)); then
      requirement_msg="${lan_requirements[0]} and ${lan_requirements[1]}"
    fi
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      die "${requirement_msg} requires LAN_IP to be set to your host's private IPv4 address in ${userconf_path}."
    fi
    if ! is_private_ipv4 "$LAN_IP"; then
      die "LAN_IP='${LAN_IP}' must be a private IPv4 address when ${requirement_msg} is enabled. Update ${userconf_path}."
    fi
  fi

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    arr_prompt_direct_port_exposure "$LAN_IP"
  fi

  local caddy_http_port_value
  arr_resolve_port caddy_http_port_value "${CADDY_HTTP_PORT:-}" 80 \
    "Invalid CADDY_HTTP_PORT=${CADDY_HTTP_PORT:-}; defaulting to 80."
  CADDY_HTTP_PORT="$caddy_http_port_value"

  local caddy_https_port_value
  arr_resolve_port caddy_https_port_value "${CADDY_HTTPS_PORT:-}" 443 \
    "Invalid CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT:-}; defaulting to 443."
  CADDY_HTTPS_PORT="$caddy_https_port_value"

  local sab_enabled_raw="${SABNZBD_ENABLED:-0}"
  local sab_enabled
  sab_enabled="$(arr_normalize_bool "$sab_enabled_raw")"
  SABNZBD_ENABLED="$sab_enabled"

  local sab_use_vpn_raw="${SABNZBD_USE_VPN:-0}"
  local sab_use_vpn
  sab_use_vpn="$(arr_normalize_bool "$sab_use_vpn_raw")"
  case "$sab_use_vpn_raw" in
    ''|0|1|true|TRUE|false|FALSE|yes|YES|no|NO|on|ON|off|OFF) ;;
    *)
      warn "Invalid SABNZBD_USE_VPN=${sab_use_vpn_raw}; defaulting to 0 (direct mode)."
      sab_use_vpn=0
    ;;
  esac

  local gluetun_available=0
  if declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1; then
    local svc=""
    for svc in "${ARR_DOCKER_SERVICES[@]:-}"; do
      if [[ "$svc" == "gluetun" ]]; then
        gluetun_available=1
        break
      fi
    done
  fi

  if ((gluetun_available)); then
    if [[ "${ENABLE_GLUETUN:-1}" == "0" ]]; then
      gluetun_available=0
    fi
  fi

  if ((gluetun_available)); then
    case "${VPN_SERVICE_PROVIDER:-protonvpn}" in
      '' | none | disabled | off)
        gluetun_available=0
        ;;
    esac
  fi

  if ((sab_enabled)) && ((sab_use_vpn == 1)) && ((gluetun_available == 0)); then
    warn "SABNZBD_USE_VPN=1 ignored (Gluetun disabled)"
    sab_use_vpn=0
  fi

  SABNZBD_USE_VPN="$sab_use_vpn"

  local sab_timeout_raw
  arr_resolve_positive_int sab_timeout_raw "${SABNZBD_TIMEOUT:-}" 15 \
    "Invalid SABNZBD_TIMEOUT=${SABNZBD_TIMEOUT:-}; defaulting to 15 seconds."
  SABNZBD_TIMEOUT="$sab_timeout_raw"

  local sab_internal_port_raw
  arr_resolve_port sab_internal_port_raw "${SABNZBD_INT_PORT:-}" 8080 \
    "Invalid SABNZBD_INT_PORT=${SABNZBD_INT_PORT:-}; defaulting to 8080."
  SABNZBD_INT_PORT="$sab_internal_port_raw"

  local sab_port_raw
  arr_resolve_port sab_port_raw "${SABNZBD_PORT:-}" "$SABNZBD_INT_PORT" \
    "Invalid SABNZBD_PORT=${SABNZBD_PORT:-}; defaulting to ${SABNZBD_INT_PORT}."
  SABNZBD_PORT="$sab_port_raw"

  local sab_host_default="${LOCALHOST_IP:-localhost}"
  local sab_host_value="${SABNZBD_HOST:-}"
  if [[ -z "$sab_host_value" ]]; then
    sab_host_value="$sab_host_default"
  fi

  local sab_host_auto=0
  if ((sab_enabled)) && ((sab_use_vpn == 1)); then
    local sab_host_lower="${sab_host_value,,}"
    local sab_default_lower="${sab_host_default,,}"
    case "$sab_host_lower" in
      "$sab_default_lower" | 127.0.0.1 | localhost | "$LOCALHOST_IP")
        sab_host_value="sabnzbd"
        sab_host_auto=1
        ;;
    esac

    if ((sab_host_auto == 0)); then
      case "$sab_host_lower" in
        sabnzbd | gluetun) ;;
        *)
          warn "SABnzbd is routed through the VPN; ensure SABNZBD_HOST='${sab_host_value}' is reachable (sabnzbd is recommended)."
          ;;
      esac
    fi
  fi

  SABNZBD_HOST="$sab_host_value"
  export ARR_SAB_HOST_AUTO="$sab_host_auto"

  local qbt_webui_default="${QBT_INT_PORT:-8082}"
  local qbt_host_default="$qbt_webui_default"
  local qbt_webui_port="$qbt_webui_default"
  local qbt_host_port="$qbt_host_default"
  local qbt_webui_status="default"
  local qbt_host_status="default"

  if [[ -n "${ARR_QBT_INT_PORT_CONFIG:-}" ]]; then
    qbt_webui_port="${ARR_QBT_INT_PORT_CONFIG}"
    qbt_webui_status="preserved"
  fi

  if [[ -n "${ARR_QBT_HOST_PORT_ENV:-}" ]]; then
    qbt_host_port="${ARR_QBT_HOST_PORT_ENV}"
    qbt_host_status="preserved"
  elif [[ -n "${QBT_PORT:-}" ]]; then
    qbt_host_port="${QBT_PORT}"
  fi

  local qbt_host_port_raw="$qbt_host_port"
  arr_resolve_port qbt_host_port "$qbt_host_port_raw" "$qbt_host_default" \
    "Invalid QBT_PORT=${qbt_host_port_raw}; defaulting to ${qbt_host_default}."
  if [[ "$qbt_host_port" == "$qbt_host_default" && "$qbt_host_port_raw" != "$qbt_host_default" ]]; then
    qbt_host_status="default"
  fi

  if [[ "$qbt_webui_status" == "preserved" && "$qbt_webui_port" != "$qbt_webui_default" ]]; then
    arr_record_preserve_note "Preserved qBittorrent WebUI port ${qbt_webui_port}"
  fi
  if [[ "$qbt_host_status" == "preserved" && "$qbt_host_port" != "$qbt_host_default" ]]; then
    arr_record_preserve_note "Preserved qBittorrent host port ${qbt_host_port}"
  fi

  local qbt_webui_port_raw="$qbt_webui_port"
  arr_resolve_port qbt_webui_port "$qbt_webui_port_raw" "$qbt_webui_default" \
    "Invalid qBittorrent WebUI port ${qbt_webui_port_raw}; using ${qbt_webui_default}."
  if [[ "$qbt_webui_port" == "$qbt_webui_default" && "$qbt_webui_port_raw" != "$qbt_webui_default" ]]; then
    qbt_webui_status="default"
  fi

  QBT_INT_PORT="$qbt_webui_port"
  QBT_PORT="$qbt_host_port"
  export ARR_QBT_INT_PORT_STATUS="$qbt_webui_status"
  export ARR_QBT_HOST_PORT_STATUS="$qbt_host_status"

  local qbt_bind_addr_value="${QBT_BIND_ADDR:-0.0.0.0}"
  if [[ -z "$qbt_bind_addr_value" ]]; then
    qbt_bind_addr_value="0.0.0.0"
  fi
  QBT_BIND_ADDR="$qbt_bind_addr_value"

  local qbt_enforce_value="${QBT_ENFORCE_WEBUI:-1}"
  case "$qbt_enforce_value" in
    0 | 1) ;;
    *)
      qbt_enforce_value=1
      ;;
  esac
  QBT_ENFORCE_WEBUI="$qbt_enforce_value"

  local sab_api_state="empty"
  local sab_api_value="${SABNZBD_API_KEY:-}"
  if [[ -n "$sab_api_value" ]]; then
    local sab_api_upper="${sab_api_value^^}"
    if [[ "$sab_api_upper" == REPLACE_WITH_* ]]; then
      sab_api_state="placeholder"
    else
      sab_api_state="set"
    fi
  fi
  ARR_SAB_API_KEY_STATE="$sab_api_state"
  export ARR_SAB_API_KEY_STATE
  case "$sab_api_state" in
    set)
      if [[ -z "${ARR_SAB_API_KEY_SOURCE:-}" ]]; then
        ARR_SAB_API_KEY_SOURCE="provided"
      fi
      ;;
    placeholder)
      ARR_SAB_API_KEY_SOURCE="placeholder"
      ;;
    empty)
      ARR_SAB_API_KEY_SOURCE="empty"
      ;;
  esac

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"

  validate_config "$PU" "$PW"

  if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
    local existing_project_name=""
    if existing_project_name="$(get_env_kv "COMPOSE_PROJECT_NAME" "$ARR_ENV_FILE" 2>/dev/null)"; then
      COMPOSE_PROJECT_NAME="$existing_project_name"
    else
      COMPOSE_PROJECT_NAME="${STACK}"
    fi
  fi
  if [[ ! ${VPN_SERVICE_PROVIDER+x} ]]; then
    VPN_SERVICE_PROVIDER="protonvpn"
  fi

  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_openvpn_user >/dev/null 2>&1; then
    OPENVPN_USER="$(arr_derive_openvpn_user)"
  else
    OPENVPN_USER=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_openvpn_password >/dev/null 2>&1; then
    OPENVPN_PASSWORD="$(arr_derive_openvpn_password)"
  else
    OPENVPN_PASSWORD=""
  fi

  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_dns_host_entry >/dev/null 2>&1; then
    DNS_HOST_ENTRY="$(arr_derive_dns_host_entry)"
  else
    DNS_HOST_ENTRY=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_gluetun_firewall_outbound_subnets >/dev/null 2>&1; then
    GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(arr_derive_gluetun_firewall_outbound_subnets)"
  else
    GLUETUN_FIREWALL_OUTBOUND_SUBNETS=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_gluetun_firewall_input_ports >/dev/null 2>&1; then
    GLUETUN_FIREWALL_INPUT_PORTS="$(arr_derive_gluetun_firewall_input_ports)"
  else
    GLUETUN_FIREWALL_INPUT_PORTS=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_compose_profiles_csv >/dev/null 2>&1; then
    COMPOSE_PROFILES="$(arr_derive_compose_profiles_csv)"
  else
    COMPOSE_PROFILES=""
  fi

  local -a upstream_dns_servers=()
  if declare -f collect_upstream_dns_servers >/dev/null 2>&1; then
    mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers 2>/dev/null || true)
  fi
  arr_assign_upstream_dns_env "${upstream_dns_servers[@]}"

  local qbt_whitelist_raw
  qbt_whitelist_raw="${QBT_AUTH_WHITELIST:-}"
  if [[ -z "$qbt_whitelist_raw" ]]; then
    qbt_whitelist_raw="${LOCALHOST_IP}/32,::1/128"
  fi
  local lan_private_subnet=""
  if lan_private_subnet="$(lan_ipv4_subnet_cidr "$LAN_IP" 2>/dev/null)"; then
    :
  else
    lan_private_subnet=""
  fi
  if [[ -n "$lan_private_subnet" ]]; then
    qbt_whitelist_raw+="${qbt_whitelist_raw:+,}${lan_private_subnet}"
  fi
  QBT_AUTH_WHITELIST="$(normalize_csv "$qbt_whitelist_raw")"

  if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
    while IFS= read -r _env_key; do
      [[ -z "$_env_key" ]] && continue
      if [[ ! ${!_env_key+x} ]]; then
        printf -v "$_env_key" '%s' ""
      fi
      # shellcheck disable=SC2163
      export "$_env_key"
    done < <(arr_collect_all_expected_env_keys)
  fi

  ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
}

# Appends the shared SABnzbd service definition to the provided compose fragment.
# The caller handles network configuration and passes 1 as the second argument
# when direct-mode ports should be exposed on the LAN.
append_sabnzbd_service_body() {
  local target="$1"
  local include_direct_port="${2:-0}"
  local sab_internal_fallback="${SABNZBD_INT_PORT:-8080}"
  local internal_port="${3:-${sab_internal_fallback}}"

  local sab_timeout_for_health
  arr_resolve_positive_int sab_timeout_for_health "${SABNZBD_TIMEOUT:-}" 60
  local health_start_period_seconds=60
  if ((sab_timeout_for_health > health_start_period_seconds)); then
    health_start_period_seconds="$sab_timeout_for_health"
  fi

  cat <<'YAML' >>"$target"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/sab/config:/config"
      - "${ARR_DOCKER_DIR}/sab/incomplete:/incomplete"
      - "${ARR_DOCKER_DIR}/sab/downloads:/downloads"
YAML

  if [[ "$include_direct_port" == "1" ]]; then
    cat <<'YAML' >>"$target"
    ports:
YAML
    arr_yaml_list_item "      " "${LAN_IP}:${SABNZBD_PORT}:${internal_port}" >>"$target"
  fi

  printf '%s\n' "    healthcheck:" >>"$target"
  local _health_url
  _health_url="$(arr_yaml_escape "http://${LOCALHOST_IP}:${internal_port}/api?mode=version&output=json")"
  printf '%s\n' "      test: [\"CMD\", \"curl\", \"-fsS\", ${_health_url}]" >>"$target"
  arr_yaml_kv "      " "interval" "30s" >>"$target"
  arr_yaml_kv "      " "timeout" "5s" >>"$target"
  arr_yaml_kv "      " "retries" "5" >>"$target"
  arr_yaml_kv "      " "start_period" "${health_start_period_seconds}s" >>"$target"

  cat <<'YAML' >>"$target"
    restart: "unless-stopped"
    # NOTE: Future hardening opportunity — consider CPU/memory limits and a read_only filesystem once defaults are vetted.
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML
}

# Generates docker-compose.yml tuned for split VPN (qBittorrent-only tunnel)
write_compose_split_mode() {
  step "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local tmp
  local sab_internal_port
  arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080

  if ! arr_validate_compose_prerequisites; then
    die "Compose prerequisites not satisfied"
  fi

  LOCAL_DNS_STATE="split-disabled"
  LOCAL_DNS_STATE_REASON="Local DNS disabled in split mode (SPLIT_VPN=1)"

  tmp="$(arr_mktemp_file "${compose_path}.XXXXXX.tmp" "$NONSECRET_FILE_MODE")" || die "Failed to create temp file for ${compose_path}"
  ensure_nonsecret_file_mode "$tmp"

  cat <<'YAML' >>"$tmp"
# -----------------------------------------------------------------------------
# docker-compose.yml is auto-generated by the stack script. Do not edit manually.
# Split VPN mode is active: only qBittorrent shares gluetun's network namespace
# while the *Arr applications run on arr_net (standard bridge) outside the VPN.
# -----------------------------------------------------------------------------
# Caddy reverse proxy disabled automatically (SPLIT_VPN=1).
services:
  gluetun:
    image: "${GLUETUN_IMAGE}"
    container_name: "gluetun"
    profiles:
      - "ipdirect"
YAML

  cat <<'YAML' >>"$tmp"
    cap_add:
      - "NET_ADMIN"
    devices:
      - "/dev/net/tun"
    environment:
      VPN_SERVICE_PROVIDER: "${VPN_SERVICE_PROVIDER}"
      VPN_TYPE: "openvpn"
      OPENVPN_USER: "${OPENVPN_USER}"
      OPENVPN_PASSWORD: "${OPENVPN_PASSWORD}"
      FREE_ONLY: "off"
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: "protonvpn"
      HTTP_CONTROL_SERVER_ADDRESS: "0.0.0.0:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: "${GLUETUN_API_KEY}"
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: "${QBT_USER}"
      QBT_PASS: "${QBT_PASS}"
      QBITTORRENT_ADDR: "http://${LOCALHOST_IP}:${QBT_INT_PORT}"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_INPUT_PORTS: "${GLUETUN_FIREWALL_INPUT_PORTS}"
      UPDATER_PERIOD: "24h"
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/gluetun:/gluetun"
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:${QBT_PORT}:${QBT_INT_PORT}"
YAML

  cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          set -eu;
          /gluetun-entrypoint healthcheck >/dev/null;
          if ! ({ ip -4 route show default; ip -6 route show default; } 2>/dev/null | LC_ALL=C grep -Eq 'dev (tun[0-9]+|wg[0-9]+)' || \
            ip -o link show 2>/dev/null | LC_ALL=C grep -Eq '[[:space:]](tun[0-9]+|wg[0-9]+):'); then
            exit 1;
          fi;
          if command -v curl >/dev/null 2>&1; then
            curl -fsS --connect-timeout 5 --max-time 8 https://api.ipify.org >/dev/null || exit 1;
          elif command -v wget >/dev/null 2>&1; then
            wget -q -T 8 -O- https://api.ipify.org >/dev/null || exit 1;
          else
            exit 1;
          fi
      interval: "30s"
      timeout: "30s"
      retries: "10"
      start_period: "120s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "3"

YAML

  cat <<'YAML' >>"$tmp"
  qbittorrent:
    image: "${QBITTORRENT_IMAGE}"
    container_name: "qbittorrent"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
      QBT_INT_PORT: "${QBT_INT_PORT}"
      QBT_BIND_ADDR: "${QBT_BIND_ADDR}"
      QBT_ENFORCE_WEBUI: "${QBT_ENFORCE_WEBUI}"
      QBT_WEBUI_INIT_HOOK: 1
YAML

  if [[ -n "${QBT_DOCKER_MODS}" ]]; then
    #  write the literal ${QBT_DOCKER_MODS} token instead of expanding it at generation time
    # shellcheck disable=SC2016  # intentional literal for compose placeholder
    arr_yaml_kv "      " "DOCKER_MODS" '${QBT_DOCKER_MODS}' >>"$tmp"
  fi

  cat <<'YAML' >>"$tmp"
    volumes:
      - "${ARR_DOCKER_DIR}/qbittorrent:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${ARR_STACK_DIR}/scripts/qbt-helper.sh:/custom-cont-init.d/00-qbt-webui:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD", "/custom-cont-init.d/00-qbt-webui", "healthcheck"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: "${SONARR_IMAGE}"
    container_name: "sonarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/sonarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${TV_DIR}:/tv"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: "${RADARR_IMAGE}"
    container_name: "radarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/radarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${MOVIES_DIR}:/movies"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: "${PROWLARR_IMAGE}"
    container_name: "prowlarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/prowlarr:/config"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: "${BAZARR_IMAGE}"
    container_name: "bazarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/bazarr:/config"
      - "${TV_DIR}:/tv"
      - "${MOVIES_DIR}:/movies"
YAML

  if [[ -n "${SUBS_DIR:-}" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${SUBS_DIR}:/subs"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: "${FLARR_IMAGE}"
    container_name: "flaresolverr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${FLARR_PORT}:${FLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      LOG_LEVEL: "info"
    healthcheck:
      test: ["CMD-SHELL", "if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 10 http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health; elif command -v wget >/dev/null 2>&1; then wget -q --timeout=10 -O- http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health; else exit 1; fi"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
      start_period: "40s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML

  if [[ "${SABNZBD_ENABLED}" == "1" ]]; then
    local sab_internal_port
    arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080
    cat <<'YAML' >>"$tmp"
  sabnzbd:
    image: "${SABNZBD_IMAGE}"
    container_name: "sabnzbd"
    profiles:
      - "ipdirect"
YAML
    if [[ "${SABNZBD_USE_VPN}" == "1" ]]; then
      cat <<'YAML' >>"$tmp"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
      append_sabnzbd_service_body "$tmp" "0" "$sab_internal_port"
    else
      cat <<'YAML' >>"$tmp"
    networks:
      - "arr_net"
YAML
      local expose_direct_port="0"
      if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
        expose_direct_port="1"
      fi
      append_sabnzbd_service_body "$tmp" "$expose_direct_port" "$sab_internal_port"
    fi
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
  configarr:
    image: "${CONFIGARR_IMAGE}"
    container_name: "configarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
    depends_on:
      sonarr:
        condition: "service_started"
      radarr:
        condition: "service_started"
    volumes:
      - "${ARR_DOCKER_DIR}/configarr/config.yml:/app/config.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/secrets.yml:/app/secrets.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/cfs:/app/cfs:ro"
    working_dir: "/app"
    entrypoint: ["/bin/sh","-lc","node dist/index.js || exit 1"]
    environment:
      TZ: "${TIMEZONE}"
    restart: "no"
    logging:
      driver: "json-file"
      options:
        max-size: "512k"
        max-file: "2"
YAML
  fi

  cat <<'YAML' >>"$tmp"

networks:
  arr_net:
    name: "${COMPOSE_PROJECT_NAME}_arr_net"
    driver: "bridge"
YAML

  printf '\n' >>"$tmp"

  if ! verify_single_level_env_placeholders "$tmp"; then
    rm -f "$tmp"
    die "Generated docker-compose.yml contains nested environment placeholders"
  fi

  if ! arr_verify_compose_placeholders "$tmp" "${ARR_ENV_FILE:-}"; then
    rm -f "$tmp"
    die "Generated docker-compose.yml contains unexpected environment placeholders"
  fi

  if ! arr_compose_autorepair_and_validate "$tmp" "$compose_path"; then
    rm -f "$tmp"
    die "Compose validation failed (see logs/compose-repair.log)"
  fi

  msg "  Local DNS status: ${LOCAL_DNS_STATE_REASON} (LOCAL_DNS_STATE=${LOCAL_DNS_STATE})"
}

# Generates docker-compose.yml for default mode, gating optional services on runtime checks
write_compose() {
  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    write_compose_split_mode
    return
  fi

  step "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local tmp

  if ! arr_validate_compose_prerequisites; then
    die "Compose prerequisites not satisfied"
  fi

  LOCAL_DNS_STATE="inactive"
  LOCAL_DNS_STATE_REASON="Local DNS container disabled (ENABLE_LOCAL_DNS=0)"
  local include_caddy=0
  local include_local_dns=0
  local -a upstream_dns_servers=()
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers)

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    include_caddy=1
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    include_local_dns=1
    LOCAL_DNS_STATE="requested"
    LOCAL_DNS_STATE_REASON="Local DNS container requested"
  fi

  if ((include_local_dns)); then
    if port_bound_any udp 53 || port_bound_any tcp 53; then
      include_local_dns=0
      LOCAL_DNS_STATE="blocked"
      LOCAL_DNS_STATE_REASON="Local DNS disabled automatically (port 53 already in use)"
      warn "Port 53 is already in use (likely systemd-resolved). Local DNS will be disabled (LOCAL_DNS_STATE=blocked)."
    fi
  fi

  if ((include_local_dns)); then
    LOCAL_DNS_STATE="active"
    LOCAL_DNS_STATE_REASON="Local DNS container enabled"
    if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
      warn "Local DNS will bind to all interfaces (0.0.0.0:53)"
    fi
  fi

  tmp="$(arr_mktemp_file "${compose_path}.XXXXXX.tmp" "$NONSECRET_FILE_MODE")" || die "Failed to create temp file for ${compose_path}"
  ensure_nonsecret_file_mode "$tmp"

  cat <<'YAML' >>"$tmp"
# -----------------------------------------------------------------------------
# docker-compose.yml is auto-generated by the stack script. Do not edit manually.
# All application containers join gluetun's network namespace so every request
# exits via the VPN (network_mode: "service:gluetun"). container_name values
# are fixed to give helper scripts predictable targets; scaling is out of scope.
# -----------------------------------------------------------------------------
YAML

  if ((include_caddy == 0)); then
    arr_yaml_comment "" "Caddy reverse proxy disabled (ENABLE_CADDY=0)." >>"$tmp"
    arr_yaml_comment "" "Set ENABLE_CADDY=1 in ${userconf_path} and rerun ./${STACK}.sh to add HTTPS hostnames via Caddy." >>"$tmp"
  fi

  cat <<'YAML' >>"$tmp"
services:
  gluetun:
    image: "${GLUETUN_IMAGE}"
    container_name: "gluetun"
    profiles:
      - "ipdirect"
    cap_add:
      - "NET_ADMIN"
    devices:
      - "/dev/net/tun"
    environment:
      VPN_SERVICE_PROVIDER: "${VPN_SERVICE_PROVIDER}"
      VPN_TYPE: "openvpn"
      OPENVPN_USER: "${OPENVPN_USER}"
      OPENVPN_PASSWORD: "${OPENVPN_PASSWORD}"
      FREE_ONLY: "off"
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: "protonvpn"
      HTTP_CONTROL_SERVER_ADDRESS: "0.0.0.0:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: "${GLUETUN_API_KEY}"
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: "${QBT_USER}"
      QBT_PASS: "${QBT_PASS}"
      QBITTORRENT_ADDR: "http://${LOCALHOST_IP}:${QBT_INT_PORT}"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_INPUT_PORTS: "${GLUETUN_FIREWALL_INPUT_PORTS}"
      UPDATER_PERIOD: "24h"
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/gluetun:/gluetun"
    ports:
      # Centralize host exposure since all services share gluetun's namespace
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${QBT_PORT}:${QBT_INT_PORT}"
YAML
  fi

  if ((include_caddy)); then
    cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${CADDY_HTTP_PORT}:${CADDY_HTTP_PORT}"
      - "${LAN_IP}:${CADDY_HTTPS_PORT}:${CADDY_HTTPS_PORT}"
YAML
  fi

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_INT_PORT}"
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_INT_PORT}"
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_INT_PORT}"
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_INT_PORT}"
      - "${LAN_IP}:${FLARR_PORT}:${FLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          set -eu;
          /gluetun-entrypoint healthcheck >/dev/null;
          if ! ({ ip -4 route show default; ip -6 route show default; } 2>/dev/null | LC_ALL=C grep -Eq 'dev (tun[0-9]+|wg[0-9]+)' || \
            ip -o link show 2>/dev/null | LC_ALL=C grep -Eq '[[:space:]](tun[0-9]+|wg[0-9]+):'); then
            exit 1;
          fi;
          if command -v curl >/dev/null 2>&1; then
            curl -fsS --connect-timeout 5 --max-time 8 https://api.ipify.org >/dev/null || exit 1;
          elif command -v wget >/dev/null 2>&1; then
            wget -q -T 8 -O- https://api.ipify.org >/dev/null || exit 1;
          else
            exit 1;
          fi
      interval: "30s"
      timeout: "30s"
      retries: "10"
      start_period: "120s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "3"
YAML

  if ((include_local_dns)); then
    cat <<'YAML' >>"$tmp"
  local_dns:
    image: "${LOCALDNS_IMAGE}"
    container_name: "arr_local_dns"
    profiles:
      - "localdns"
    cap_add:
      - "NET_ADMIN"
    ports:
      - "${LAN_IP}:53:53/udp"
      - "${LAN_IP}:53:53/tcp"
    command:
      - "--log-facility=-"
      - "--log-async=5"
      - "--log-queries"
      - "--no-resolv"
YAML
    local server
    for server in "${upstream_dns_servers[@]}"; do
      arr_yaml_list_item "      " "--server=${server}" >>"$tmp"
    done
    cat <<'YAML' >>"$tmp"
      - "--domain-needed"
      - "--bogus-priv"
      - "--local-service"
      - "--domain=${LAN_DOMAIN_SUFFIX}"
      - "--local=/${LAN_DOMAIN_SUFFIX}/"
      - "--address=/${LAN_DOMAIN_SUFFIX}/${DNS_HOST_ENTRY}"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          if command -v drill >/dev/null 2>&1; then
            drill -Q example.com @${LOCALHOST_IP} >/dev/null 2>&1;
          elif command -v nslookup >/dev/null 2>&1; then
            nslookup example.com ${LOCALHOST_IP} >/dev/null 2>&1;
          elif command -v dig >/dev/null 2>&1; then
            dig +time=2 +tries=1 @${LOCALHOST_IP} example.com >/dev/null 2>&1;
          else
            exit 1;
          fi
      interval: "10s"
      timeout: "3s"
      retries: "6"
      start_period: "10s"

YAML
  fi

  cat <<'YAML' >>"$tmp"
  qbittorrent:
    image: "${QBITTORRENT_IMAGE}"
    container_name: "qbittorrent"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
      QBT_INT_PORT: "${QBT_INT_PORT}"
      QBT_BIND_ADDR: "${QBT_BIND_ADDR}"
      QBT_ENFORCE_WEBUI: "${QBT_ENFORCE_WEBUI}"
      QBT_WEBUI_INIT_HOOK: "1"
YAML
  if [[ -n "${QBT_DOCKER_MODS}" ]]; then
    #  write the literal ${QBT_DOCKER_MODS} token instead of expanding it at generation time
    # shellcheck disable=SC2016  # intentional literal for compose placeholder
    arr_yaml_kv "      " "DOCKER_MODS" '${QBT_DOCKER_MODS}' >>"$tmp"
  fi
  cat <<'YAML' >>"$tmp"
    volumes:
      - "${ARR_DOCKER_DIR}/qbittorrent:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${ARR_STACK_DIR}/scripts/qbt-helper.sh:/custom-cont-init.d/00-qbt-webui:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD", "/custom-cont-init.d/00-qbt-webui", "healthcheck"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: "${SONARR_IMAGE}"
    container_name: "sonarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/sonarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${TV_DIR}:/tv"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: "${RADARR_IMAGE}"
    container_name: "radarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/radarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${MOVIES_DIR}:/movies"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: "${PROWLARR_IMAGE}"
    container_name: "prowlarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/prowlarr:/config"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: "${BAZARR_IMAGE}"
    container_name: "bazarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/bazarr:/config"
      - "${TV_DIR}:/tv"
      - "${MOVIES_DIR}:/movies"
YAML

  if [[ -n "${SUBS_DIR:-}" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${SUBS_DIR}:/subs"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: "${FLARR_IMAGE}"
    container_name: "flaresolverr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: "info"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS --max-time 10 http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health || wget -q --timeout=10 -O- http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health || exit 1"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
      start_period: "40s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML

  if [[ "${SABNZBD_ENABLED}" == "1" ]]; then
    local sab_internal_port
    arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080
    cat <<'YAML' >>"$tmp"
  sabnzbd:
    image: "${SABNZBD_IMAGE}"
    container_name: "sabnzbd"
    profiles:
      - "ipdirect"
YAML
    if [[ "${SABNZBD_USE_VPN}" == "1" ]]; then
      cat <<'YAML' >>"$tmp"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
      append_sabnzbd_service_body "$tmp" "0" "$sab_internal_port"
    else
      local expose_direct_port="0"
      if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
        expose_direct_port="1"
      fi
      append_sabnzbd_service_body "$tmp" "$expose_direct_port" "$sab_internal_port"
    fi
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
  configarr:
    image: "${CONFIGARR_IMAGE}"
    container_name: "configarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
      sonarr:
        condition: "service_started"
      radarr:
        condition: "service_started"
    volumes:
      - "${ARR_DOCKER_DIR}/configarr/config.yml:/app/config.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/secrets.yml:/app/secrets.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/cfs:/app/cfs:ro"
    working_dir: "/app"
    entrypoint: ["/bin/sh","-lc","node dist/index.js || exit 1"]
    environment:
      TZ: "${TIMEZONE}"
    restart: "no"
    logging:
      driver: "json-file"
      options:
        max-size: "512k"
        max-file: "2"
YAML
  fi

  if ((include_caddy)); then
    cat <<'YAML' >>"$tmp"
  caddy:
    image: "${CADDY_IMAGE}"
    container_name: "caddy"
    profiles:
      - "proxy"
    network_mode: "service:gluetun"
    volumes:
      - "${ARR_DOCKER_DIR}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro"
      - "${ARR_DOCKER_DIR}/caddy/data:/data"
      - "${ARR_DOCKER_DIR}/caddy/config:/config"
      - "${ARR_DOCKER_DIR}/caddy/ca-pub:/ca-pub:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
    if ((include_local_dns)); then
      cat <<'YAML' >>"$tmp"
      local_dns:
        condition: "service_healthy"
YAML
    fi
    cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          curl -fsS --max-time 3 http://${LOCALHOST_IP}:${CADDY_HTTP_PORT}/healthz >/dev/null 2>&1 || curl -fsS --max-time 3 http://${LOCALHOST_IP}/healthz >/dev/null 2>&1 || wget -qO- --timeout=3 http://${LOCALHOST_IP}:${CADDY_HTTP_PORT}/healthz >/dev/null 2>&1
      interval: "10s"
      timeout: "5s"
      retries: "6"
      start_period: "20s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML
  fi

  printf '\n' >>"$tmp"

  if ! verify_single_level_env_placeholders "$tmp"; then
    rm -f "$tmp"
    die "Generated docker-compose.yml contains nested environment placeholders"
  fi

  if ! arr_verify_compose_placeholders "$tmp" "${ARR_ENV_FILE:-}"; then
    rm -f "$tmp"
    die "Generated docker-compose.yml contains unexpected environment placeholders"
  fi

  if ! arr_compose_autorepair_and_validate "$tmp" "$compose_path"; then
    rm -f "$tmp"
    die "Compose validation failed (see logs/compose-repair.log)"
  fi

  msg "  Local DNS status: ${LOCAL_DNS_STATE_REASON} (LOCAL_DNS_STATE=${LOCAL_DNS_STATE})"
}
# Writes Gluetun hook/auth assets so API key and port forwarding stay aligned
write_gluetun_control_assets() {
  msg "[pf] Preparing Gluetun control assets"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"
  local hooks_dir="${gluetun_root}/hooks"

  ensure_data_dir_mode "$gluetun_root"
  ensure_dir_mode "$hooks_dir" "$DATA_DIR_MODE"

  local auth_dir="${gluetun_root}/auth"
  local auth_config="${auth_dir}/config.toml"
  ensure_dir_mode "$auth_dir" "$DATA_DIR_MODE"

  # Only write role-based auth for Gluetun >=3.40 to avoid confusing older builds
  if gluetun_version_requires_auth_config 2>/dev/null && [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    local sanitized_key
    sanitized_key=${GLUETUN_API_KEY//$'\r'/}
    if [[ "$sanitized_key" == *$'\n'* ]]; then
      sanitized_key=${sanitized_key//$'\n'/}
      warn "[pf] Stripped newline characters from GLUETUN_API_KEY before writing auth config"
    fi
    sanitized_key=${sanitized_key//\\/\\\\}
    sanitized_key="$(printf '%s' "$sanitized_key" | sed 's/"/\\"/g')"

    local auth_payload
    auth_payload=$(
      cat <<EOF
[[roles]]
name = "${STACK}"
auth = "apikey"
apikey = "${sanitized_key}"
routes = [
  # Port forwarding endpoints
  "GET /v1/openvpn/portforwarded",

  # VPN status and control
  "GET /v1/openvpn/status",
  "PUT /v1/openvpn/status",

  # Public IP information
  "GET /v1/publicip/ip"
]
EOF
    )

    local auth_action=""
    if [[ ! -f "$auth_config" ]]; then
      auth_action="created"
    else
      local current_config
      current_config="$(cat "$auth_config" 2>/dev/null || printf '')"
      if [[ "$current_config" != "$auth_payload" ]]; then
        auth_action="updated"
      fi
    fi

    if [[ -n "$auth_action" ]]; then
      atomic_write "$auth_config" "$auth_payload" "$SECRET_FILE_MODE"
      msg "  Gluetun auth config ${auth_action} at ${auth_config}"
    fi
  else
    if gluetun_version_requires_auth_config 2>/dev/null; then
      warn "[pf] GLUETUN_API_KEY is empty; skipping Gluetun auth config generation (Gluetun 3.40+ requires an API key for control routes)"
    fi
  fi

  cat >"${hooks_dir}/update-qbt-port.sh" <<'HOOK'
#!/bin/sh
set -eu

log() {
    printf '[%s] [update-qbt-port] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" >&2
}

if ! command -v curl >/dev/null 2>&1; then
    log "curl not available inside Gluetun; skipping port update"
    exit 0
fi

PORT_SPEC="${1:-}"
PORT_VALUE="${PORT_SPEC%%,*}"
PORT_VALUE="${PORT_VALUE%%:*}"

case "$PORT_VALUE" in
    ''|*[!0-9]*)
        log "Ignoring non-numeric port payload: ${PORT_SPEC}"
        exit 0
        ;;
esac

QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://${LOCALHOST_IP:-localhost}:${QBT_INT_PORT:-8082}}"
PAYLOAD=$(printf 'json={"listen_port":%s,"random_port":false}' "$PORT_VALUE")

COOKIE_FILE=""
cleanup_cookie() {
    if [ -n "$COOKIE_FILE" ]; then
        rm -f "$COOKIE_FILE" 2>/dev/null || true
        COOKIE_FILE=""
    fi
}
trap cleanup_cookie EXIT

attempt_update() {
    UPDATE_METHOD=""

    if curl -fsS --max-time 8 \
        --data "$PAYLOAD" \
        "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        UPDATE_METHOD="direct"
        return 0
    fi

    if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
        COOKIE_FILE="$(mktemp "${TMPDIR:-/tmp}/update-qbt-cookie.XXXXXX")" || {
            log "Failed to create temporary cookie file"
            return 1
        }
        if curl -fsS --max-time 5 -c "$COOKIE_FILE" \
            --data-urlencode "username=${QBT_USER}" \
            --data-urlencode "password=${QBT_PASS}" \
            "${QBITTORRENT_ADDR%/}/api/v2/auth/login" >/dev/null 2>&1; then
            if curl -fsS --max-time 8 -b "$COOKIE_FILE" \
                --data "$PAYLOAD" \
                "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
                UPDATE_METHOD="authenticated"
                cleanup_cookie
                return 0
            fi
            log "Authenticated but failed to apply port update"
        else
            log "qBittorrent authentication failed"
        fi
        cleanup_cookie
    else
        if [ "${ATTEMPT:-0}" = "1" ]; then
            log "Skipping authenticated update: QBT_USER/QBT_PASS not provided"
        fi
    fi

    return 1
}

MAX_ATTEMPTS=3
ATTEMPT=0
UPDATE_METHOD=""

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))

    if attempt_update; then
        if [ "$UPDATE_METHOD" = "authenticated" ]; then
            log "Updated qBittorrent listen port to ${PORT_VALUE} after authentication (attempt ${ATTEMPT})"
        else
            log "Updated qBittorrent listen port to ${PORT_VALUE} (attempt ${ATTEMPT})"
        fi
        exit 0
    fi

    if [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; then
        log "Attempt ${ATTEMPT} failed, retrying..."
        sleep 2
    fi
done

log "Failed to update port after ${MAX_ATTEMPTS} attempts"
exit 1
HOOK

  ensure_file_mode "${hooks_dir}/update-qbt-port.sh" 700
}

# Ensures Caddy basic auth credentials exist, regenerating bcrypt/hash artifacts as needed
ensure_caddy_auth() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🔐 Skipping Caddy Basic Auth setup (ENABLE_CADDY=0)"
    return 0
  fi

  step "🔐 Ensuring Caddy Basic Auth"

  hydrate_caddy_auth_from_env_file

  local sanitized_user
  sanitized_user="$(sanitize_user "${CADDY_BASIC_AUTH_USER}")"
  if [[ "$sanitized_user" != "$CADDY_BASIC_AUTH_USER" ]]; then
    CADDY_BASIC_AUTH_USER="$sanitized_user"
    persist_env_var "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    msg "  Caddy user sanitized -> ${CADDY_BASIC_AUTH_USER}"
  fi

  local current_hash
  current_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH:-}")"
  CADDY_BASIC_AUTH_HASH="$current_hash"

  local need_regen=0
  if [[ "${FORCE_REGEN_CADDY_AUTH:-0}" == "1" ]]; then
    need_regen=1
  elif [[ -z "$current_hash" ]] || ! valid_bcrypt "$current_hash"; then
    need_regen=1
  fi

  local cred_dir="${ARR_DOCKER_DIR}/caddy"
  local cred_file="${cred_dir}/credentials"

  if [[ "$need_regen" == "1" ]]; then
    local plaintext
    plaintext="$(gen_safe_password 20)"

    local hash_output
    hash_output="$(caddy_bcrypt "$plaintext" || true)"
    local new_hash
    new_hash="$(printf '%s\n' "$hash_output" | awk '/^\$2[aby]\$/{hash=$0} END {if (hash) print hash}')"

    if [[ -z "$new_hash" ]] || ! valid_bcrypt "$new_hash"; then
      die "Failed to generate Caddy bcrypt hash (docker or ${CADDY_IMAGE} unavailable?)"
    fi

    CADDY_BASIC_AUTH_HASH="$new_hash"
    persist_env_var "CADDY_BASIC_AUTH_HASH" "$CADDY_BASIC_AUTH_HASH"

    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    (
      umask 0077
      {
        printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
        printf 'password=%s\n' "$plaintext"
      } >"$cred_file"
    )
    chmod 600 "$cred_file" 2>/dev/null || true

    local passmask
    passmask="$(obfuscate_sensitive "$plaintext" 2 2)"
    msg "  Generated new Caddy credentials -> user: ${CADDY_BASIC_AUTH_USER}, pass: ${passmask}"
    msg "  Full credentials saved to: ${cred_file}"
  else
    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    local existing_plain=""
    if [[ -f "$cred_file" ]]; then
      existing_plain="$(grep '^password=' "$cred_file" | head -n1 | cut -d= -f2- || true)"
    fi
    if [[ -n "$existing_plain" ]]; then
      (
        umask 0077
        {
          printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
          printf 'password=%s\n' "$existing_plain"
        } >"$cred_file"
      )
      chmod 600 "$cred_file" 2>/dev/null || true
    else
      warn "Caddy credentials file missing plaintext password; use --rotate-caddy-auth to recreate it."
    fi
    msg "  Existing Caddy bcrypt hash is valid ✓"
  fi
}

# Publishes Caddy's internal CA to a readable location for LAN distribution
sync_caddy_ca_public_copy() {
  local wait_attempts=1
  local quiet=0

  while (($#)); do
    case "$1" in
      --wait)
        wait_attempts=10
        ;;
      --quiet)
        quiet=1
        ;;
    esac
    shift
  done

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local ca_source="${caddy_root}/data/pki/authorities/local/root.crt"
  local ca_pub_dir="${caddy_root}/ca-pub"
  local ca_dest="${ca_pub_dir}/root.crt"

  ensure_dir "$ca_pub_dir"
  chmod "$DATA_DIR_MODE" "$ca_pub_dir" 2>/dev/null || true

  local attempt
  for ((attempt = 1; attempt <= wait_attempts; attempt++)); do
    if [[ -f "$ca_source" ]]; then
      if [[ -f "$ca_dest" ]] && cmp -s "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        return 0
      fi

      if cp -f "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        msg "  Published Caddy root certificate to ${ca_dest}"
        return 0
      fi

      warn "Failed to copy Caddy root certificate to ${ca_dest}"
      return 1
    fi

    if ((attempt < wait_attempts)); then
      sleep 2
    fi
  done

  if ((quiet == 0)); then
    warn "Caddy root certificate not found at ${ca_source}; it will be copied after Caddy issues it."
  fi

  return 1
}

# Generates Caddyfile and copies CA assets when proxying is enabled
write_caddy_assets() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🌐 Skipping Caddy configuration (ENABLE_CADDY=0)"
    return 0
  fi

  step "🌐 Writing Caddy reverse proxy config"

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local data_dir="${caddy_root}/data"
  local config_dir="${caddy_root}/config"
  local caddyfile="${caddy_root}/Caddyfile"
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  ensure_dir "$caddy_root"
  ensure_dir "$data_dir"
  ensure_dir "$config_dir"
  chmod "$DATA_DIR_MODE" "$caddy_root" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$data_dir" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$config_dir" 2>/dev/null || true

  # Normalize LAN CIDRs into single-space separators
  local lan_cidrs
  lan_cidrs="$(printf '%s' "${CADDY_LAN_CIDRS}" | tr ',\t\r\n' '    ')"
  lan_cidrs="$(printf '%s\n' "$lan_cidrs" | xargs 2>/dev/null || printf '')"
  if [[ -z "$lan_cidrs" ]]; then
    lan_cidrs="${LOCALHOST_IP}/32"
  fi

  local caddy_auth_hash
  caddy_auth_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH}")"

  if ! is_bcrypt_hash "$caddy_auth_hash"; then
    warn "CADDY_BASIC_AUTH_HASH does not appear to be a valid bcrypt string; use --rotate-caddy-auth to regenerate."
  fi

  # Prefer normalized suffix from .env; fall back to computed value
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local default_upstream_host="${LOCALHOST_IP:-localhost}"
  if [[ -z "$default_upstream_host" || "$default_upstream_host" == "0.0.0.0" ]]; then
    default_upstream_host="localhost"
  fi

  local -a services=(
    "qbittorrent|${QBT_INT_PORT}|${default_upstream_host}"
    "sonarr|${SONARR_PORT}|${default_upstream_host}"
    "radarr|${RADARR_PORT}|${default_upstream_host}"
    "prowlarr|${PROWLARR_PORT}|${default_upstream_host}"
    "bazarr|${BAZARR_PORT}|${default_upstream_host}"
    "flaresolverr|${FLARR_PORT}|${default_upstream_host}"
  )

  if [[ "${SABNZBD_ENABLED:-0}" == "1" && "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
    local sab_proxy_port="${SABNZBD_PORT}"
    local sab_upstream_host="${SABNZBD_HOST:-$default_upstream_host}"
    if [[ -z "$sab_upstream_host" || "$sab_upstream_host" == "0.0.0.0" ]]; then
      sab_upstream_host="$default_upstream_host"
    fi
    if [[ -n "$sab_proxy_port" && "$sab_proxy_port" =~ ^[0-9]+$ ]]; then
      services+=("sabnzbd|${sab_proxy_port}|${sab_upstream_host}")
    fi
  fi

  local caddyfile_content
  caddyfile_content="$({
    printf '%s\n' "# Auto-generated by ${STACK}.sh"
    printf '# Adjust LAN CIDRs or add TLS settings via %s overrides.\n\n' "$userconf_path"
    printf '{\n'
    printf '  admin off\n'
    printf '}\n\n'

    # Plain HTTP health endpoint for container healthcheck
    printf 'http://ca.%s {\n' "$domain_suffix"
    printf '    root * /ca-pub\n'
    printf '    file_server\n'
    printf '    # Serve the public root over HTTP to avoid bootstrap loops\n'
    printf '    @ca_cert {\n'
    printf '        path /root.crt\n'
    printf '    }\n'
    printf '    handle @ca_cert {\n'
    printf '        header Content-Type "application/pkix-cert"\n'
    printf '        header Content-Disposition "attachment; filename=\"%s-root.cer\""\n' "$STACK"
    printf '    }\n'
    printf '}\n\n'

    local entry name port upstream_host host
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      host="${name}.${domain_suffix}"
      printf '%s {\n' "$host"
      printf '    tls internal\n'
      printf '    @lan remote_ip %s\n' "$lan_cidrs"
      printf '    handle @lan {\n'
      printf '        reverse_proxy %s:%s\n' "$upstream_host" "$port"
      printf '    }\n'
      printf '    handle {\n'
      printf '        basic_auth * {\n'
      printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
      printf '        }\n'
      printf '        reverse_proxy %s:%s\n' "$upstream_host" "$port"
      printf '    }\n'
      printf '}\n\n'
    done

    printf ':%s, :%s {\n' "$CADDY_HTTP_PORT" "$CADDY_HTTPS_PORT"
    printf '    encode zstd gzip\n'
    printf '    @lan remote_ip %s\n' "$lan_cidrs"
    printf '    route /healthz {\n'
    printf '        respond "ok" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle @lan {\n'
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://%s:%s\n' "$upstream_host" "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle {\n'
    printf '        basic_auth * {\n'
    printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
    printf '        }\n'
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://%s:%s\n' "$upstream_host" "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    tls internal\n'
    printf '}\n\n'
  })"

  atomic_write "$caddyfile" "$caddyfile_content" "$NONSECRET_FILE_MODE"

  sync_caddy_ca_public_copy --quiet || true

  if ! grep -Fq "${CADDY_BASIC_AUTH_USER}" "$caddyfile"; then
    warn "Caddyfile is missing the configured Basic Auth user; verify CADDY_BASIC_AUTH_USER"
  fi

  # shellcheck disable=SC2016  # intentional literal $ in regex
  if ! grep -qE '\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}' "$caddyfile"; then
    warn "Caddyfile bcrypt string may be invalid; hash regeneration fixes this (use --rotate-caddy-auth)."
  fi
}

# Copies the shared Gluetun helper script into the stack workspace
sync_gluetun_library() {
  step "📚 Syncing Gluetun helper library"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/gluetun.sh" "$ARR_STACK_DIR/scripts/gluetun.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/gluetun.sh" 755
}

# Syncs VPN auto-reconnect scripts with executable permissions into the stack
sync_vpn_auto_reconnect_assets() {
  step "📡 Syncing VPN auto-reconnect helpers"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/vpn-auto-reconnect.sh" "$ARR_STACK_DIR/scripts/vpn-auto-reconnect.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/vpn-auto-reconnect.sh" 755

  cp "${REPO_ROOT}/scripts/vpn-auto-reconnect-daemon.sh" "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh" 755
}

# Installs SABnzbd helper into the stack scripts directory
write_sab_helper_script() {
  step "🧰 Writing SABnzbd helper script"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/sab-helper.sh" "$ARR_STACK_DIR/scripts/sab-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/sab-helper.sh" 755

  msg "  SABnzbd helper: ${ARR_STACK_DIR}/scripts/sab-helper.sh"
}

# Installs qBittorrent helper shim into the stack scripts directory
write_qbt_helper_script() {
  step "🧰 Writing qBittorrent helper script"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/qbt-helper.sh" 755

  rm -f "$ARR_STACK_DIR/scripts/qbt-webui.sh"

  msg "  qBittorrent helper (also init hook): ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

# Reconciles qBittorrent configuration defaults while preserving user customizations
write_qbt_config() {
  step "🧩 Writing qBittorrent config"
  local config_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local runtime_dir="${config_dir}/qBittorrent"
  local conf_file="${config_dir}/qBittorrent.conf"
  local legacy_conf="${runtime_dir}/qBittorrent.conf"

  ensure_dir "$config_dir"
  ensure_dir "$runtime_dir"

  if [[ -f "$legacy_conf" && ! -f "$conf_file" ]]; then
    msg "  Migrating legacy config from ${legacy_conf}"
    mv "$legacy_conf" "$conf_file"
    ensure_secret_file_mode "$conf_file"
  fi

  if [[ -f "$legacy_conf" ]]; then
    msg "  Removing unused legacy config at ${legacy_conf}"
    rm -f "$legacy_conf"
  fi
  local default_auth_whitelist="${LOCALHOST_IP}/32,::1/128"
  local qb_lan_whitelist=""
  if qb_lan_whitelist="$(lan_ipv4_subnet_cidr "${LAN_IP:-}" 2>/dev/null)" && [[ -n "$qb_lan_whitelist" ]]; then
    default_auth_whitelist+=,${qb_lan_whitelist}
  fi

  local auth_whitelist
  auth_whitelist="$(normalize_csv "${QBT_AUTH_WHITELIST:-$default_auth_whitelist}")"
  QBT_AUTH_WHITELIST="$auth_whitelist"
  msg "  Stored WebUI auth whitelist entries: ${auth_whitelist}"

  local vt_root="${VUETORRENT_ROOT:-/config/vuetorrent}"
  local vt_alt_value="true"
  if [[ "${VUETORRENT_ALT_ENABLED:-1}" -eq 0 ]]; then
    vt_alt_value="false"
  fi

  local default_conf
  default_conf="$(
    cat <<EOF
[AutoRun]
enabled=false

[BitTorrent]
Session\AddTorrentStopped=false
Session\DefaultSavePath=/completed/
Session\TempPath=/downloads/incomplete/
Session\TempPathEnabled=true

[Meta]
MigrationVersion=8

[Network]
PortForwardingEnabled=false

[Preferences]
General\UseRandomPort=false
Connection\UPnP=false
Connection\UseNAT-PMP=false
WebUI\UseUPnP=false
Downloads\SavePath=/completed/
Downloads\TempPath=/downloads/incomplete/
Downloads\TempPathEnabled=true
WebUI\Address=${QBT_BIND_ADDR}
WebUI\AlternativeUIEnabled=${vt_alt_value}
WebUI\RootFolder=${vt_root}
WebUI\Port=${QBT_INT_PORT}
WebUI\Username=${QBT_USER}
WebUI\LocalHostAuth=true
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\AuthSubnetWhitelist=${auth_whitelist}
WebUI\CSRFProtection=true
WebUI\ClickjackingProtection=true
WebUI\HostHeaderValidation=false
WebUI\HTTPS\Enabled=false
WebUI\ServerDomains=*
EOF
  )"

  local source_content="$default_conf"
  if [[ -f "$conf_file" ]]; then
    source_content="$(<"$conf_file")"
  fi

  local managed_spec
  local -a managed_lines=(
    "WebUI\\Address=${QBT_BIND_ADDR}"
    "WebUI\\Port=${QBT_INT_PORT}"
    "WebUI\\AlternativeUIEnabled=${vt_alt_value}"
    "WebUI\\RootFolder=${vt_root}"
    "WebUI\\ServerDomains=*"
    "WebUI\\LocalHostAuth=true"
    "WebUI\\AuthSubnetWhitelistEnabled=true"
    "WebUI\\CSRFProtection=true"
    "WebUI\\ClickjackingProtection=true"
    "WebUI\\HostHeaderValidation=false"
    "WebUI\\AuthSubnetWhitelist=${auth_whitelist}"
  )
  managed_spec="$(printf '%s\n' "${managed_lines[@]}")"
  managed_spec="${managed_spec%$'\n'}"

  local managed_spec_for_awk
  # Escape backslashes so awk -v does not treat sequences like \A as escapes
  managed_spec_for_awk="${managed_spec//\\/\\\\}"

  local updated_content
  updated_content="$(
    printf '%s' "$source_content" \
      | awk -v managed="$managed_spec_for_awk" '
        BEGIN {
          FS = "=";
          OFS = "=";
          order_count = 0;
          count = split(managed, arr, "\n");
          for (i = 1; i <= count; i++) {
            if (arr[i] == "") {
              continue;
            }
            split(arr[i], kv, "=");
            key = kv[1];
            value = substr(arr[i], length(key) + 2);
            replacements[key] = value;
            order[++order_count] = key;
          }
        }
        {
          line = $0;
          if (index(line, "=") == 0) {
            print line;
            next;
          }
          split(line, kv, "=");
          key = kv[1];
          if (key in replacements) {
            print key, replacements[key];
            seen[key] = 1;
          } else {
            print line;
          }
        }
        END {
          for (i = 1; i <= order_count; i++) {
            key = order[i];
            if (!(key in seen)) {
              print key, replacements[key];
            }
          }
        }
      '
  )"

  atomic_write "$conf_file" "$updated_content" "$SECRET_FILE_MODE"
}

ensure_qbt_config() {
  msg "Ensuring qBittorrent configuration is applied"

  # Sleep to allow qBittorrent to restart safely; configurable via QBT_CONFIG_SLEEP (default: 5 seconds)
  sleep "${QBT_CONFIG_SLEEP:-5}"

  if ! docker inspect qbittorrent --format '{{.State.Running}}' 2>/dev/null | grep -q "true"; then
    warn "qBittorrent container not running, skipping config sync"
  fi

  sync_qbt_password_from_logs || true

  docker stop qbittorrent >/dev/null 2>&1 || true
  sleep "${QBT_CONFIG_SLEEP:-5}"

  write_qbt_config

  docker start qbittorrent >/dev/null 2>&1 || true

  return 0
}

# Materializes Configarr config/secrets with sanitized policy values when enabled
write_configarr_assets() {
  if [[ "${ENABLE_CONFIGARR:-0}" != "1" ]]; then
    msg "🧾 Skipping Configarr assets (ENABLE_CONFIGARR=0)"
    return 0
  fi

  step "🧾 Preparing Configarr assets"

  local configarr_root="${ARR_DOCKER_DIR}/configarr"
  local runtime_config="${configarr_root}/config.yml"
  local runtime_secrets="${configarr_root}/secrets.yml"
  local runtime_cfs="${configarr_root}/cfs"
  local -A configarr_policy=()

  ensure_dir_mode "$configarr_root" "$DATA_DIR_MODE"
  ensure_dir_mode "$runtime_cfs" "$DATA_DIR_MODE"

  local sanitized_video_min_res=""
  local sanitized_video_max_res=""
  local episode_max_mbmin=""
  local episode_min_mbmin=""
  local episode_pref_mbmin=""
  local episode_cap_mb=""
  local sanitized_ep_max_gb=""
  local sanitized_ep_min_mb=""
  local sanitized_runtime_min=""
  local sanitized_season_max_gb=""
  local sanitized_mbmin_decimals=""

  if have_command python3; then
    local py_output=""
    if py_output=$(
      python3 <<'PY'
import math
import os


def trim_float(value: float, precision: int = 2) -> str:
    if math.isclose(value, round(value)):
        return str(int(round(value)))
    fmt = "{:." + str(precision) + "f}"
    text = fmt.format(value)
    return text.rstrip("0").rstrip(".")


def sanitize_resolution(name: str, default: str, allowed: list[str], warnings: list[str]) -> str:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    lowered = raw.lower()
    for candidate in allowed:
        if candidate.lower() == lowered:
            return candidate
    warnings.append(f"{name}='{raw}' not supported; using {default}")
    return default


def parse_float(name: str, default: float, warnings: list[str], minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name, "")
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        warnings.append(f"{name}='{raw}' is not numeric; using {default}")
        return default
    if minimum is not None and value < minimum:
        warnings.append(f"{name}={raw} below minimum {minimum}; clamping")
        value = minimum
    if maximum is not None and value > maximum:
        warnings.append(f"{name}={raw} above maximum {maximum}; clamping")
        value = maximum
    return value


warnings: list[str] = []
allowed_res = ["480p", "576p", "720p", "1080p", "2160p"]
res_index = {res: idx for idx, res in enumerate(allowed_res)}

min_res = sanitize_resolution("ARR_VIDEO_MIN_RES", "720p", allowed_res, warnings)
max_res = sanitize_resolution("ARR_VIDEO_MAX_RES", "1080p", allowed_res, warnings)

if res_index[min_res] > res_index[max_res]:
    warnings.append(
        f"ARR_VIDEO_MIN_RES='{min_res}' and ARR_VIDEO_MAX_RES='{max_res}' conflict; using 720p–1080p"
    )
    min_res = "720p"
    max_res = "1080p"

max_gb = parse_float("ARR_EP_MAX_GB", 5.0, warnings, minimum=1.0, maximum=20.0)
min_mb = parse_float("ARR_EP_MIN_MB", 250.0, warnings, minimum=1.0)
runtime = parse_float("ARR_TV_RUNTIME_MIN", 45.0, warnings, minimum=1.0)
season_cap = parse_float("ARR_SEASON_MAX_GB", 30.0, warnings, minimum=1.0)

dec_raw = os.environ.get("ARR_MBMIN_DECIMALS", "1") or "1"
try:
    decimals = int(dec_raw)
except ValueError:
    warnings.append(f"ARR_MBMIN_DECIMALS='{dec_raw}' invalid; using 1")
    decimals = 1

if decimals < 0:
    warnings.append("ARR_MBMIN_DECIMALS below 0; clamping to 0")
    decimals = 0
elif decimals > 3:
    warnings.append("ARR_MBMIN_DECIMALS above 3; clamping to 3")
    decimals = 3

max_total_mb = max_gb * 1024.0

if min_mb >= max_total_mb:
    warnings.append(
        f"ARR_EP_MIN_MB={min_mb} must be smaller than ARR_EP_MAX_GB*1024={max_total_mb}; reducing"
    )
    min_mb = min(250.0, max_total_mb * 0.5)
    if min_mb <= 0:
        min_mb = max_total_mb * 0.25

episode_max_mbmin = max_total_mb / runtime
episode_min_mbmin = min_mb / runtime

if episode_max_mbmin < 20.0:
    warnings.append(
        f"Derived episode max {episode_max_mbmin:.2f} MB/min is too small; using 60"
    )
    episode_max_mbmin = 60.0

if episode_min_mbmin >= episode_max_mbmin:
    episode_min_mbmin = max(episode_max_mbmin * 0.5, 1.0)

episode_pref_mbmin = (episode_min_mbmin + episode_max_mbmin) / 2.0

fmt = "{:." + str(decimals) + "f}"

print(f"sanitized_video_min_res={min_res}")
print(f"sanitized_video_max_res={max_res}")
print(f"episode_max_mbmin={fmt.format(episode_max_mbmin)}")
print(f"episode_min_mbmin={fmt.format(episode_min_mbmin)}")
print(f"episode_pref_mbmin={fmt.format(episode_pref_mbmin)}")
print(f"episode_cap_mb={int(round(max_total_mb))}")
print(f"sanitized_ep_max_gb={trim_float(max_gb)}")
print(f"sanitized_ep_min_mb={trim_float(min_mb, 1)}")
print(f"sanitized_runtime_min={trim_float(runtime, 1)}")
print(f"sanitized_season_max_gb={trim_float(season_cap, 1)}")
print(f"sanitized_mbmin_decimals={decimals}")

for warning in warnings:
    print("warn::" + warning)
PY
    ); then
      while IFS= read -r line; do
        case "$line" in
          warn::*)
            warn "Configarr: ${line#warn::}"
            ;;
          sanitized_video_min_res=*)
            sanitized_video_min_res="${line#*=}"
            ;;
          sanitized_video_max_res=*)
            sanitized_video_max_res="${line#*=}"
            ;;
          episode_max_mbmin=*)
            episode_max_mbmin="${line#*=}"
            ;;
          episode_min_mbmin=*)
            episode_min_mbmin="${line#*=}"
            ;;
          episode_pref_mbmin=*)
            episode_pref_mbmin="${line#*=}"
            ;;
          episode_cap_mb=*)
            episode_cap_mb="${line#*=}"
            ;;
          sanitized_ep_max_gb=*)
            sanitized_ep_max_gb="${line#*=}"
            ;;
          sanitized_ep_min_mb=*)
            sanitized_ep_min_mb="${line#*=}"
            ;;
          sanitized_runtime_min=*)
            sanitized_runtime_min="${line#*=}"
            ;;
          sanitized_season_max_gb=*)
            sanitized_season_max_gb="${line#*=}"
            ;;
          sanitized_mbmin_decimals=*)
            sanitized_mbmin_decimals="${line#*=}"
            ;;
        esac
      done <<<"$py_output"
    else
      warn "Configarr: failed to evaluate policy heuristics via python3; using defaults"
    fi
  else
    warn "Configarr: python3 unavailable; using default policy heuristics"
  fi

  : "${sanitized_video_min_res:=720p}"
  : "${sanitized_video_max_res:=1080p}"
  : "${episode_max_mbmin:=113.8}"
  : "${episode_min_mbmin:=5.6}"
  : "${episode_pref_mbmin:=59.7}"
  : "${episode_cap_mb:=5120}"
  : "${sanitized_ep_max_gb:=5}"
  : "${sanitized_ep_min_mb:=250}"
  : "${sanitized_runtime_min:=45}"
  : "${sanitized_season_max_gb:=30}"
  : "${sanitized_mbmin_decimals:=1}"

  declare -A res_index=(
    [480p]=0
    [576p]=1
    [720p]=2
    [1080p]=3
    [2160p]=4
  )

  local min_idx="${res_index[$sanitized_video_min_res]:-${res_index[720p]}}"
  local max_idx="${res_index[$sanitized_video_max_res]:-${res_index[1080p]}}"

  local include_720=0
  local include_1080=0

  if ((min_idx <= res_index[720p] && max_idx >= res_index[720p])); then
    include_720=1
  fi
  if ((min_idx <= res_index[1080p] && max_idx >= res_index[1080p])); then
    include_1080=1
  fi

  if ((include_720 == 0 && include_1080 == 0)); then
    include_1080=1
    sanitized_video_min_res="1080p"
    sanitized_video_max_res="1080p"
    min_idx="${res_index[1080p]}"
    max_idx="${res_index[1080p]}"
  fi

  local -a sonarr_qualities=()
  local -a radarr_qualities=()

  if ((include_720)); then
    sonarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
    radarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
  fi
  if ((include_1080)); then
    sonarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Bluray-1080p Remux")
    radarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Remux-1080p")
  fi

  if ((${#sonarr_qualities[@]} == 0)); then
    sonarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi
  if ((${#radarr_qualities[@]} == 0)); then
    radarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi

  local sonarr_quality_yaml=""
  local radarr_quality_yaml=""
  local quality

  for quality in "${sonarr_qualities[@]}"; do
    sonarr_quality_yaml+="    - quality: \"${quality}\"\n"
    sonarr_quality_yaml+="      min: \"${episode_min_mbmin}\"\n"
    sonarr_quality_yaml+="      preferred: \"${episode_pref_mbmin}\"\n"
    sonarr_quality_yaml+="      max: \"${episode_max_mbmin}\"\n"
  done

  for quality in "${radarr_qualities[@]}"; do
    radarr_quality_yaml+="    - quality: \"${quality}\"\n"
    radarr_quality_yaml+="      min: \"${episode_min_mbmin}\"\n"
    radarr_quality_yaml+="      preferred: \"${episode_pref_mbmin}\"\n"
    radarr_quality_yaml+="      max: \"${episode_max_mbmin}\"\n"
  done

  local sonarr_override_path="${runtime_cfs}/sonarr-quality-definition-override.yml"
  local radarr_override_path="${runtime_cfs}/radarr-quality-definition-override.yml"
  local common_cf_path="${runtime_cfs}/common-negative-formats.yml"

  if [[ ! -f "$sonarr_override_path" ]]; then
    local sonarr_content
    sonarr_content="# Auto-generated by ${STACK}.sh for Configarr size guardrails\n"
    sonarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    sonarr_content+="quality_definition:\n"
    sonarr_content+="  qualities:\n"
    sonarr_content+="${sonarr_quality_yaml}"
    atomic_write "$sonarr_override_path" "$sonarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Sonarr quality override: ${sonarr_override_path}"
  else
    ensure_nonsecret_file_mode "$sonarr_override_path"
  fi

  if [[ ! -f "$radarr_override_path" ]]; then
    local radarr_content
    radarr_content="# Auto-generated by ${STACK}.sh for Configarr size guardrails\n"
    radarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    radarr_content+="quality_definition:\n"
    radarr_content+="  qualities:\n"
    radarr_content+="${radarr_quality_yaml}"
    atomic_write "$radarr_override_path" "$radarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Radarr quality override: ${radarr_override_path}"
  else
    ensure_nonsecret_file_mode "$radarr_override_path"
  fi

  normalize_toggle() {
    local value="${1:-0}"
    case "$value" in
      1 | true | TRUE | yes | YES | on | ON)
        printf '1'
        ;;
      *)
        printf '0'
        ;;
    esac
  }

  sanitize_score() {
    local value="${1:-0}"
    local default="${2:-0}"
    if [[ "$value" =~ ^-?[0-9]+$ ]]; then
      printf '%s' "$value"
    else
      warn "Configarr: invalid score '${value}', using ${default}"
      printf '%s' "$default"
    fi
  }

  local english_only
  english_only="$(normalize_toggle "${ARR_ENGLISH_ONLY:-1}")"
  local discourage_multi
  discourage_multi="$(normalize_toggle "${ARR_DISCOURAGE_MULTI:-1}")"
  local penalize_hd_x265
  penalize_hd_x265="$(normalize_toggle "${ARR_PENALIZE_HD_X265:-1}")"
  local strict_junk_block
  strict_junk_block="$(normalize_toggle "${ARR_STRICT_JUNK_BLOCK:-1}")"

  local junk_score
  junk_score="$(sanitize_score "${ARR_JUNK_NEGATIVE_SCORE:- -1000}" "-1000")"
  local x265_score
  x265_score="$(sanitize_score "${ARR_X265_HD_NEGATIVE_SCORE:- -200}" "-200")"
  local multi_score
  multi_score="$(sanitize_score "${ARR_MULTI_NEGATIVE_SCORE:- -50}" "-50")"
  local english_bias_raw
  english_bias_raw="$(sanitize_score "${ARR_ENGLISH_POSITIVE_SCORE:-50}" "50")"

  local english_penalty_score="-${english_bias_raw#-}"

  local -a policy_profile_targets=("WEB-1080p" "HD Bluray + WEB")
  append_cf_block() {
    local score="$1"
    local label="$2"
    shift 2 || return 0
    local -a ids=("$@")
    if [[ -z "$score" || "$score" == "0" ]]; then
      return 0
    fi
    if ((${#ids[@]} == 0)); then
      return 0
    fi
    local block="  # ${label}\n  - trash_ids:\n"
    local id
    for id in "${ids[@]}"; do
      block+="      - $(arr_yaml_escape "${id}")\n"
    done
    block+="    assign_scores_to:\n"
    local target
    for target in "${policy_profile_targets[@]}"; do
      block+="      - name: $(arr_yaml_escape "${target}")\n"
      block+="        score: $(arr_yaml_escape "${score}")\n"
    done
    printf '%s' "$block"
  }

  local -a cf_ids_lq=("9c11cd3f07101cdba90a2d81cf0e56b4" "90a6f9a284dff5103f6346090e6280c8")
  local -a cf_ids_lq_title=("e2315f990da2e2cbfc9fa5b7a6fcfe48" "e204b80c87be9497a8a6eaff48f72905")
  local -a cf_ids_upscaled=("23297a736ca77c0fc8e70f8edd7ee56c" "bfd8eb01832d646a0a89c4deb46f8564")
  local -a cf_ids_language=("69aa1e159f97d860440b04cd6d590c4f" "0dc8aec3bd1c47cd6c40c46ecd27e846")
  local -a cf_ids_multi=("7ba05c6e0e14e793538174c679126996" "4b900e171accbfb172729b63323ea8ca")
  local -a cf_ids_x265=("47435ece6b99a0b477caf360e79ba0bb" "dc98083864ea246d05a42df0d05f81cc")

  local common_cf_body=""
  local block=""

  if ((strict_junk_block)); then
    block="$(append_cf_block "$junk_score" "LQ releases" "${cf_ids_lq[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block "$junk_score" "LQ (Release Title)" "${cf_ids_lq_title[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block "$junk_score" "Upscaled flags" "${cf_ids_upscaled[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((english_only)); then
    block="$(append_cf_block "$english_penalty_score" "Language: Not English" "${cf_ids_language[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((discourage_multi)); then
    block="$(append_cf_block "$multi_score" "MULTi releases" "${cf_ids_multi[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((penalize_hd_x265)); then
    block="$(append_cf_block "$x265_score" "x265 (HD)" "${cf_ids_x265[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  local common_cf_exists=0
  if [[ -n "$common_cf_body" ]]; then
    local cf_payload="# Auto-generated by ${STACK}.sh to reinforce Configarr scoring\n"
    cf_payload+="# Adjust ARR_* environment variables to regenerate; delete this file to rebuild.\n"
    cf_payload+="custom_formats:\n"
    cf_payload+="$common_cf_body"
    if [[ ! -f "$common_cf_path" ]]; then
      atomic_write "$common_cf_path" "$cf_payload" "$NONSECRET_FILE_MODE"
      msg "  Created shared custom-format reinforcements: ${common_cf_path}"
    else
      ensure_nonsecret_file_mode "$common_cf_path"
    fi
    common_cf_exists=1
  elif [[ -f "$common_cf_path" ]]; then
    ensure_nonsecret_file_mode "$common_cf_path"
    common_cf_exists=1
  fi

  local -a sonarr_templates=("sonarr-quality-definition-series")
  local sonarr_profile_template="${SONARR_TRASH_TEMPLATE:-sonarr-v4-quality-profile-web-1080p}"
  if [[ -n "$sonarr_profile_template" ]]; then
    sonarr_templates+=("${sonarr_profile_template}")
  fi
  sonarr_templates+=("sonarr-v4-custom-formats-web-1080p")
  if [[ -f "$sonarr_override_path" ]]; then
    sonarr_templates+=("sonarr-quality-definition-override")
  fi
  if ((common_cf_exists)); then
    sonarr_templates+=("common-negative-formats")
  fi

  local -a radarr_templates=("radarr-quality-definition")
  local radarr_profile_template="${RADARR_TRASH_TEMPLATE:-radarr-v5-quality-profile-hd-bluray-web}"
  if [[ -n "$radarr_profile_template" ]]; then
    radarr_templates+=("${radarr_profile_template}")
  fi
  radarr_templates+=("radarr-v5-custom-formats-hd-bluray-web")
  if [[ -f "$radarr_override_path" ]]; then
    radarr_templates+=("radarr-quality-definition-override")
  fi
  if ((common_cf_exists)); then
    radarr_templates+=("common-negative-formats")
  fi

  local sonarr_include_yaml=""
  local template
  for template in "${sonarr_templates[@]}"; do
    sonarr_include_yaml+="      - template: $(arr_yaml_escape "${template}")\n"
  done
  sonarr_include_yaml+="      # - template: sonarr-v4-quality-profile-web-2160p\n"
  sonarr_include_yaml+="      # - template: sonarr-v4-custom-formats-web-2160p\n"

  local radarr_include_yaml=""
  for template in "${radarr_templates[@]}"; do
    radarr_include_yaml+="      - template: $(arr_yaml_escape "${template}")\n"
  done
  radarr_include_yaml+="      # - template: radarr-v5-quality-profile-uhd-bluray-web\n"
  radarr_include_yaml+="      # - template: radarr-v5-custom-formats-uhd-bluray-web\n"

  local default_config
  default_config=$(
    cat <<EOF_CFG
# Auto-generated by the stack script. Edit cautiously or disable via ENABLE_CONFIGARR=0.
version: 1

localConfigTemplatesPath: /app/cfs
# localCustomFormatsPath: /app/cfs

sonarr:
  main:
    define: true
    host: http://${LOCALHOST_IP}:${SONARR_PORT}
    apiKey: !secret SONARR_API_KEY
    include:
${sonarr_include_yaml}    custom_formats: []

radarr:
  main:
    define: true
    host: http://${LOCALHOST_IP}:${RADARR_PORT}
    apiKey: !secret RADARR_API_KEY
    include:
${radarr_include_yaml}    custom_formats: []
EOF_CFG
  )

  if [[ ! -f "$runtime_config" ]]; then
    atomic_write "$runtime_config" "$default_config" "$NONSECRET_FILE_MODE"
    msg "  Installed default config: ${runtime_config}"
  else
    ensure_nonsecret_file_mode "$runtime_config"
  fi

  if [[ ! -f "$runtime_secrets" ]]; then
    local secrets_stub
    secrets_stub=$(
      cat <<'EOF'
SONARR_API_KEY: "REPLACE_WITH_SONARR_API_KEY"
RADARR_API_KEY: "REPLACE_WITH_RADARR_API_KEY"
PROWLARR_API_KEY: "REPLACE_WITH_PROWLARR_API_KEY"
SABNZBD_API_KEY: "REPLACE_WITH_SABNZBD_API_KEY"
EOF
    )
    atomic_write "$runtime_secrets" "$secrets_stub" "$SECRET_FILE_MODE"
    msg "  Stubbed secrets file: ${runtime_secrets}"
  else
    ensure_secret_file_mode "$runtime_secrets"
  fi

  if [[ -f "$runtime_secrets" ]]; then
    if ! grep -q '^SABNZBD_API_KEY:' "$runtime_secrets" 2>/dev/null; then
      printf 'SABNZBD_API_KEY: "REPLACE_WITH_SABNZBD_API_KEY"\n' >>"$runtime_secrets"
      ensure_secret_file_mode "$runtime_secrets"
      msg "  Added SABnzbd placeholder to Configarr secrets"
    fi

    if [[ "${ARR_SAB_API_KEY_STATE:-}" == "set" ]]; then
      local sab_secret_result=""
      if sab_secret_result="$(arr_update_secret_line "$runtime_secrets" "SABNZBD_API_KEY" "$SABNZBD_API_KEY" 0 2>/dev/null)"; then
        case "$sab_secret_result" in
          updated | created | appended)
            msg "  Configarr secrets: synced SABnzbd API key"
            ;;
        esac
      fi
    fi
  fi

  local resolution_display="${sanitized_video_min_res}–${sanitized_video_max_res}"
  local lang_primary="${ARR_LANG_PRIMARY:-en}"
  lang_primary="${lang_primary,,}"

  configarr_policy[resolution]="$resolution_display"
  configarr_policy[episode_cap_gb]="$sanitized_ep_max_gb"
  configarr_policy[episode_mbmin]="$episode_max_mbmin"
  configarr_policy[runtime]="$sanitized_runtime_min"
  configarr_policy[season_cap_gb]="$sanitized_season_max_gb"
  configarr_policy[language_primary]="$lang_primary"

  if ((english_only)); then
    configarr_policy[english_bias]="ON (score ${english_penalty_score})"
  else
    configarr_policy[english_bias]="OFF"
  fi
  if ((discourage_multi)); then
    configarr_policy[multi_penalty]="ON (score ${multi_score})"
  else
    configarr_policy[multi_penalty]="OFF"
  fi
  if ((penalize_hd_x265)); then
    configarr_policy[x265_penalty]="ON (score ${x265_score})"
  else
    configarr_policy[x265_penalty]="OFF"
  fi
  if ((strict_junk_block)); then
    if ((common_cf_exists)); then
      configarr_policy[junk_reinforce]="ON (score ${junk_score})"
    else
      configarr_policy[junk_reinforce]="ON (template missing)"
    fi
  else
    configarr_policy[junk_reinforce]="OFF"
  fi

  CONFIGARR_POLICY_RESOLUTION="${configarr_policy[resolution]}"
  CONFIGARR_POLICY_EP_GB="${configarr_policy[episode_cap_gb]}"
  CONFIGARR_POLICY_EP_MBMIN="${configarr_policy[episode_mbmin]}"
  CONFIGARR_POLICY_RUNTIME="${configarr_policy[runtime]}"
  CONFIGARR_POLICY_SEASON_GB="${configarr_policy[season_cap_gb]}"
  CONFIGARR_POLICY_LANG="${configarr_policy[language_primary]}"
  CONFIGARR_POLICY_ENGLISH="${configarr_policy[english_bias]}"
  CONFIGARR_POLICY_MULTI="${configarr_policy[multi_penalty]}"
  CONFIGARR_POLICY_X265="${configarr_policy[x265_penalty]}"
  CONFIGARR_POLICY_JUNK="${configarr_policy[junk_reinforce]}"
  export CONFIGARR_POLICY_RESOLUTION CONFIGARR_POLICY_EP_GB CONFIGARR_POLICY_EP_MBMIN \
    CONFIGARR_POLICY_RUNTIME CONFIGARR_POLICY_SEASON_GB CONFIGARR_POLICY_LANG \
    CONFIGARR_POLICY_ENGLISH CONFIGARR_POLICY_MULTI CONFIGARR_POLICY_X265 CONFIGARR_POLICY_JUNK

  msg "  Configarr policy: ${resolution_display}, cap ${sanitized_ep_max_gb} GB (~${episode_max_mbmin} MB/min)"
  msg "  Penalties: English=${configarr_policy[english_bias]}, Multi=${configarr_policy[multi_penalty]}, x265=${configarr_policy[x265_penalty]}, Junk=${configarr_policy[junk_reinforce]}"
}

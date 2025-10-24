# shellcheck shell=bash
# Purpose: Manage stack directory creation and collab-mode tracking utilities.
# Inputs: Uses ARR_STACK_DIR, ARR_DOCKER_DIR, ARR_DOCKER_SERVICES, ARR_PERMISSION_PROFILE, COLLAB_GROUP_WRITE_ENABLED.
# Outputs: Creates directories on disk and updates COLLAB_CREATED_MEDIA_DIRS tracking variable.
# Exit codes: Functions return non-zero when directory creation or permission enforcement fails.
if [[ -n "${__SETUP_DIRECTORIES_LOADED:-}" ]]; then
  return 0
fi
__SETUP_DIRECTORIES_LOADED=1

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

mkdirs() {
  if [[ -z "${ARR_STACK_DIR:-}" ]]; then
    die "ARR_STACK_DIR is required for directory setup"
  fi

  if [[ -z "${ARR_DOCKER_DIR:-}" ]]; then
    die "ARR_DOCKER_DIR is required for directory setup"
  fi

  if ! declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1 || ((${#ARR_DOCKER_SERVICES[@]} == 0)); then
    die "ARR_DOCKER_SERVICES must be defined before mkdirs runs"
  fi

  if [[ -z "${DATA_DIR_MODE:-}" ]]; then
    local fallback_mode=""

    if [[ -n "${ARR_DATA_DIR_MODE_OVERRIDE:-}" ]]; then
      if [[ "${ARR_DATA_DIR_MODE_OVERRIDE}" =~ ^[0-7]{3,4}$ ]]; then
        fallback_mode="${ARR_DATA_DIR_MODE_OVERRIDE}"
      else
        warn "ARR_DATA_DIR_MODE_OVERRIDE='${ARR_DATA_DIR_MODE_OVERRIDE}' is invalid (expected octal like 770); ignoring override"
      fi
    fi

    if [[ -z "$fallback_mode" ]]; then
      local profile="${ARR_PERMISSION_PROFILE:-strict}"
      case "$profile" in
        collab | collaborative)
          if [[ -z "${PGID:-}" || "${PGID:-}" == "0" ]]; then
            fallback_mode="750"
          else
            fallback_mode="770"
          fi
          ;;
        strict | *)
          fallback_mode="700"
          ;;
      esac
    fi

    if [[ -z "$fallback_mode" ]]; then
      die "DATA_DIR_MODE is required but could not be determined"
    fi

    DATA_DIR_MODE="$fallback_mode"
    export DATA_DIR_MODE
    warn "DATA_DIR_MODE was unset; defaulting to ${DATA_DIR_MODE}"
  fi

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

  local -a collab_setup_pairs=("${DOWNLOADS_DIR}|Downloads" "${COMPLETED_DIR}|Completed")
  local pair
  for pair in "${collab_setup_pairs[@]}"; do
    local dir="${pair%%|*}"
    local label="${pair#*|}"
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
  manage_media_dir "$MUSIC_DIR" "Music"

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


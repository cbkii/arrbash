# shellcheck shell=bash
# Applies idempotent migrations for auth config, env normalization, and collab perms
run_one_time_migrations() {
  local gluetun_340_marker="${ARR_DOCKER_DIR}/.gluetun-340-migration"
  if [[ ! -f "$gluetun_340_marker" ]]; then
    local auth_config="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
    if gluetun_version_requires_auth_config 2>/dev/null; then
      step "🔄 Upgrading to Gluetun 3.40+ auth model"

      if [[ -f "$auth_config" ]]; then
        local auth_backup=""
        auth_backup="${auth_config}.bak.$(date +%s)"
        if mv "$auth_config" "$auth_backup" 2>/dev/null; then
          msg "  Backed up existing auth config to ${auth_backup}"
        else
          rm -f "$auth_config" 2>/dev/null || true
        fi
      fi

      if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
        write_gluetun_control_assets
      fi

      : >"$gluetun_340_marker"
      ensure_file_mode "$gluetun_340_marker" 600
    fi
  fi

  if [[ -f "${ARR_ENV_FILE}" ]]; then
    local env_backup_created=0
    local env_backup_path=""

    # Captures a single backup of the env file before mutating entries
    ensure_env_backup() {
      if ((env_backup_created == 0)); then
        env_backup_path="${ARR_ENV_FILE}.bak.$(date +%s)"
        if cp "${ARR_ENV_FILE}" "$env_backup_path" 2>/dev/null; then
          chmod 600 "$env_backup_path" 2>/dev/null || true
          warn "Backed up existing .env to ${env_backup_path} before applying migrations"
          env_backup_created=1
        else
          warn "Unable to create backup of ${ARR_ENV_FILE} before migrations"
        fi
      fi
    }

    local existing_line existing_value existing_unescaped fixed_value sed_value

    existing_line="$(grep '^OPENVPN_USER=' "${ARR_ENV_FILE}" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#OPENVPN_USER=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      fixed_value="${existing_unescaped%+pmp}+pmp"
      if [[ "$fixed_value" != "$existing_unescaped" ]]; then
        ensure_env_backup
        sed_value="$(escape_sed_replacement "$fixed_value")"
        portable_sed "s|^OPENVPN_USER=.*$|OPENVPN_USER=${sed_value}|" "${ARR_ENV_FILE}"
        warn "OPENVPN_USER was missing '+pmp'; updated automatically in ${ARR_ENV_FILE}"
      fi
    fi

    existing_line="$(grep '^CADDY_BASIC_AUTH_HASH=' "${ARR_ENV_FILE}" | head -n1 || true)"
    if [[ -n "$existing_line" ]]; then
      existing_value="${existing_line#CADDY_BASIC_AUTH_HASH=}"
      existing_unescaped="$(unescape_env_value_from_compose "$existing_value")"
      if [[ "$existing_value" != "$existing_unescaped" ]]; then
        ensure_env_backup
        sed_value="$(escape_sed_replacement "$existing_unescaped")"
        portable_sed "s|^CADDY_BASIC_AUTH_HASH=.*$|CADDY_BASIC_AUTH_HASH=${sed_value}|" "${ARR_ENV_FILE}"
        warn "Normalized CADDY_BASIC_AUTH_HASH format for Docker Compose compatibility"
      fi
    fi

    unset -f ensure_env_backup || true
  fi

  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && "${COLLAB_GROUP_WRITE_ENABLED:-0}" == "1" ]]; then
    local collab_marker="${ARR_DOCKER_DIR}/.${STACK}-collab-v1"
    if [[ -d "${ARR_DOCKER_DIR}" && ! -e "${collab_marker}" ]]; then
      local collab_migrations=0
      local collab_failures=0
      local dir

      for dir in "${ARR_DOCKER_DIR}" "${ARR_DOCKER_DIR}"/*; do
        [[ -d "$dir" ]] || continue
        local mode
        mode="$(stat -c '%a' "$dir" 2>/dev/null || echo '')"
        if [[ "$mode" == "750" ]]; then
          if chmod "$DATA_DIR_MODE" "$dir" 2>/dev/null; then
            ((collab_migrations++))
          else
            warn "Could not migrate ${dir} to collaborative mode ${DATA_DIR_MODE}"
            collab_failures=1
          fi
        fi
      done

      if ((collab_migrations > 0)); then
        msg "Updated ${collab_migrations} directory(ies) to ${DATA_DIR_MODE} for the collaborative profile"
      fi

      if ((collab_failures == 0)); then
        : >"${collab_marker}" 2>/dev/null || true
        chmod 600 "${collab_marker}" 2>/dev/null || true
      fi
    fi
  fi
}

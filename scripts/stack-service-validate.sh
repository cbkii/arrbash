# shellcheck shell=bash
# Purpose: Validate generated compose artifacts and container images prior to startup.
# Inputs: Requires ARR_STACK_DIR, ARR_ENV_FILE, ARR_DOCKER_DIR, and Docker CLI availability.
# Outputs: Emits warnings/errors, writes temporary diagnostics, and may persist image pins in .env.
# Exit codes: Functions return non-zero when validation fails or dependencies are missing.
if [[ -n "${__SERVICE_VALIDATE_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_VALIDATE_LOADED=1

validate_generated_paths() {
  if [[ -z "${ARR_STACK_DIR:-}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    ARR_STACK_DIR="$(arr_stack_dir)"
  fi
  local compose_path
  compose_path="${COMPOSE_FILE:-${ARR_STACK_DIR}/docker-compose.yml}"
  local env_file
  env_file="$(arr_env_file)"
  local -a errors=()

  if [[ -z "${ARR_STACK_DIR:-}" ]]; then
    errors+=("Unable to resolve stack directory (ARR_STACK_DIR=${ARR_STACK_DIR:-})")
  elif [[ ! -d "$ARR_STACK_DIR" ]]; then
    errors+=("Stack directory missing: ${ARR_STACK_DIR}")
  fi

  if [[ -z "$compose_path" ]]; then
    errors+=("Compose file path could not be determined")
  else
    local compose_dir
    compose_dir="$(dirname "$compose_path")"
    if [[ ! -d "$compose_dir" ]]; then
      errors+=("Compose output directory missing: ${compose_dir}")
    fi
    if [[ ! -f "$compose_path" ]]; then
      errors+=("docker-compose.yml not found at ${compose_path}")
    elif [[ ! -s "$compose_path" ]]; then
      errors+=("docker-compose.yml at ${compose_path} is empty")
    fi
  fi

  if [[ -z "$env_file" ]]; then
    errors+=(".env file path could not be determined")
  else
    local env_dir
    env_dir="$(dirname "$env_file")"
    if [[ ! -d "$env_dir" ]]; then
      errors+=(".env output directory missing: ${env_dir}")
    fi
    if [[ ! -f "$env_file" ]]; then
      errors+=(".env not found at ${env_file}")
    elif [[ ! -s "$env_file" ]]; then
      errors+=(".env at ${env_file} is empty")
    fi
  fi

  if ((${#errors[@]} > 0)); then
    local message="Generated file validation failed:"
    local err
    for err in "${errors[@]}"; do
      message+=$'\n'"  - ${err}"
    done
    die "$message"
  fi
}

# Runs docker compose config to detect unresolved env placeholders before deploy
preflight_compose_interpolation() {
  local file="${COMPOSE_FILE:-${ARR_STACK_DIR}/docker-compose.yml}"
  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir "$log_dir"
  local warn_log="${log_dir}/compose-interpolation.log"

  local -a compose_cmd=()
  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    compose_cmd=("${DOCKER_COMPOSE_CMD[@]}")
  fi

  if ((${#compose_cmd[@]} == 0)); then
    if declare -f arr_resolve_compose_cmd >/dev/null 2>&1; then
      if ! arr_resolve_compose_cmd >/dev/null 2>&1; then
        warn "[ERROR] Docker Compose command unavailable; cannot validate interpolation."
        exit 1
      fi
    elif declare -f detect_compose_cmd >/dev/null 2>&1; then
      local compose_cmd_raw=""
      if compose_cmd_raw="$(detect_compose_cmd 2>/dev/null)"; then
        read -r -a DOCKER_COMPOSE_CMD <<<"$compose_cmd_raw"
      fi
    fi
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    compose_cmd=("${DOCKER_COMPOSE_CMD[@]}")
  fi

  if ((${#compose_cmd[@]} == 0)); then
    warn "[ERROR] Docker Compose command unavailable; cannot validate interpolation."
    exit 1
  fi

  if ! "${compose_cmd[@]}" -f "$file" config >/dev/null 2>"$warn_log"; then
    warn "[ERROR] docker compose config failed; see ${warn_log}"
    exit 1
  fi

  if LC_ALL=C grep -qE 'variable is not set' "$warn_log" 2>/dev/null; then
    warn "[ERROR] Unresolved Compose variables detected:"
    if LC_ALL=C grep -E 'variable is not set' "$warn_log" >/dev/null 2>&1; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        msg "  ${line}"
      done < <(LC_ALL=C grep -E 'variable is not set' "$warn_log")
    fi
    exit 1
  fi

  if [[ ! -s "$warn_log" ]]; then
    rm -f "$warn_log"
  fi
}

# Validates docker-compose.yml syntax and surfaces context on failure
validate_compose_or_die() {
  local file="${COMPOSE_FILE:-${ARR_STACK_DIR}/docker-compose.yml}"
  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir "$log_dir"
  local errlog="${log_dir}/compose.err"
  local configdump="${log_dir}/compose-config.json"

  local -a compose_cmd=()
  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
    compose_cmd=("${DOCKER_COMPOSE_CMD[@]}")
  fi

  if ((${#compose_cmd[@]} == 0)); then
    if declare -f arr_resolve_compose_cmd >/dev/null 2>&1; then
      if ! arr_resolve_compose_cmd >/dev/null 2>&1; then
        warn "[ERROR] Docker Compose command unavailable; cannot validate."
        exit 1
      fi
    elif declare -f detect_compose_cmd >/dev/null 2>&1; then
      local compose_cmd_raw=""
      if compose_cmd_raw="$(detect_compose_cmd 2>/dev/null)"; then
        read -r -a DOCKER_COMPOSE_CMD <<<"$compose_cmd_raw"
      fi
    fi
    if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
      compose_cmd=("${DOCKER_COMPOSE_CMD[@]}")
    fi
  fi

  if ((${#compose_cmd[@]} == 0)); then
    warn "[ERROR] Docker Compose command unavailable; cannot validate."
    exit 1
  fi

  if ! "${compose_cmd[@]}" -f "$file" config -q 2>"$errlog"; then
    warn "[ERROR] Compose validation failed; see ${errlog}"
    local line
    line="$(LC_ALL=C grep -oE 'line ([0-9]+)' "$errlog" | LC_ALL=C awk '{print $2}' | LC_ALL=C tail -1 || true)"
    if [[ -n "$line" && -r "$file" ]]; then
      local start=$((line - 5))
      local end=$((line + 5))
      ((start < 1)) && start=1
      msg "  Error context from docker-compose.yml:"
      nl -ba "$file" | LC_ALL=C sed -n "${start},${end}p" \
        | while IFS= read -r context_line; do
          [[ -z "$context_line" ]] && continue
          msg "    ${context_line}"
        done
    fi

    local services_tmp=""
    local services_err="${errlog}.services.err"
    if services_tmp="$(arr_mktemp_file "${errlog}.services.XXXXXX" "$NONSECRET_FILE_MODE")"; then
      if "${compose_cmd[@]}" -f "$file" config --services >"$services_tmp" 2>"$services_err"; then
        while IFS= read -r service; do
          [[ -z "$service" ]] && continue
          msg "  Checking service: ${service}"
          if ! "${compose_cmd[@]}" -f "$file" config "$service" >/dev/null 2>"${errlog}.${service}"; then
            warn "  Service ${service} has configuration errors:"
            if [[ -s "${errlog}.${service}" ]]; then
              while IFS= read -r service_err; do
                [[ -z "$service_err" ]] && continue
                msg "    ${service_err}"
              done <"${errlog}.${service}"
            else
              cat "${errlog}.${service}" 2>/dev/null || true
            fi
            rm -f "${errlog}.${service}" 2>/dev/null || true
          else
            rm -f "${errlog}.${service}" 2>/dev/null || true
          fi
        done <"$services_tmp"
      else
        warn "Failed to enumerate services for compose validation; see ${services_err}"
        cat "$services_err" 2>/dev/null || true
      fi
      arr_cleanup_temp_path "$services_tmp"
      rm -f "$services_err" 2>/dev/null || true
    else
      warn "Unable to create temporary file for compose service list"
    fi

    exit 1
  fi

  if ! "${compose_cmd[@]}" -f "$file" config --format=json >"$configdump" 2>"${errlog}.json"; then
    warn "Failed to generate JSON config dump at ${configdump}"
    cat "${errlog}.json" 2>/dev/null >&2 || true
    rm -f "$configdump"
  fi

  rm -f "${errlog}.json" 2>/dev/null || true

  rm -f "$errlog"
}

# Rewrites .env image variables when fallback tags are selected
update_env_image_var() {
  local var_name="$1"
  local new_value="$2"

  if [[ -z "$var_name" || -z "$new_value" ]]; then
    return
  fi

  printf -v "$var_name" '%s' "$new_value"

  if [[ -f "${ARR_ENV_FILE}" ]] && LC_ALL=C arr_run_sensitive_command grep -q "^${var_name}=" "${ARR_ENV_FILE}"; then
    if ! portable_sed "s|^${var_name}=.*|${var_name}=${new_value}|" "${ARR_ENV_FILE}"; then
      local sed_status=$?
      die "Failed to update ${var_name} in ${ARR_ENV_FILE}; portable_sed exited with status ${sed_status}"
    fi
  fi
}

# Uses docker manifest inspect to verify image availability
check_image_exists() {
  local image="$1"

  local timeout=10

  if ! command -v docker >/dev/null 2>&1; then
    return 2
  fi

  # Retry manifest lookup up to 3 times with simple backoff for flaky registries
  local attempt
  for attempt in 1 2 3; do
    if command -v timeout >/dev/null 2>&1; then
      timeout "$timeout" docker manifest inspect "$image" >/dev/null 2>&1 && return 0
    else
      docker manifest inspect "$image" >/dev/null 2>&1 && return 0
    fi
    if ((attempt < 3)); then
      sleep $((attempt * 2))
    fi
  done

  if docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

# Ensures all service images exist using declared tags without silent downgrades
validate_images() {
  step "🔍 Validating Docker images..."

  if ! command -v docker >/dev/null 2>&1; then
    warn "  Docker CLI unavailable; skipping image validation (sandbox)."
    return 0
  fi

  local image_vars=(
    GLUETUN_IMAGE
    QBITTORRENT_IMAGE
    SONARR_IMAGE
    RADARR_IMAGE
    PROWLARR_IMAGE
    BAZARR_IMAGE
    FLARR_IMAGE
  )

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    image_vars+=(CONFIGARR_IMAGE)
  fi

  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    image_vars+=(SABNZBD_IMAGE)
  fi

  local failed_images=()
  local -A downgrade_applied=()

  for var_name in "${image_vars[@]}"; do
    local image="${!var_name:-}"
    [[ -z "$image" ]] && continue

    msg "  Checking $image..."

    if check_image_exists "$image"; then
      msg "  ✅ Valid: $image"
      continue
    fi

    local base_image="$image"
    local tag=""
    if [[ "$image" == *:* ]]; then
      base_image="${image%:*}"
      tag="${image##*:}"
    fi

    if [[ "$tag" != "latest" && "$base_image" == lscr.io/linuxserver/* && "${ARR_ALLOW_TAG_DOWNGRADE:-0}" == "1" ]]; then
      local latest_image="${base_image}:latest"
      msg "    Trying opt-in fallback: $latest_image"

      if check_image_exists "$latest_image"; then
        msg "    ✅ Using fallback: $latest_image"
        downgrade_applied["$var_name"]="$latest_image"
        update_env_image_var "$var_name" "$latest_image"
        continue
      fi
    fi

    warn "  ❌ Could not validate: $image"
    failed_images+=("$image")
  done

  if ((${#failed_images[@]} > 0)); then
    warn "================================================"
    warn "Some images could not be validated:"
    for img in "${failed_images[@]}"; do
      warn "  - $img"
    done
    if [[ "${ARR_ALLOW_TAG_DOWNGRADE:-0}" != "1" ]]; then
      warn "Set ARR_ALLOW_TAG_DOWNGRADE=1 to permit temporary :latest fallback for LinuxServer images."
    fi
    warn "Check the image names and tags in .env or ${ARR_USERCONF_PATH}"
    warn "================================================"
    return 1
  fi

  if ((${#downgrade_applied[@]} > 0)); then
    local key
    for key in "${!downgrade_applied[@]}"; do
      msg "  ⤵️  ${key} downgraded to ${downgrade_applied[$key]} (ARR_ALLOW_TAG_DOWNGRADE=1)"
    done
  fi

  return 0
}

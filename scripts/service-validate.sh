# shellcheck shell=bash
# Purpose: Validate generated compose artifacts, Caddy configuration, and container images prior to startup.
# Inputs: Requires ARR_STACK_DIR, ARR_ENV_FILE, ARR_DOCKER_DIR, ENABLE_CADDY, and Docker CLI availability.
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

  if ! compose -f "$file" config >/dev/null 2>"$warn_log"; then
    printf '%s docker compose config failed; see %s\n' "$STACK_LABEL" "$warn_log" >&2
    exit 1
  fi

  if grep -qE 'variable is not set' "$warn_log" 2>/dev/null; then
    printf '%s unresolved Compose variables detected:\n' "$STACK_LABEL" >&2
    grep -E 'variable is not set' "$warn_log" >&2 || true
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

  if ! compose -f "$file" config -q 2>"$errlog"; then
    printf '%s Compose validation failed; see %s\n' "$STACK_LABEL" "$errlog"
    local line
    line="$(grep -oE 'line ([0-9]+)' "$errlog" | awk '{print $2}' | tail -1 || true)"
    if [[ -n "$line" && -r "$file" ]]; then
      local start=$((line - 5))
      local end=$((line + 5))
      ((start < 1)) && start=1
      printf '%s Error context from docker-compose.yml:\n' "$STACK_LABEL"
      nl -ba "$file" | sed -n "${start},${end}p"
    fi

    while IFS= read -r service; do
      [[ -z "$service" ]] && continue
      printf '%s Checking service: %s\n' "$STACK_LABEL" "$service"
      if ! compose -f "$file" config "$service" >/dev/null 2>"${errlog}.${service}"; then
        printf '%s Service %s has configuration errors:\n' "$STACK_LABEL" "$service"
        cat "${errlog}.${service}" 2>/dev/null || true
      else
        rm -f "${errlog}.${service}" 2>/dev/null || true
      fi
    done < <(compose -f "$file" config --services 2>/dev/null)

    exit 1
  fi

  if ! compose -f "$file" config --format=json >"$configdump" 2>"${errlog}.json"; then
    printf '%s Failed to generate JSON config dump at %s\n' "$STACK_LABEL" "$configdump" >&2
    cat "${errlog}.json" 2>/dev/null >&2 || true
    rm -f "$configdump"
  fi

  rm -f "${errlog}.json" 2>/dev/null || true

  rm -f "$errlog"
}

# Validates generated Caddyfile using docker image when proxying is enabled
validate_caddy_config() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🧪 Skipping Caddy validation (ENABLE_CADDY=0)"
    return 0
  fi

  local caddyfile="${ARR_DOCKER_DIR}/caddy/Caddyfile"

  if [[ ! -f "$caddyfile" ]]; then
    warn "Caddyfile not found at ${caddyfile}; skipping validation"
    return 0
  fi

  if [[ -z "${CADDY_IMAGE:-}" ]]; then
    warn "CADDY_IMAGE is unset; skipping Caddy config validation"
    return 0
  fi

  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir "$log_dir"
  local logfile="${log_dir}/caddy-validate.log"

  step "🧪 Validating Caddy configuration"

  local -a env_args=()
  if [[ -n "${LAN_IP:-}" ]]; then
    env_args+=(-e "LAN_IP=${LAN_IP}")
  fi
  if [[ -n "${LOCALHOST_IP:-}" ]]; then
    env_args+=(-e "LOCALHOST_IP=${LOCALHOST_IP}")
  fi

  local -a docker_args=(--rm)
  if ((${#env_args[@]} > 0)); then
    docker_args+=("${env_args[@]}")
  fi
  docker_args+=(-v "${caddyfile}:/etc/caddy/Caddyfile:ro" "${CADDY_IMAGE}" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile)

  if ! docker run "${docker_args[@]}" >"$logfile" 2>&1; then
    warn "Caddy validation failed; see ${logfile}"
    cat "$logfile"
    exit 1
  fi

  # shellcheck disable=SC2016  # literal ${ is intentional to flag unresolved placeholders
  if grep -q '\${' "$caddyfile"; then
    warn "Caddyfile contains unresolved variable references that might cause issues at runtime"
    # shellcheck disable=SC2016  # literal ${ is intentional to flag unresolved placeholders
    grep -n '\${' "$caddyfile"
  fi

  rm -f "$logfile"
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
    portable_sed "s|^${var_name}=.*|${var_name}=${new_value}|" "${ARR_ENV_FILE}"
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

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    image_vars+=(CADDY_IMAGE)
  fi

  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    image_vars+=(SABNZBD_IMAGE)
  fi

  if [[ "${LOCAL_DNS_STATE:-inactive}" == "active" ]]; then
    LOCALDNS_IMAGE="${LOCALDNS_IMAGE:-4km3/dnsmasq:2.90-r3}"
    image_vars+=(LOCALDNS_IMAGE)
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


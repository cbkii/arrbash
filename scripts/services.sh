# shellcheck shell=bash

# Confirms manual VueTorrent install has required assets before activation
vuetorrent_manual_is_complete() {
  local dir="$1"

  [[ -d "$dir" && -f "$dir/public/index.html" ]]
}

# Reads installed VueTorrent version from version.txt when available
vuetorrent_manual_version() {
  local dir="$1"

  if [[ -f "$dir/version.txt" ]]; then
    head -n1 "$dir/version.txt" 2>/dev/null | tr -d '\r\n'
  fi
}

vuetorrent_manual_unavailable() {
  # shellcheck disable=SC2034
  VUETORRENT_VERSION=""
  # shellcheck disable=SC2034
  VUETORRENT_ALT_ENABLED=0
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_LEVEL="warn"
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_MESSAGE="Manual VueTorrent install unavailable; qBittorrent default UI active."
  write_qbt_config
}

# Manages VueTorrent deployment, choosing LSIO mod or manual download as configured
install_vuetorrent() {
  local manual_dir="${ARR_DOCKER_DIR}/qbittorrent/vuetorrent"
  if [[ "${VUETORRENT_MODE}" != "manual" ]]; then
    step "Ensuring VueTorrent (LSIO Docker mod)"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_VERSION=""
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent via LSIO Docker mod (WebUI root ${VUETORRENT_ROOT})."
    if [[ -d "$manual_dir" ]]; then
      rm -rf "$manual_dir" 2>/dev/null || warn "Could not remove manual VueTorrent directory at ${manual_dir}"
    fi
    return 0
  fi

  step "Ensuring VueTorrent (manual mode)"

  if vuetorrent_manual_is_complete "$manual_dir"; then
    local version
    version="$(vuetorrent_manual_version "$manual_dir")"
    # shellcheck disable=SC2034
    VUETORRENT_VERSION="$version"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    if [[ -n "$version" ]]; then
      msg "  VueTorrent already present at ${manual_dir} (version ${version})"
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT} (version ${version})."
    else
      msg "  VueTorrent already present at ${manual_dir}"
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT}."
    fi
    chown -R "${PUID}:${PGID}" "$manual_dir" 2>/dev/null || true
    return 0
  fi

  if ! check_dependencies curl unzip sha256sum; then
    warn "Missing curl, unzip, or sha256sum; skipping VueTorrent download"
    vuetorrent_manual_unavailable
    return 0
  fi

  local download_url
  if [[ -n "${VUETORRENT_DOWNLOAD_URL:-}" ]]; then
    download_url="${VUETORRENT_DOWNLOAD_URL}"
  else
    download_url="https://github.com/VueTorrent/VueTorrent/releases/latest/download/vuetorrent.zip"
  fi

  local tmp_archive
  if ! tmp_archive="$(arr_mktemp_file "/tmp/vuetorrent.download.XXXXXX" "$NONSECRET_FILE_MODE")"; then
    warn "Unable to create temporary file for VueTorrent archive"
    vuetorrent_manual_unavailable
    return 0
  fi

  local -a curl_args=(
    --fail
    --location
    --silent
    --show-error
    --output "$tmp_archive"
  )

  if ! curl "${curl_args[@]}" "$download_url" >/dev/null 2>&1; then
    local curl_status=$?
    rm -f "$tmp_archive" 2>/dev/null || true
    warn "Failed to download VueTorrent archive (curl exit status ${curl_status})"
    vuetorrent_manual_unavailable
    return 0
  fi

  local archive_sha
  archive_sha="$(sha256sum "$tmp_archive" 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$archive_sha" ]]; then
    msg "  VueTorrent archive SHA256 ${archive_sha}"
  fi

  if [[ -n "${VUETORRENT_SHA256:-}" && "$archive_sha" != "${VUETORRENT_SHA256}" ]]; then
    rm -f "$tmp_archive" 2>/dev/null || true
    warn "Downloaded VueTorrent archive checksum mismatch"
    vuetorrent_manual_unavailable
    return 0
  fi

  local extract_dir
  if ! extract_dir="$(arr_mktemp_dir "/tmp/vuetorrent.extract.XXXXXX")"; then
    rm -f "$tmp_archive" 2>/dev/null || true
    warn "Unable to create extraction directory for VueTorrent"
    vuetorrent_manual_unavailable
    return 0
  fi

  if ! unzip -qo "$tmp_archive" -d "$extract_dir"; then
    rm -f "$tmp_archive" 2>/dev/null || true
    rm -rf "$extract_dir" 2>/dev/null || true
    warn "Failed to unzip VueTorrent archive"
    vuetorrent_manual_unavailable
    return 0
  fi

  rm -f "$tmp_archive" 2>/dev/null || true

  local source_root="$extract_dir"
  if [[ ! -f "$source_root/public/index.html" ]]; then
    local nested_public
    nested_public="$(find "$extract_dir" -type f -path '*/public/index.html' -print -quit 2>/dev/null || printf '')"
    if [[ -n "$nested_public" ]]; then
      source_root="$(dirname "$(dirname "$nested_public")")"
    fi
  fi

  if [[ ! -f "$source_root/public/index.html" ]]; then
    rm -rf "$extract_dir" 2>/dev/null || true
    warn "VueTorrent archive missing public/index.html"
    vuetorrent_manual_unavailable
    return 0
  fi

  local staging_dir
  if ! staging_dir="$(arr_mktemp_dir "/tmp/vuetorrent.staging.XXXXXX")"; then
    rm -rf "$extract_dir" 2>/dev/null || true
    warn "Unable to stage VueTorrent files"
    vuetorrent_manual_unavailable
    return 0
  fi

  if ! cp -a "$source_root"/. "$staging_dir"/; then
    rm -rf "$extract_dir" "$staging_dir" 2>/dev/null || true
    warn "Failed to prepare VueTorrent files"
    vuetorrent_manual_unavailable
    return 0
  fi

  rm -rf "$extract_dir" 2>/dev/null || true

  ensure_dir "${ARR_DOCKER_DIR}/qbittorrent"

  local backup_dir=""
  if [[ -d "$manual_dir" ]]; then
    backup_dir="${manual_dir}.bak.$$"
    if ! mv "$manual_dir" "$backup_dir"; then
      rm -rf "$staging_dir" 2>/dev/null || true
      warn "Unable to move existing VueTorrent directory"
      vuetorrent_manual_unavailable
      return 0
    fi
  fi

  if ! mv "$staging_dir" "$manual_dir"; then
    rm -rf "$staging_dir" 2>/dev/null || true
    if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
      mv "$backup_dir" "$manual_dir" 2>/dev/null || rm -rf "$backup_dir" 2>/dev/null || true
    fi
    warn "Failed to activate VueTorrent manual install"
    vuetorrent_manual_unavailable
    return 0
  fi

  if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
    rm -rf "$backup_dir" 2>/dev/null || true
  fi

  chown -R "${PUID}:${PGID}" "$manual_dir" 2>/dev/null || true

  local version
  version="$(vuetorrent_manual_version "$manual_dir")"
  # shellcheck disable=SC2034
  VUETORRENT_VERSION="$version"
  # shellcheck disable=SC2034
  VUETORRENT_ALT_ENABLED=1
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_LEVEL="msg"
  if [[ -n "$version" ]]; then
    msg "  VueTorrent installed at ${manual_dir} (version ${version})"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT} (version ${version})."
  else
    msg "  VueTorrent installed at ${manual_dir}"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT}."
  fi
}

# Maps logical service names to compose container identifiers (handles overrides)
service_container_name() {
  local service="$1"
  case "$service" in
    local_dns)
      printf '%s' "arr_local_dns"
      ;;
    *)
      printf '%s' "$service"
      ;;
  esac
}

restart_stack_service() {
  local service="$1"

  if [[ -z "$service" ]]; then
    return 0
  fi

  if ! declare -f compose >/dev/null 2>&1; then
    warn "compose helper unavailable; cannot restart ${service}"
    return 1
  fi

  if ! compose restart "$service" >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

service_sab_helper_path() {
  local helper="${ARR_STACK_DIR}/scripts/sab-helper.sh"
  if [[ -x "$helper" ]]; then
    printf '%s\n' "$helper"
    return 0
  fi
  helper="${REPO_ROOT}/scripts/sab-helper.sh"
  if [[ -x "$helper" ]]; then
    printf '%s\n' "$helper"
    return 0
  fi
  return 1
}

service_start_sabnzbd() {
  [[ "${SABNZBD_ENABLED:-0}" == "1" ]] || return 0
  msg "[sabnzbd] Enabled (startup managed via docker compose)."
}

service_health_sabnzbd() {
  [[ "${SABNZBD_ENABLED:-0}" == "1" ]] || return 0
  local helper
  if ! helper="$(service_sab_helper_path)"; then
    warn "[sabnzbd] Helper script not found; skipping health check"
    return 0
  fi
  local version
  if version="$($helper version 2>/dev/null)"; then
    msg "[sabnzbd] API reachable (${version})"
  else
    warn "[sabnzbd] Health check failed (verify SABNZBD_HOST/SABNZBD_PORT or container status)"
  fi
}

arr_effective_project_name() {
  local project="${COMPOSE_PROJECT_NAME:-}"

  if [[ -n "$project" ]]; then
    printf '%s\n' "$project"
    return 0
  fi

  local -a env_candidates=()
  if [[ -n "${ARR_ENV_FILE:-}" ]]; then
    env_candidates+=("${ARR_ENV_FILE}")
  fi
  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    local stack_env="${ARR_STACK_DIR}/.env"
    if [[ -z "${ARR_ENV_FILE:-}" || "${ARR_ENV_FILE}" != "$stack_env" ]]; then
      env_candidates+=("$stack_env")
    fi
  fi

  local candidate value
  for candidate in "${env_candidates[@]}"; do
    if [[ -f "$candidate" ]] && value="$(get_env_kv "COMPOSE_PROJECT_NAME" "$candidate" 2>/dev/null)"; then
      project="$value"
      break
    fi
  done

  if [[ -z "$project" && -n "${ARR_STACK_DIR:-}" ]]; then
    local compose_file="${ARR_STACK_DIR}/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
      local raw
      raw="$(grep -m1 -E '^[[:space:]]*name:[[:space:]]*' "$compose_file" 2>/dev/null || printf '')"
      raw="${raw#*:}"
      raw="${raw%%#*}"
      raw="${raw//\"/}"
      raw="${raw//\'/}"
      if [[ -n "$raw" ]]; then
        project="$(printf '%s\n' "$raw" | xargs 2>/dev/null || printf '%s' "$raw")"
      fi
    fi
  fi

  if [[ -z "$project" ]]; then
    project="arrstack"
  fi

  printf '%s\n' "$project"
}

# Stops existing stack containers and removes stale temp artifacts without nuking volumes
safe_cleanup() {
  step "🧹 Safely stopping existing services..."

  if [[ -f "${ARR_STACK_DIR}/docker-compose.yml" ]]; then
    compose stop 2>/dev/null || true
    sleep 5
    compose down --remove-orphans 2>/dev/null || true
  fi

  local temp_files=(
    "${ARR_DOCKER_DIR}/gluetun/forwarded_port"
    "${ARR_DOCKER_DIR}/gluetun/forwarded_port.json"
    "${ARR_DOCKER_DIR}/gluetun/port-forwarding.json"
    "${ARR_DOCKER_DIR}/qbittorrent/qBittorrent/BT_backup/.cleaning"
  )

  local file
  for file in "${temp_files[@]}"; do
    rm -f "$file" 2>/dev/null || true
  done

  local project_label
  project_label="$(arr_effective_project_name 2>/dev/null || printf 'arrstack')"

  docker ps -a --filter "label=com.docker.compose.project=${project_label}" --format "{{.ID}}" \
    | xargs -r docker rm -f 2>/dev/null || true
}

# Runs docker compose config to detect unresolved env placeholders before deploy
preflight_compose_interpolation() {
  local file="${COMPOSE_FILE:-${ARR_STACK_DIR}/docker-compose.yml}"
  local log_dir="${ARR_LOG_DIR:-${ARR_STACK_DIR}/logs}"
  ensure_dir "$log_dir"
  local warn_log="${log_dir}/compose-interpolation.log"

  if ! compose -f "$file" config >/dev/null 2>"$warn_log"; then
    echo "[arrstack] docker compose config failed; see ${warn_log}" >&2
    exit 1
  fi

  if grep -qE 'variable is not set' "$warn_log" 2>/dev/null; then
    echo "[arrstack] unresolved Compose variables detected:" >&2
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
  local log_dir="${ARR_STACK_DIR}/logs"
  ensure_dir "$log_dir"
  local errlog="${log_dir}/compose.err"
  local configdump="${log_dir}/compose-config.json"

  if ! compose -f "$file" config -q 2>"$errlog"; then
    echo "[arrstack] Compose validation failed; see $errlog"
    local line
    line="$(grep -oE 'line ([0-9]+)' "$errlog" | awk '{print $2}' | tail -1 || true)"
    if [[ -n "$line" && -r "$file" ]]; then
      local start=$((line - 5))
      local end=$((line + 5))
      ((start < 1)) && start=1
      echo "[arrstack] Error context from docker-compose.yml:"
      nl -ba "$file" | sed -n "${start},${end}p"
    fi

    while IFS= read -r service; do
      [[ -z "$service" ]] && continue
      echo "[arrstack] Checking service: $service"
      if ! compose -f "$file" config "$service" >/dev/null 2>"${errlog}.${service}"; then
        echo "[arrstack] Service $service has configuration errors:"
        cat "${errlog}.${service}" 2>/dev/null || true
      else
        rm -f "${errlog}.${service}" 2>/dev/null || true
      fi
    done < <(compose -f "$file" config --services 2>/dev/null)

    exit 1
  fi

  if ! compose -f "$file" config --format=json >"$configdump" 2>"${errlog}.json"; then
    echo "[arrstack] Failed to generate JSON config dump at $configdump" >&2
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

  local log_dir="${ARR_LOG_DIR:-${ARR_STACK_DIR}/logs}"
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

  if grep -q '\${' "$caddyfile"; then
    warn "Caddyfile contains unresolved variable references that might cause issues at runtime"
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

  if [[ -f "${ARR_ENV_FILE}" ]] && grep -q "^${var_name}=" "${ARR_ENV_FILE}"; then
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

  if command -v timeout >/dev/null 2>&1; then
    if timeout "$timeout" docker manifest inspect "$image" >/dev/null 2>&1; then
      return 0
    fi
  else
    if docker manifest inspect "$image" >/dev/null 2>&1; then
      return 0
    fi
  fi

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

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" && "${LOCAL_DNS_SERVICE_ENABLED:-0}" == "1" ]]; then
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

# Starts individual compose service and prints any non-empty output
compose_up_service() {
  local service="$1"
  local output=""

  msg "  Starting $service..."
  if output="$(compose up -d "$service" 2>&1)"; then
    if [[ "$output" == *"is up-to-date"* ]]; then
      msg "  $service is up-to-date"
    elif [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  else
    warn "  Failed to start $service"
    if [[ -n "$output" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done <<<"$output"
    fi
  fi
  sleep 2
}

# Captures qBittorrent temporary password from logs and persists to .env
sync_qbt_password_from_logs() {
  if [[ "${QBT_PASS}" != "adminadmin" ]]; then
    return
  fi

  msg "  Detecting qBittorrent temporary password..."
  local attempts=0
  local detected=""

  while ((attempts < 60)); do
    detected="$(docker logs qbittorrent 2>&1 | grep -i "temporary password" | tail -1 | sed 's/.*temporary password[^:]*: *//' | awk '{print $1}' || true)"
    if [[ -n "$detected" ]]; then
      QBT_PASS="$detected"
      persist_env_var QBT_PASS "${QBT_PASS}"
      msg "  Saved qBittorrent temporary password to .env (QBT_PASS)"
      return
    fi
    sleep 2
    ((attempts++))
  done

  warn "  Unable to automatically determine the qBittorrent password. Update QBT_PASS in .env manually."
}

# Checks if a default route exists via a VPN tunnel interface (configurable pattern)
arr_gluetun_tunnel_route_present() {
  local name="${1:-gluetun}"
  local iface_pattern="${2:-dev (tun[0-9]+|wg[0-9]+)}"

  docker exec "$name" sh -c "ip -4 route show default 2>/dev/null | grep -Eq '$iface_pattern'" >/dev/null 2>&1
}

arr_gluetun_connectivity_probe() {
  local name="${1:-gluetun}"
  shift || true

  local -a urls=()
  if (($# == 0)); then
    urls=(
      "https://api.ipify.org"
      "https://ipconfig.io/ip"
      "https://1.1.1.1/cdn-cgi/trace"
    )
  else
    urls=("$@")
  fi

  local url=""
  ARR_GLUETUN_CONNECTIVITY_LAST_URL=""

  for url in "${urls[@]}"; do
    if docker exec "$name" sh -c "curl -fsS --connect-timeout 5 --max-time 8 '$url' >/dev/null" >/dev/null 2>&1; then
      ARR_GLUETUN_CONNECTIVITY_LAST_URL="$url"
      return 0
    fi
  done

  return 1
}

arr_wait_for_gluetun_ready() {
  local name="${1:-gluetun}"
  local max_wait="${2:-150}"
  local check_interval="${3:-5}"

  ARR_GLUETUN_FAILURE_REASON=""

  if ! command -v docker >/dev/null 2>&1; then
    ARR_GLUETUN_FAILURE_REASON="docker binary not available"
    return 1
  fi

  msg "Waiting for Gluetun readiness (container, health, tunnel, connectivity)..."

  local elapsed=0
  local last_state=""
  local last_health=""
  local reported_no_healthcheck=0
  local tunnel_announced=0
  local tunnel_warned=0
  local connectivity_warned=0

  while ((elapsed < max_wait)); do
    local inspect_output=""
    inspect_output="$(docker inspect "$name" --format '{{.State.Status}} {{if .State.Health}}true {{.State.Health.Status}}{{else}}false none{{end}}' 2>/dev/null || true)"

    if [[ -z "$inspect_output" ]]; then
      ARR_GLUETUN_FAILURE_REASON="Gluetun container '${name}' not found"
      warn "  Gluetun container '${name}' not found."
      return 1
    fi

    local state has_health health_status
    read -r state has_health health_status <<<"$inspect_output"

    if [[ "$state" != "running" ]]; then
      case "$state" in
        restarting)
          if [[ "$last_state" != "$state" ]]; then
            warn "  Gluetun is restarting; waiting for stability..."
          fi
          ;;
        created|starting)
          if [[ "$last_state" != "$state" ]]; then
            msg "  Gluetun container reported state '${state}'. Waiting for it to run..."
          fi
          ;;
        exited|dead|removing|paused)
          ARR_GLUETUN_FAILURE_REASON="Gluetun state '${state}' (expected running)"
          warn "  Gluetun state is '${state}' (expected running)."
          return 1
          ;;
        *)
          ARR_GLUETUN_FAILURE_REASON="Gluetun state '${state}' (expected running)"
          warn "  Gluetun state is '${state}' (expected running)."
          return 1
          ;;
      esac

      last_state="$state"

      local remaining=$((max_wait - elapsed))
      local sleep_for=$check_interval
      if ((remaining < sleep_for)); then
        sleep_for=$remaining
      fi
      sleep "$sleep_for"
      elapsed=$((elapsed + sleep_for))
      continue
    fi

    if [[ "$last_state" != "running" ]]; then
      msg "  ✅ Gluetun container is running"
    fi
    last_state="$state"

    if [[ "$has_health" == "true" ]]; then
      case "$health_status" in
        healthy)
          if [[ "$last_health" != "healthy" ]]; then
            msg "  ✅ Gluetun healthcheck reports healthy"
          fi
          ;;
        starting)
          if [[ "$last_health" != "starting" ]]; then
            msg "  Gluetun healthcheck starting; waiting for healthy signal..."
          fi
          last_health="$health_status"

          local remaining=$((max_wait - elapsed))
          local sleep_for=$check_interval
          if ((remaining < sleep_for)); then
            sleep_for=$remaining
          fi
          sleep "$sleep_for"
          elapsed=$((elapsed + sleep_for))
          continue
          ;;
        *)
          ARR_GLUETUN_FAILURE_REASON="Gluetun healthcheck reported '${health_status}'"
          warn "  Gluetun healthcheck reported '${health_status}'."
          return 1
          ;;
      esac
    else
      if ((reported_no_healthcheck == 0)); then
        msg "  Gluetun container has no Docker healthcheck; relying on tunnel/connectivity probes."
        reported_no_healthcheck=1
      fi
    fi
    last_health="$health_status"

    if arr_gluetun_tunnel_route_present "$name"; then
      if ((tunnel_announced == 0)); then
        msg "  ✅ VPN tunnel interface (tun0/wg0) present"
        tunnel_announced=1
      fi
    else
      if ((tunnel_warned == 0)); then
        warn "  Waiting for VPN tunnel interface (tun0/wg0) inside Gluetun..."
        tunnel_warned=1
      fi

      local remaining=$((max_wait - elapsed))
      local sleep_for=$check_interval
      if ((remaining < sleep_for)); then
        sleep_for=$remaining
      fi
      sleep "$sleep_for"
      elapsed=$((elapsed + sleep_for))
      continue
    fi

    if arr_gluetun_connectivity_probe "$name"; then
      local probe_url="${ARR_GLUETUN_CONNECTIVITY_LAST_URL:-unknown}"
      msg "  ✅ VPN connectivity confirmed via ${probe_url}"
      return 0
    fi

    if ((connectivity_warned == 0)); then
      warn "  Waiting for outbound connectivity through Gluetun tunnel..."
      connectivity_warned=1
    fi

    local remaining=$((max_wait - elapsed))
    local sleep_for=$check_interval
    if ((remaining < sleep_for)); then
      sleep_for=$remaining
    fi
    sleep "$sleep_for"
    elapsed=$((elapsed + sleep_for))
  done

  ARR_GLUETUN_FAILURE_REASON="VPN connectivity not verified within ${max_wait}s"
  warn "  Gluetun did not become ready within ${max_wait}s."
  return 1
}

# Launches VPN auto-reconnect daemon when configured and available
stop_existing_vpn_auto_reconnect_workers() {
  local daemon_path="$1"
  local pid_file="$2"

  if [[ -z "$daemon_path" ]]; then
    return 0
  fi

  local -a candidate_pids=()
  local pid

  if [[ -n "$pid_file" && -f "$pid_file" ]]; then
    pid="$(cat "$pid_file" 2>/dev/null || printf '')"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      candidate_pids+=("$pid")
    fi
  fi

  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r pid; do
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        candidate_pids+=("$pid")
      fi
    done < <(pgrep -f -- "$daemon_path" 2>/dev/null || true)
  else
    while IFS= read -r pid; do
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        candidate_pids+=("$pid")
      fi
    done < <(ps -eo pid,command 2>/dev/null | awk -v path="$daemon_path" 'index($0, path) {print $1}' || true)
  fi

  if [[ ${#candidate_pids[@]} -eq 0 ]]; then
    if [[ -n "$pid_file" ]]; then
      rm -f "$pid_file" 2>/dev/null || true
    fi
    return 0
  fi

  # Deduplicate candidate_pids using associative array for O(n) complexity
  declare -A seen_pids=()
  for pid in "${candidate_pids[@]}"; do
    seen_pids["$pid"]=1
  done
  candidate_pids=("${!seen_pids[@]}")

  msg "[vpn-auto] Stopping existing auto-reconnect worker(s): ${candidate_pids[*]}"

  local attempt
  for pid in "${candidate_pids[@]}"; do
    if kill "$pid" 2>/dev/null; then
      for attempt in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 1
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
  done

  if [[ -n "$pid_file" ]]; then
    rm -f "$pid_file" 2>/dev/null || true
  fi

  return 0
}

start_vpn_auto_reconnect_if_enabled() {
  if ! declare -f vpn_auto_reconnect_is_enabled >/dev/null 2>&1; then
    return 0
  fi

  if ! vpn_auto_reconnect_is_enabled; then
    msg "[vpn-auto] Auto-reconnect disabled (VPN_AUTO_RECONNECT_ENABLED=${VPN_AUTO_RECONNECT_ENABLED:-0})"
    return 0
  fi

  local daemon_path="${ARR_STACK_DIR}/scripts/vpn-auto-reconnect-daemon.sh"
  if [[ ! -x "$daemon_path" ]]; then
    warn "[vpn-auto] Auto-reconnect daemon missing at ${daemon_path}"
    return 1
  fi

  local state_dir pid_file log_file
  state_dir="$(vpn_auto_reconnect_state_dir 2>/dev/null || printf '')"
  if [[ -z "$state_dir" ]]; then
    state_dir="${ARR_DOCKER_DIR}/gluetun/auto-reconnect"
  fi
  ensure_dir_mode "$state_dir" "$DATA_DIR_MODE"
  pid_file="${state_dir}/daemon.pid"
  log_file="${state_dir}/daemon.log"

  stop_existing_vpn_auto_reconnect_workers "$daemon_path" "$pid_file"

  msg "[vpn-auto] Launching auto-reconnect daemon"

  touch "$log_file" 2>/dev/null || true
  ensure_nonsecret_file_mode "$log_file"

  if nohup "$daemon_path" >>"$log_file" 2>&1 & then
    local pid=$!
    printf '%s\n' "$pid" >"$pid_file"
    ensure_secret_file_mode "$pid_file"
    msg "[vpn-auto] Daemon started (pid ${pid})"
  else
    warn "[vpn-auto] Failed to start auto-reconnect daemon"
  fi
}

# Prints container runtime status and port-forward summary for quick health glance
show_service_status() {
  msg "Service status summary:"
  local -a services=(gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr)
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    services+=(caddy)
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" && "${LOCAL_DNS_SERVICE_ENABLED:-0}" == "1" ]]; then
    services+=(local_dns)
  fi
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    services+=(sabnzbd)
  fi

  for service in "${services[@]}"; do
    local container
    container="$(service_container_name "$service")"
    local status
    status="$(docker inspect "$container" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
    printf '  %-15s: %s\n' "$service" "$status"
  done

  if [[ -f "${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_STATE_FILE:-pf-state.json}" ]]; then
    local pf_state="${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_STATE_FILE:-pf-state.json}"
    local pf_status
    pf_status="$(grep -Eo '"status"[[:space:]]*:[[:space:]]*"[^"]+"' "$pf_state" 2>/dev/null | head -n1 | sed 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || true)"
    local pf_port
    pf_port="$(grep -Eo '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$pf_state" 2>/dev/null | head -n1 | sed 's/.*"port"[[:space:]]*:[[:space:]]*//' || true)"
    if [[ -n "$pf_status" ]]; then
      msg "[pf] Current PF status: ${pf_status} (port=${pf_port:-0})"
    fi
  fi
}

# Disables Docker's userland proxy to let dnsmasq bind :53 reliably
ensure_docker_userland_proxy_disabled() {
  if [[ "${ENABLE_LOCAL_DNS:-0}" != "1" || "${LOCAL_DNS_SERVICE_ENABLED:-0}" != "1" ]]; then
    msg "[dns] Skipping userland-proxy update (local DNS inactive)"
    return 0
  fi

  local conf="${ARR_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
  local conf_dir
  conf_dir="$(dirname "$conf")"

  local merge_tool_preference="${ARR_DAEMON_JSON_TOOL:-}"
  local merge_tool=""
  if [[ "$merge_tool_preference" == "python" ]] && command -v python3 >/dev/null 2>&1; then
    merge_tool="python"
  elif [[ "$merge_tool_preference" == "jq" ]] && command -v jq >/dev/null 2>&1; then
    merge_tool="jq"
  elif command -v jq >/dev/null 2>&1; then
    merge_tool="jq"
  elif command -v python3 >/dev/null 2>&1; then
    merge_tool="python"
  else
    warn "[dns] jq or python3 is required to edit ${conf}. Install one of them and rerun."
    return 1
  fi

  if [[ ! -e "$conf" ]]; then
    if [[ ! -d "$conf_dir" ]] && ! mkdir -p "$conf_dir"; then
      warn "[dns] Failed to create ${conf_dir}"
      return 1
    fi
  fi

  if [[ -f "$conf" && ! -w "$conf" && ! -w "$conf_dir" ]]; then
    warn "[dns] Docker daemon.json requires root to modify."
    warn "[dns] Run with sudo or set {\"userland-proxy\": false} in ${conf} manually."
    return 1
  fi

  if [[ "$merge_tool" == "jq" && -s "$conf" ]]; then
    if jq -e '."userland-proxy" == false' "$conf" >/dev/null 2>&1; then
      msg "[dns] Docker userland-proxy already disabled"
      return 0
    fi
    if ! jq empty "$conf" >/dev/null 2>&1; then
      warn "[dns] ${conf} contains invalid JSON; fix the file manually before continuing."
      return 1
    fi
  elif [[ "$merge_tool" == "python" && -s "$conf" ]]; then
    local python_status=0
    python3 - "$conf" <<'PY' || python_status=$?
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    data = json.loads(path.read_text()) if path.stat().st_size else {}
except json.JSONDecodeError as exc:  # pragma: no cover
    print(f"Invalid JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if data.get("userland-proxy") is False:
    sys.exit(0)

sys.exit(1)
PY
    case "$python_status" in
      0)
        msg "[dns] Docker userland-proxy already disabled"
        return 0
        ;;
      1)
        :
        ;;
      *)
        warn "[dns] ${conf} contains invalid JSON; fix the file manually before continuing."
        return 1
        ;;
    esac
  fi

  local backup
  backup="${conf}.arrstack.$(date +%Y%m%d-%H%M%S).bak"
  if [[ -f "$conf" ]]; then
    if ! cp -p "$conf" "$backup"; then
      warn "[dns] Failed to create backup at ${backup}"
      return 1
    fi
  else
    printf '{}\n' >"$backup" 2>/dev/null || true
  fi

  local tmp
  if ! tmp="$(mktemp)"; then
    warn "[dns] Failed to create temporary file for ${conf}"
    return 1
  fi

  local merge_status=0
  if [[ "$merge_tool" == "jq" ]]; then
    if [[ -s "$conf" ]]; then
      jq -S '."userland-proxy" = false' "$conf" >"$tmp" 2>/dev/null || merge_status=$?
    else
      printf '{\n  "userland-proxy": false\n}\n' >"$tmp" || merge_status=1
    fi
  else
    python3 - "$conf" "$tmp" <<'PY' || merge_status=$?
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])

data = {}
if source.exists() and source.stat().st_size:
    try:
        data = json.loads(source.read_text())
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}", file=sys.stderr)
        sys.exit(2)

data["userland-proxy"] = False

dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
  fi

  if ((merge_status != 0)); then
    rm -f "$tmp" 2>/dev/null || true
    warn "[dns] Failed to merge userland-proxy setting into ${conf}"
    warn "[dns] Backup saved at ${backup}"
    return 1
  fi

  if ! mv "$tmp" "$conf"; then
    rm -f "$tmp" 2>/dev/null || true
    warn "[dns] Failed to replace ${conf}. Backup saved at ${backup}"
    return 1
  fi
  if [[ -f "$backup" ]]; then
    chmod --reference "$backup" "$conf" 2>/dev/null || ensure_nonsecret_file_mode "$conf"
  else
    ensure_nonsecret_file_mode "$conf"
  fi

  local restart_allowed=0
  if [[ "${ASSUME_YES:-0}" == "1" || "${ARR_HOST_RESTART_OK:-0}" == "1" ]]; then
    restart_allowed=1
  fi

  if ((restart_allowed)); then
    if command -v systemctl >/dev/null 2>&1; then
      if ! systemctl restart docker >/dev/null 2>&1; then
        warn "[dns] Failed to restart Docker; run 'sudo systemctl restart docker' manually."
        return 1
      fi
      if ! systemctl is-active --quiet docker; then
        warn "[dns] Docker failed to report healthy after restart; inspect 'journalctl -xeu docker'."
        return 1
      fi
      msg "[dns] Docker daemon restarted to apply userland-proxy change"
    elif command -v service >/dev/null 2>&1; then
      if ! service docker restart >/dev/null 2>&1; then
        warn "[dns] Failed to restart Docker; run 'sudo service docker restart' manually."
        return 1
      fi
      msg "[dns] Docker daemon restarted to apply userland-proxy change"
    else
      warn "[dns] Docker restart command not found; restart the daemon manually to apply changes."
    fi
  else
    warn "[dns] Docker restart required to apply userland-proxy change. Re-run with --yes or ARR_HOST_RESTART_OK=1."
  fi

  msg "[dns] Docker userland-proxy set to false"
  return 0
}

# Orchestrates service startup: cleanup, validation, image pulls, health waits, summaries
start_stack() {
  step "Starting service stack"

  cd "${ARR_STACK_DIR}" || die "Failed to change to ${ARR_STACK_DIR}"

  arr_clear_run_failure || true

  safe_cleanup

  if ! ensure_docker_userland_proxy_disabled; then
    return 1
  fi

  if ! validate_images; then
    return 1
  fi

  install_vuetorrent

  msg "Starting Gluetun VPN container..."
  local gluetun_output=""
  if ! gluetun_output="$(compose up -d gluetun 2>&1)"; then
    warn "Failed to start Gluetun via docker compose"
    if [[ -n "$gluetun_output" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$gluetun_output"
    fi
    docker logs --tail=60 gluetun 2>&1 | sed 's/^/    /' || true
    arr_write_run_failure "VPN not running: failed to start Gluetun via docker compose." "VPN_NOT_RUNNING"
    return 1
  fi

  if [[ -n "$gluetun_output" ]]; then
    while IFS= read -r line; do
      printf '  %s\n' "$line"
    done <<<"$gluetun_output"
  fi

  if ! arr_wait_for_gluetun_ready gluetun 150 5; then
    local failure_reason
    failure_reason="${ARR_GLUETUN_FAILURE_REASON:-Gluetun did not become ready}"
    docker logs --tail=120 gluetun 2>&1 | sed 's/^/    /' || true
    arr_write_run_failure "VPN not running: ${failure_reason}." "VPN_NOT_RUNNING"
    return 1
  fi

  if declare -f start_async_pf_if_enabled >/dev/null 2>&1; then
    local pf_state_file=""
    local pf_log_file=""
    if declare -f pf_state_path >/dev/null 2>&1; then
      pf_state_file="$(pf_state_path)"
    else
      pf_state_file="${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_STATE_FILE:-pf-state.json}"
    fi
    if declare -f pf_log_path >/dev/null 2>&1; then
      pf_log_file="$(pf_log_path)"
    else
      pf_log_file="${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_LOG_FILE:-port-forwarding.log}"
    fi

    if [[ "${PF_ASYNC_ENABLE:-1}" == "1" && "${VPN_SERVICE_PROVIDER:-}" == "protonvpn" && "${VPN_PORT_FORWARDING:-on}" == "on" ]]; then
      msg "[pf] Launching asynchronous ProtonVPN port forwarding worker..."
      msg "  Strict mode (GLUETUN_PF_STRICT): ${GLUETUN_PF_STRICT:-0}"
      msg "  State file: ${pf_state_file}"
      msg "  Log file:   ${pf_log_file}"
      start_async_pf_if_enabled || {
        if [[ "${GLUETUN_PF_STRICT:-0}" == "1" ]]; then
          warn "[pf] Worker exited non-zero (strict)."
        else
          warn "[pf] Worker exited non-zero but GLUETUN_PF_STRICT=0 (continuing)."
        fi
      }
    else
      msg "[pf] Port forwarding worker skipped (PF_ASYNC_ENABLE=${PF_ASYNC_ENABLE:-1}, provider=${VPN_SERVICE_PROVIDER:-unknown}, forwarding=${VPN_PORT_FORWARDING:-off})."
    fi
  fi

  start_vpn_auto_reconnect_if_enabled
  service_start_sabnzbd

  local services=()
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" && "${LOCAL_DNS_SERVICE_ENABLED:-0}" == "1" ]]; then
    services+=(local_dns)
  fi
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    services+=(caddy)
  fi
  services+=(qbittorrent sonarr radarr prowlarr bazarr flaresolverr)
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    services+=(sabnzbd)
  fi

  local service
  local qb_started=0
  local -a failed_services=()

  for service in "${services[@]}"; do
    msg "Starting $service..."
    local start_output=""

    if start_output="$(compose up -d "$service" 2>&1)"; then
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi
      if [[ "$service" == "qbittorrent" ]]; then
        qb_started=1
      fi
    else
      warn "Failed to start $service"
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi
      failed_services+=("$service")
      continue
    fi

    sleep 3
  done

  sleep 5
  local -a created_services=()
  for service in "${services[@]}"; do
    local container
    container="$(service_container_name "$service")"
    local status
    status="$(docker inspect "$container" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
    if [[ "$status" == "created" ]]; then
      created_services+=("$service")
    fi
  done

  if ((${#created_services[@]} > 0)); then
    msg "Force-starting services that were stuck in 'created' state..."
    for service in "${created_services[@]}"; do
      docker start "$(service_container_name "$service")" 2>/dev/null || true
    done
  fi

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    if ! sync_caddy_ca_public_copy --wait; then
      warn "Caddy CA root certificate is not published yet; fetch http://ca.${ARR_DOMAIN_SUFFIX_CLEAN}/root.crt after Caddy issues it."
    fi
  fi

  if ((qb_started)); then
    ensure_qbt_config || true
  fi

  if ((${#failed_services[@]} > 0)); then
    warn "The following services failed to start: ${failed_services[*]}"
  fi

  service_health_sabnzbd

  arr_schedule_delayed_api_sync || true

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
}

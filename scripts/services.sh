# shellcheck shell=bash

# Confirms manual VueTorrent install has required assets before activation
vuetorrent_manual_is_complete() {
  local dir="$1"

  [[ -d "$dir" && -f "$dir/public/index.html" && -f "$dir/version.txt" ]]
}

# Reads installed VueTorrent version from version.txt when available
vuetorrent_manual_version() {
  local dir="$1"

  if [[ -f "$dir/version.txt" ]]; then
    head -n1 "$dir/version.txt" 2>/dev/null | tr -d '\r\n'
  fi
}

# Manages VueTorrent deployment, choosing LSIO mod or manual download as configured
install_vuetorrent() {
  local manual_dir="${ARR_DOCKER_DIR}/qbittorrent/vuetorrent"
  local releases_url="https://api.github.com/repos/VueTorrent/VueTorrent/releases/latest"

  if [[ "${VUETORRENT_MODE}" != "manual" ]]; then
    msg "🎨 Using VueTorrent from LSIO Docker mod"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_VERSION=""
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent via LSIO Docker mod (WebUI root ${VUETORRENT_ROOT})."
    if [[ -d "$manual_dir" ]]; then
      msg "  Removing manual VueTorrent directory at ${manual_dir} (LSIO mod active)"
      rm -rf "$manual_dir" 2>/dev/null || warn "  Could not remove ${manual_dir}"
    fi
    return 0
  fi

  msg "🎨 Ensuring VueTorrent WebUI (manual mode)"

  local had_existing_complete=0
  if vuetorrent_manual_is_complete "$manual_dir"; then
    had_existing_complete=1
  fi

  local attempted_install=0
  local install_success=0
  local download_url=""
  local temp_zip=""
  local temp_extract=""
  local staging_dir=""
  local backup_dir=""

  while true; do
    if ! check_dependencies jq unzip; then
      warn "  Missing jq or unzip; skipping VueTorrent download"
      break
    fi

    attempted_install=1

    download_url=$(curl -sL "$releases_url" | jq -r '.assets[] | select(.name == "vuetorrent.zip") | .browser_download_url' 2>/dev/null || printf '')
    if [[ -z "$download_url" ]]; then
      warn "  Could not determine VueTorrent download URL"
      break
    fi

    temp_zip="/tmp/vuetorrent-$$.zip"
    if ! curl -sL "$download_url" -o "$temp_zip"; then
      warn "  Failed to download VueTorrent archive"
      break
    fi

    if ! temp_extract="$(arrstack_mktemp_dir "/tmp/vuetorrent.XXXX")"; then
      warn "  Failed to create extraction directory"
      break
    fi

    if ! unzip -qo "$temp_zip" -d "$temp_extract"; then
      warn "  Failed to extract VueTorrent archive"
      break
    fi

    local source_root="$temp_extract"
    if [[ ! -f "$source_root/index.html" ]]; then
      local nested_index=""
      nested_index="$(find "$temp_extract" -type f -name 'index.html' -print -quit 2>/dev/null || printf '')"
      if [[ -n "$nested_index" ]]; then
        source_root="$(dirname "$nested_index")"
      fi
    fi

    if [[ ! -f "$source_root/index.html" ]]; then
      warn "  VueTorrent archive did not include index.html"
      break
    fi

    if ! staging_dir="$(arrstack_mktemp_dir "/tmp/vuetorrent.staging.XXXX")"; then
      warn "  Failed to create staging directory"
      break
    fi

    if ! cp -a "$source_root"/. "$staging_dir"/; then
      warn "  Failed to stage VueTorrent files"
      break
    fi

    if [[ ! -f "$staging_dir/public/index.html" ]]; then
      warn "  Staged VueTorrent files missing public/index.html"
      break
    fi

    if [[ ! -f "$staging_dir/version.txt" ]]; then
      warn "  Staged VueTorrent files missing version.txt"
      break
    fi

    if [[ -d "$manual_dir" ]]; then
      backup_dir="${manual_dir}.bak.$$"
      if ! mv "$manual_dir" "$backup_dir"; then
        warn "  Failed to move existing VueTorrent install aside"
        break
      fi
    fi

    ensure_dir "${ARR_DOCKER_DIR}/qbittorrent"
    if ! mv "$staging_dir" "$manual_dir"; then
      warn "  Failed to activate new VueTorrent install"
      if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
        mv "$backup_dir" "$manual_dir" 2>/dev/null || warn "  Failed to restore previous VueTorrent files"
      fi
      break
    fi

    staging_dir=""

    if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
      rm -rf "$backup_dir" 2>/dev/null || true
      backup_dir=""
    fi

    install_success=1
    break
  done

  if [[ -n "$temp_zip" ]]; then
    rm -f "$temp_zip" 2>/dev/null || true
  fi
  if [[ -n "$temp_extract" ]]; then
    rm -rf "$temp_extract" 2>/dev/null || true
  fi
  if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
    rm -rf "$staging_dir" 2>/dev/null || true
  fi
  if [[ -n "$backup_dir" && -d "$backup_dir" && ! -d "$manual_dir" ]]; then
    mv "$backup_dir" "$manual_dir" 2>/dev/null || rm -rf "$backup_dir" 2>/dev/null || true
  fi

  if ((install_success)); then
    chown -R "${PUID}:${PGID}" "$manual_dir" 2>/dev/null || true
  fi

  local manual_complete=0
  if vuetorrent_manual_is_complete "$manual_dir"; then
    manual_complete=1
  fi

  if ((manual_complete)); then
    local version
    version="$(vuetorrent_manual_version "$manual_dir")"
    # shellcheck disable=SC2034
    VUETORRENT_VERSION="$version"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    if ((install_success)); then
      msg "  ✅ VueTorrent installed at ${manual_dir}${version:+ (version ${version})}"
    elif ((had_existing_complete)); then
      msg "  ℹ️ VueTorrent already present at ${manual_dir}${version:+ (version ${version})}"
    else
      msg "  ✅ VueTorrent files verified at ${manual_dir}"
    fi
    if [[ -n "$version" ]]; then
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT} (version ${version})."
    else
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT}."
    fi
  else
    if ((attempted_install)); then
      warn "  Manual VueTorrent install is incomplete"
    elif ((had_existing_complete)); then
      warn "  Existing VueTorrent files missing required assets"
    else
      warn "  Manual VueTorrent files not found"
    fi
    # shellcheck disable=SC2034
    VUETORRENT_VERSION=""
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=0
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="warn"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="Manual VueTorrent install unavailable; qBittorrent default UI active."
    write_qbt_config
  fi

  # Avoid aggressive cleanup so sibling services aren't interrupted mid-run
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
    warn "[sabnzbd] Health check failed (verify SABNZBD_URL or container status)"
  fi
}

# Stops existing stack containers and removes stale temp artifacts without nuking volumes
safe_cleanup() {
  msg "🧹 Safely stopping existing services..."

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

  docker ps -a --filter "label=com.docker.compose.project=arrstack" --format "{{.ID}}" \
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
    echo "[arrstack] Tip: run scripts/dev/find-unescaped-dollar.sh \"${file}\"" >&2
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

  if ! compose -f "$file" config -q 2>"$errlog"; then
    echo "[arrstack] Compose validation failed; see $errlog"
    local line
    line="$(grep -oE 'line ([0-9]+)' "$errlog" | awk '{print $2}' | tail -1 || true)"
    if [[ -n "$line" && -r "$file" ]]; then
      local start=$((line - 5))
      local end=$((line + 5))
      ((start < 1)) && start=1
      nl -ba "$file" | sed -n "${start},${end}p"
    fi
    exit 1
  fi

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

  msg "🧪 Validating Caddy configuration"

  if ! docker run --rm \
    -v "${caddyfile}:/etc/caddy/Caddyfile:ro" \
    "${CADDY_IMAGE}" \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    >"$logfile" 2>&1; then
    warn "Caddy validation failed; see ${logfile}"
    cat "$logfile"
    exit 1
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

# Ensures all service images exist, falling back to :latest for LSIO when needed
validate_images() {
  msg "🔍 Validating Docker images..."

  local image_vars=(
    GLUETUN_IMAGE
    QBITTORRENT_IMAGE
    SONARR_IMAGE
    RADARR_IMAGE
    PROWLARR_IMAGE
    BAZARR_IMAGE
    FLARESOLVERR_IMAGE
  )

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    image_vars+=(CONFIGARR_IMAGE)
  fi

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    image_vars+=(CADDY_IMAGE)
  fi

  local failed_images=()

  for var_name in "${image_vars[@]}"; do
    local image="${!var_name:-}"
    [[ -z "$image" ]] && continue

    msg "  Checking $image..."

    # Check via manifest (remote) or local cache without pulling layers
    if check_image_exists "$image"; then
      msg "  ✅ Valid: $image"
      continue
    fi

    # If failed, try fallback for LinuxServer images only
    local base_image="$image"
    local tag=""
    if [[ "$image" == *:* ]]; then
      base_image="${image%:*}"
      tag="${image##*:}"
    fi

    if [[ "$tag" != "latest" && "$base_image" == lscr.io/linuxserver/* ]]; then
      local latest_image="${base_image}:latest"
      msg "    Trying fallback: $latest_image"

      if check_image_exists "$latest_image"; then
        msg "    ✅ Using fallback: $latest_image"

        case "$base_image" in
          *qbittorrent) update_env_image_var QBITTORRENT_IMAGE "$latest_image" ;;
          *sonarr) update_env_image_var SONARR_IMAGE "$latest_image" ;;
          *radarr) update_env_image_var RADARR_IMAGE "$latest_image" ;;
          *prowlarr) update_env_image_var PROWLARR_IMAGE "$latest_image" ;;
          *bazarr) update_env_image_var BAZARR_IMAGE "$latest_image" ;;
        esac

        continue
      else
        warn "  ⚠️ Could not validate: $image"
        failed_images+=("$image")
      fi
    else
      warn "  ⚠️ Could not validate: $image"
      failed_images+=("$image")
    fi
  done

  if ((${#failed_images[@]} > 0)); then
    warn "================================================"
    warn "Some images could not be validated:"
    for img in "${failed_images[@]}"; do
      warn "  - $img"
    done
    warn "Check the image names and tags in .env or ${ARR_USERCONF_PATH}"
    warn "================================================"
  fi
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

# Polls Gluetun health and control API until VPN is ready or times out
wait_for_vpn_connection() {
  local max_wait="${1:-180}"
  local elapsed=0
  local check_interval=5
  local host="${LOCALHOST_IP:-127.0.0.1}"
  local vpn_status_url
  local public_ip_url
  local consecutive_failures=0
  local max_consecutive=3

  msg "Waiting for VPN connection (max ${max_wait}s)..."

  while ((elapsed < 30)); do
    local status
    status="$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
    if [[ "$status" == "running" ]]; then
      break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  if [[ $host == *:* && $host != [* ]]; then
    vpn_status_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://[$host]:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  else
    vpn_status_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
    public_ip_url="http://${host}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip"
  fi

  elapsed=0
  local reported_healthy=0
  local -a curl_cmd=(curl -fsS --max-time 5)
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    curl_cmd+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
  fi

  while ((elapsed < max_wait)); do
    local health
    health="$(docker inspect gluetun --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)"

    if [[ "$health" == "healthy" ]]; then
      if ((reported_healthy == 0)); then
        msg "  ✅ Gluetun is healthy"
        reported_healthy=1
      fi

      if "${curl_cmd[@]}" "$vpn_status_url" >/dev/null 2>&1; then
        msg "  ✅ VPN connected after ${elapsed}s"
        msg "  ✅ VPN API responding"

        local ip_payload
        ip_payload="$("${curl_cmd[@]}" "$public_ip_url" 2>/dev/null || true)"
        if [[ -n "$ip_payload" ]]; then
          local ip_summary
          if ip_summary="$(gluetun_public_ip_summary "$ip_payload" 2>/dev/null || true)" && [[ -n "$ip_summary" ]]; then
            msg "  🌐 Public IP: ${ip_summary}"
          elif [[ "$ip_payload" =~ \"public_ip\"[[:space:]]*:[[:space:]]*\"\" ]]; then
            msg "  🌐 Public IP: (pending assignment)"
          else
            msg "  🌐 Public IP response: ${ip_payload}"
          fi
        else
          msg "  🌐 Public IP: (pending assignment)"
        fi

        return 0
      fi
    fi

    consecutive_failures=$((consecutive_failures + 1))

    if ((consecutive_failures >= max_consecutive)); then
      warn "VPN health checks failing consistently after ${elapsed}s"
      return 1
    fi

    sleep "$check_interval"
    elapsed=$((elapsed + check_interval))
  done

  warn "VPN connection timeout after ${max_wait}s"
  return 1
}

# Launches VPN auto-reconnect daemon when configured and available
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

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file" 2>/dev/null || printf '')"
    if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
      msg "[vpn-auto] Auto-reconnect daemon already running (pid ${existing_pid})"
      return 0
    fi
    rm -f "$pid_file" 2>/dev/null || true
  fi

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
  if [[ "${ENABLE_LOCAL_DNS:-0}" != "1" ]]; then
    return 0
  fi

  local conf="/etc/docker/daemon.json"
  if [[ -f "$conf" ]] && grep -q '"userland-proxy"[[:space:]]*:[[:space:]]*false' "$conf" 2>/dev/null; then
    return 0
  fi

  if [[ ! -w "$conf" && ! -w "$(dirname "$conf")" ]]; then
    warn "[dns] Docker daemon.json requires root to modify."
    warn "[dns] Run: sudo ${BASH_SOURCE[0]} to configure userland-proxy"
    warn "[dns] Or manually set: {\"userland-proxy\": false} in $conf and restart Docker"
    return 0
  fi

  msg "[dns] Disabling Docker userland-proxy for reliable :53 publishing"

  local conf_dir
  conf_dir="$(dirname "$conf")"
  if ! mkdir -p "$conf_dir"; then
    warn "[dns] Failed to create ${conf_dir}"
    return 0
  fi

  if command -v jq >/dev/null 2>&1 && [[ -s "$conf" ]]; then
    local tmp
    if ! tmp="$(mktemp)"; then
      warn "[dns] Failed to create temporary file for ${conf}"
      return 0
    fi
    if ! jq -S --argjson v false '."userland-proxy"=$v' "$conf" >"$tmp"; then
      rm -f "$tmp" 2>/dev/null || true
      warn "[dns] Failed to update ${conf}"
      return 0
    fi
    if ! mv "$tmp" "$conf"; then
      rm -f "$tmp" 2>/dev/null || true
      warn "[dns] Failed to replace ${conf}"
      return 0
    fi
  else
    if ! printf '{\n  "userland-proxy": false\n}\n' >"$conf"; then
      warn "[dns] Failed to write ${conf}"
      return 0
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl restart docker >/dev/null 2>&1; then
      die "[dns] Failed to restart Docker after updating ${conf}"
    fi
    if ! systemctl is-active --quiet docker; then
      die "[dns] Docker failed to restart after userland-proxy change. Check: journalctl -xeu docker"
    fi
  elif command -v service >/dev/null 2>&1; then
    if ! service docker restart >/dev/null 2>&1; then
      die "[dns] Failed to restart Docker after updating ${conf}"
    fi
    if ! service docker status >/dev/null 2>&1; then
      die "[dns] Docker failed to restart after userland-proxy change. Check: service docker status"
    fi
  else
    warn "[dns] Docker restart command not found; restart Docker manually to apply userland-proxy change"
    return 0
  fi

  msg "[dns] Docker userland-proxy disabled successfully"
  return 0
}

# Orchestrates service startup: cleanup, validation, image pulls, health waits, summaries
start_stack() {
  msg "🚀 Starting services"

  cd "${ARR_STACK_DIR}" || die "Failed to change to ${ARR_STACK_DIR}"

  safe_cleanup

  ensure_docker_userland_proxy_disabled

  validate_images

  install_vuetorrent

  msg "Starting Gluetun VPN container..."
  if ! compose up -d gluetun 2>&1; then
    warn "Initial Gluetun start failed (compose)"
    docker logs --tail=60 gluetun 2>&1 | sed 's/^/    /' || true
  fi

  sleep 10

  local restart_count=0
  local gluetun_status=""
  while ((restart_count < 5)); do
    gluetun_status="$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "unknown")"

    if [[ "$gluetun_status" == "running" ]]; then
      break
    elif [[ "$gluetun_status" == "restarting" ]]; then
      warn "Gluetun is restarting (attempt $((restart_count + 1))/5)"
      docker logs --tail=25 gluetun 2>&1 | grep -E -i 'auth|fail|error|cannot|fatal' | tail -n 8 | sed 's/^/    /' || true
      sleep 8
      ((restart_count++))
    else
      break
    fi
  done

  if ((restart_count >= 5)); then
    warn "Gluetun stuck in restart loop. Common causes:"
    warn "  - Wrong Proton credentials (ensure +pmp)."
    warn "  - SERVER_COUNTRIES invalid / empty."
    warn "  - DNS or base network outage."
    warn "  - Gluetun <3.40 with stray auth config (delete gluetun/auth/config.toml)."
    docker logs --tail=120 gluetun 2>&1 | sed 's/^/    /' || true
    die "Aborting due to repeated Gluetun restarts"
  fi

  if [[ "$gluetun_status" != "running" ]]; then
    warn "Gluetun status after startup: ${gluetun_status}"
  fi

  msg "Waiting for VPN connection (baseline tunnel; PF may still be pending)..."
  local vpn_wait_levels=(60 120 180)
  local vpn_ready=0

  local max_wait
  for max_wait in "${vpn_wait_levels[@]}"; do
    if wait_for_vpn_connection "$max_wait"; then
      vpn_ready=1
      break
    fi

    warn "VPN not ready after ${max_wait}s, extending timeout..."
  done

  if ((vpn_ready == 0)); then
    warn "VPN connection not verified after extended wait."
    warn "Continuing anyway; dependent services may encounter connectivity errors until Gluetun stabilizes."
    docker logs --tail=120 gluetun 2>&1 | sed 's/^/    /' || true
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
  for service in "${services[@]}"; do
    msg "Starting $service..."
    local service_started=0
    local start_output=""

    if start_output="$(compose up -d "$service" 2>&1)"; then
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi
      service_started=1
    else
      warn "Failed to start $service with normal dependencies"
      if [[ -n "$start_output" ]]; then
        while IFS= read -r line; do
          printf '  %s\n' "$line"
        done <<<"$start_output"
      fi

      local fallback_output=""
      if fallback_output="$(compose up -d --no-deps "$service" 2>&1)"; then
        msg "  Started $service without dependency checks"
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        service_started=1
      else
        warn "Failed to start $service even without dependencies, skipping..."
        if [[ -n "$fallback_output" ]]; then
          while IFS= read -r line; do
            printf '    %s\n' "$line"
          done <<<"$fallback_output"
        fi
        continue
      fi
    fi

    if [[ "$service" == "qbittorrent" ]] && ((service_started == 1)); then
      qb_started=1
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
    sync_qbt_password_from_logs
  fi

  service_health_sabnzbd

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
}

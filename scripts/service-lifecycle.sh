# shellcheck shell=bash
# Purpose: Orchestrate stack startup, compose operations, and VPN readiness checks.
# Inputs: Uses ARR_STACK_DIR, ARR_DOCKER_DIR, ENABLE_CADDY, SABNZBD_ENABLED, LOCAL_DNS_STATE, and Compose tooling.
# Outputs: Manages container lifecycle, updates run failure markers, and prints service status summaries.
# Exit codes: Functions return non-zero when compose commands, VPN readiness, or Docker configuration adjustments fail.
if [[ -n "${__SERVICE_LIFECYCLE_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_LIFECYCLE_LOADED=1

arr_effective_project_name() {
  local project="${COMPOSE_PROJECT_NAME:-}"

  if [[ -n "$project" ]]; then
    printf '%s\n' "$project"
    return 0
  fi

  local -a env_candidates=()
  local stack_env
  stack_env="$(arr_env_file)"
  if [[ -n "${ARR_ENV_FILE:-}" ]]; then
    env_candidates+=("${ARR_ENV_FILE}")
    if [[ "${ARR_ENV_FILE}" != "$stack_env" ]]; then
      env_candidates+=("$stack_env")
    fi
  elif [[ -n "$stack_env" ]]; then
    env_candidates+=("$stack_env")
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
    project="${STACK}"
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
  project_label="$(arr_effective_project_name 2>/dev/null || printf '%s' "${STACK}")"

  docker ps -a --filter "label=com.docker.compose.project=${project_label}" --format "{{.ID}}" \
    | xargs -r docker rm -f 2>/dev/null || true
}

# Ensures generated compose and environment files exist before proceeding
compose_service_is_running() {
  local service="$1"
  local project

  project="$(arr_effective_project_name 2>/dev/null || printf '%s' "${STACK}")"

  docker ps \
    --filter "label=com.docker.compose.project=${project}" \
    --filter "label=com.docker.compose.service=${service}" \
    --filter "status=running" \
    --format '{{.ID}}' \
    | grep -q .
}

# Runs `docker compose up -d` while capturing output for optional logging
compose_up_detached_capture() {
  local output_var="$1"
  shift || true

  if [[ -z "$output_var" ]]; then
    die "compose_up_detached_capture requires an output variable name"
  fi

  local compose_output=""
  if compose_output="$(compose up -d "$@" 2>&1)"; then
    printf -v "$output_var" '%s' "$compose_output"
    if [[ "${ARR_COMPOSE_PROGRESS:-quiet}" == "inherit" && -n "$compose_output" ]]; then
      printf '%s\n' "$compose_output"
    fi
    return 0
  fi

  printf -v "$output_var" '%s' "$compose_output"
  return 1
}

# Starts individual compose service and streams docker compose output
compose_up_service() {
  local service="$1"
  local was_running=0
  local compose_output=""

  if compose_service_is_running "$service"; then
    was_running=1
  fi

  msg "  Starting $service..."
  if compose_up_detached_capture compose_output "$service"; then
    local running_after=0
    if compose_service_is_running "$service"; then
      running_after=1
    else
      sleep 1
      if compose_service_is_running "$service"; then
        running_after=1
      fi
    fi

    if ((running_after)); then
      if ((was_running)); then
        msg "  $service already running (no changes needed)"
      else
        msg "  $service started"
      fi
    else
      warn "  $service not running after docker compose up; inspect container logs"
      if [[ -n "$compose_output" ]]; then
        printf '%s\n' "$compose_output" | sed 's/^/    /'
      fi
    fi
  else
    warn "  Failed to start $service"
    if [[ -n "$compose_output" ]]; then
      printf '%s\n' "$compose_output" | sed 's/^/    /'
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
  local iface_pattern="${2:-tun[0-9]+|wg[0-9]+}"

  docker exec "$name" sh -eu -c '
    pattern=$1
    route_pattern="dev (${pattern})"
    link_pattern="[[:space:]](${pattern}):"

    if ip -4 route show default 2>/dev/null | grep -Eq "$route_pattern"; then
      exit 0
    fi

    if ip -6 route show default 2>/dev/null | grep -Eq "$route_pattern"; then
      exit 0
    fi

    if ip -o link show 2>/dev/null | grep -Eq "$link_pattern"; then
      exit 0
    fi

    exit 1
  ' _ "$iface_pattern" >/dev/null 2>&1
}

arr_gluetun_connectivity_probe() {
  local name="${1:-gluetun}"
  shift || true

  local -a urls=()
  if (($# > 0)); then
    urls=("$@")
  else
    local configured_urls="${GLUETUN_CONNECTIVITY_PROBE_URLS:-}"
    if [[ -n "$configured_urls" ]] && declare -f normalize_csv >/dev/null 2>&1; then
      local normalized=""
      normalized="$(normalize_csv "$configured_urls")"
      if [[ -n "$normalized" ]]; then
        IFS=',' read -r -a urls <<<"$normalized"
      fi
    fi

    if ((${#urls[@]} == 0)); then
      urls=(
        "https://api.ipify.org"
        "https://ipconfig.io/ip"
        "https://1.1.1.1/cdn-cgi/trace"
      )
    fi
  fi

  local -a sanitized_urls=()
  local candidate=""
  for candidate in "${urls[@]}"; do
    candidate="${candidate//[$'\r\n\t']/}"
    if [[ -n "$candidate" ]]; then
      sanitized_urls+=("$candidate")
    fi
  done

  if ((${#sanitized_urls[@]} == 0)); then
    sanitized_urls=(
      "https://api.ipify.org"
      "https://ipconfig.io/ip"
      "https://1.1.1.1/cdn-cgi/trace"
    )
  fi

  ARR_GLUETUN_CONNECTIVITY_LAST_URL=""
  ARR_GLUETUN_CONNECTIVITY_FAILURE_REASON=""

  local probe_output=""
  local probe_status=0

  if probe_output="$(
    docker exec "$name" sh -eu -c '
      if [ "$#" -eq 0 ]; then
        set -- "https://api.ipify.org" "https://ipconfig.io/ip" "https://1.1.1.1/cdn-cgi/trace"
      fi

      have_curl=1
      have_wget=1
      command -v curl >/dev/null 2>&1 || have_curl=0
      command -v wget >/dev/null 2>&1 || have_wget=0

      if [ "$have_curl" -eq 0 ] && [ "$have_wget" -eq 0 ]; then
        exit 3
      fi

      for url in "$@"; do
        if [ "$have_curl" -eq 1 ]; then
          if curl -fsS --connect-timeout 5 --max-time 8 "$url" >/dev/null 2>&1; then
            printf %s "$url"
            exit 0
          fi
        fi
        if [ "$have_wget" -eq 1 ]; then
          if wget -q -T 8 -O- "$url" >/dev/null 2>&1; then
            printf %s "$url"
            exit 0
          fi
        fi
      done

      exit 1
    ' _ "${sanitized_urls[@]}"
  )"; then
    ARR_GLUETUN_CONNECTIVITY_LAST_URL="${probe_output}"
    return 0
  fi

  probe_status=$?
  if ((probe_status == 3)); then
    ARR_GLUETUN_CONNECTIVITY_FAILURE_REASON="curl/wget unavailable inside Gluetun"
    return 3
  fi

  return 1
}

arr_wait_for_gluetun_ready() {
  local name="${1:-gluetun}"
  local max_wait="${2:-150}"
  local check_interval="${3:-5}"

  ARR_GLUETUN_FAILURE_REASON=""
  ARR_GLUETUN_CONNECTIVITY_FAILURE_REASON=""

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
    # Robust against caller IFS: enforce space splitting locally
    if arr_read_fields "$inspect_output" state has_health health_status; then
      :
    else
      ARR_GLUETUN_FAILURE_REASON="docker inspect returned empty/invalid output for ${name}"
      warn "  docker inspect returned empty/invalid output; aborting readiness wait."
      return 1
    fi

    if [[ "$state" != "running" ]]; then
      case "$state" in
        restarting)
          if [[ "$last_state" != "$state" ]]; then
            warn "  Gluetun is restarting; waiting for stability..."
          fi
          ;;
        created | starting)
          if [[ "$last_state" != "$state" ]]; then
            msg "  Gluetun container reported state '${state}'. Waiting for it to run..."
          fi
          ;;
        exited | dead | removing | paused)
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

    local connectivity_rc=$?
    if ((connectivity_rc == 3)); then
      ARR_GLUETUN_FAILURE_REASON="${ARR_GLUETUN_CONNECTIVITY_FAILURE_REASON:-Gluetun connectivity probe missing curl/wget}"
      warn "  Gluetun connectivity probe cannot run (missing curl/wget inside container)."
      return 1
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

  msg "Stopping existing auto-reconnect worker(s): ${candidate_pids[*]}"

  for pid in "${candidate_pids[@]}"; do
    if kill "$pid" 2>/dev/null; then
      for _ in 1 2 3 4 5; do
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
    msg "Auto-reconnect disabled (VPN_AUTO_RECONNECT_ENABLED=${VPN_AUTO_RECONNECT_ENABLED:-0})"
    return 0
  fi

  local daemon_path="${ARR_STACK_DIR}/scripts/vpn-auto-reconnect-daemon.sh"
  if [[ ! -x "$daemon_path" ]]; then
    warn "Auto-reconnect daemon missing at ${daemon_path}"
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

  msg "Launching auto-reconnect daemon"

  touch "$log_file" 2>/dev/null || true
  ensure_nonsecret_file_mode "$log_file"

  if nohup "$daemon_path" >>"$log_file" 2>&1 & then
    local pid=$!
    printf '%s\n' "$pid" >"$pid_file"
    ensure_secret_file_mode "$pid_file"
    msg "Daemon started (pid ${pid})"
  else
    warn "Failed to start auto-reconnect daemon"
  fi
}

# Prints container runtime status and port-forward summary for quick health glance
show_service_status() {
  msg "Service status summary:"
  local -a services=(gluetun qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr)
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    services+=(caddy)
  fi
  if [[ "${LOCAL_DNS_STATE:-inactive}" == "active" ]]; then
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
      msg "Current PF status: ${pf_status} (port=${pf_port:-0})"
    fi
  fi
}

# Disables Docker's userland proxy to let dnsmasq bind :53 reliably
ensure_docker_userland_proxy_disabled() {
  if [[ "${LOCAL_DNS_STATE:-inactive}" != "active" ]]; then
    msg "Skipping userland-proxy update (local DNS inactive)"
    return 0
  fi

  local conf="${ARR_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
  local conf_dir
  conf_dir="$(dirname "$conf")"

  local merge_tool_preference="${ARR_DAEMON_JSON_TOOL:-}"
  local merge_tool=""

  if [[ -n "$merge_tool_preference" && "$merge_tool_preference" != "jq" ]]; then
    warn "Only jq is supported for editing ${conf}; ignoring ARR_DAEMON_JSON_TOOL=${merge_tool_preference}"
  fi

  if command -v jq >/dev/null 2>&1; then
    merge_tool="jq"
  else
    warn "jq is required to edit ${conf}. Install jq and rerun."
    return 1
  fi

  if [[ ! -e "$conf" ]]; then
    if [[ ! -d "$conf_dir" ]] && ! mkdir -p "$conf_dir"; then
      warn "Failed to create ${conf_dir}"
      return 1
    fi
  fi

  if [[ -f "$conf" && ! -w "$conf" && ! -w "$conf_dir" ]]; then
    warn "Docker daemon.json requires root to modify."
    warn "Run with sudo or set {\"userland-proxy\": false} in ${conf} manually."
    return 1
  fi

  if [[ "$merge_tool" == "jq" && -s "$conf" ]]; then
    if jq -e '."userland-proxy" == false' "$conf" >/dev/null 2>&1; then
      msg "Docker userland-proxy already disabled"
      return 0
    fi
    if ! jq empty "$conf" >/dev/null 2>&1; then
      warn "${conf} contains invalid JSON; fix the file manually before continuing."
      return 1
    fi

  fi

  local backup
  # Any edits to ${conf} are reversible: restore the generated backup over ${conf}
  # (e.g. `sudo cp "${backup}" "${conf}"`) and restart Docker to roll back the DNS
  # userland-proxy change if needed.
  backup="${conf}.${STACK}.$(date +%Y%m%d-%H%M%S).bak"
  if [[ -f "$conf" ]]; then
    if ! cp -p "$conf" "$backup"; then
      warn "Failed to create backup at ${backup}"
      return 1
    fi
  else
    printf '{}\n' >"$backup" 2>/dev/null || true
  fi

  local tmp
  if ! tmp="$(arr_mktemp_file "${conf}.XXXXXX.tmp")"; then
    warn "Failed to create temporary file for ${conf}"
    return 1
  fi

  local merge_status=0
  if [[ "$merge_tool" == "jq" ]]; then
    if [[ -s "$conf" ]]; then
      jq -S '."userland-proxy" = false' "$conf" >"$tmp" 2>/dev/null || merge_status=$?
    else
      printf '{\n  "userland-proxy": false\n}\n' >"$tmp" || merge_status=1
    fi
  fi

  if ((merge_status != 0)); then
    arr_cleanup_temp_path "$tmp"
    warn "Failed to merge userland-proxy setting into ${conf}"
    warn "Backup saved at ${backup}"
    return 1
  fi

  if ! mv "$tmp" "$conf"; then
    arr_cleanup_temp_path "$tmp"
    warn "Failed to replace ${conf}. Backup saved at ${backup}"
    return 1
  fi
  arr_unregister_temp_path "$tmp"
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
        warn "Failed to restart Docker; run 'sudo systemctl restart docker' manually."
        warn "Rollback available at: ${backup}"
        return 1
      fi
      if ! systemctl is-active --quiet docker; then
        warn "Docker failed to report healthy after restart; inspect 'journalctl -xeu docker'."
        return 1
      fi
      msg "Docker daemon restarted to apply userland-proxy change"
    elif command -v service >/dev/null 2>&1; then
      if ! service docker restart >/dev/null 2>&1; then
        warn "Failed to restart Docker; run 'sudo service docker restart' manually."
        warn "Rollback available at: ${backup}"
        return 1
      fi
      msg "Docker daemon restarted to apply userland-proxy change"
    else
      warn "Docker restart command not found; restart the daemon manually to apply changes."
    fi
  else
    warn "Docker restart required to apply userland-proxy change. Re-run with --yes or ARR_HOST_RESTART_OK=1."
  fi

  msg "Docker userland-proxy set to false"
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
  local compose_output_gluetun=""
  if ! compose_up_detached_capture compose_output_gluetun gluetun; then
    warn "Failed to start Gluetun via docker compose"
    if [[ -n "$compose_output_gluetun" ]]; then
      printf '%s\n' "$compose_output_gluetun" | sed 's/^/    /'
    fi
    docker logs --tail=60 gluetun 2>&1 | sed 's/^/    /' || true
    arr_write_run_failure "VPN not running: failed to start Gluetun via docker compose." "VPN_NOT_RUNNING"
    return 1
  fi
  msg "Gluetun container started"

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
      msg "Launching asynchronous ProtonVPN port forwarding worker..."
      msg "  Strict mode (GLUETUN_PF_STRICT): ${GLUETUN_PF_STRICT:-0}"
      msg "  State file: ${pf_state_file}"
      msg "  Log file:   ${pf_log_file}"
      start_async_pf_if_enabled || {
        if [[ "${GLUETUN_PF_STRICT:-0}" == "1" ]]; then
          warn "Worker exited non-zero (strict)."
        else
          warn "Worker exited non-zero but GLUETUN_PF_STRICT=0 (continuing)."
        fi
      }
    else
      msg "Port forwarding worker skipped (PF_ASYNC_ENABLE=${PF_ASYNC_ENABLE:-1}, provider=${VPN_SERVICE_PROVIDER:-unknown}, forwarding=${VPN_PORT_FORWARDING:-off})."
    fi
  fi

  start_vpn_auto_reconnect_if_enabled
  service_start_sabnzbd

  local services=()
  if [[ "${LOCAL_DNS_STATE:-inactive}" == "active" ]]; then
    services+=(local_dns)
  fi
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    services+=(caddy)
  fi
  services+=(qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr)
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    services+=(sabnzbd)
  fi

  local service
  local qb_started=0
  local -a failed_services=()

  for service in "${services[@]}"; do
    msg "Starting $service..."

    if [[ "$service" == "qbittorrent" ]]; then
      ensure_qbt_webui_config_ready
    fi

    local compose_output_service=""
    if compose_up_detached_capture compose_output_service "$service"; then
      if [[ "$service" == "qbittorrent" ]]; then
        qb_started=1
      fi
    else
      warn "Failed to start $service"
      if [[ -n "$compose_output_service" ]]; then
        printf '%s\n' "$compose_output_service" | sed 's/^/    /'
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

  if ! arr_schedule_delayed_api_sync; then
    warn "arr_schedule_delayed_api_sync failed; API sync may be delayed or incomplete."
  fi

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
}

# shellcheck shell=bash
# Purpose: Orchestrate stack startup, compose operations, and VPN readiness checks.
# Inputs: Uses ARR_STACK_DIR, ARR_DOCKER_DIR, SABNZBD_ENABLED, and Compose tooling.
# Outputs: Manages container lifecycle, updates run failure markers, and prints service status summaries.
# Exit codes: Functions return non-zero when compose commands, VPN readiness, or Docker configuration adjustments fail.
if [[ -n "${__SERVICE_LIFECYCLE_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_LIFECYCLE_LOADED=1

# Source qbt-api.sh for qBittorrent API functions (qbt_set_password, etc.)
_lifecycle_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_lifecycle_script_dir}/qbt-api.sh" ]]; then
  # shellcheck source=scripts/qbt-api.sh
  . "${_lifecycle_script_dir}/qbt-api.sh"
fi
unset _lifecycle_script_dir

# Generates a PBKDF2-SHA512 hash for qBittorrent WebUI password.
# qBittorrent uses: PBKDF2-HMAC-SHA512, 100,000 iterations, 16-byte salt.
# Format: @ByteArray(<base64_salt>:<base64_hash>)
# Returns: The hash string to write to WebUI\Password_PBKDF2 in qBittorrent.conf
# Requires: python3 with hashlib (standard library)
qbt_generate_pbkdf2_hash() {
  local password="$1"

  if [[ -z "$password" ]]; then
    return 1
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi

  # Generate PBKDF2 hash using Python (hashlib is standard library)
  python3 -c "
import hashlib
import os
import base64
import sys

password = sys.argv[1]
salt = os.urandom(16)
iterations = 100000
dk = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, iterations)
print('@ByteArray(' + base64.b64encode(salt).decode() + ':' + base64.b64encode(dk).decode() + ')')
" "$password" 2>/dev/null
}

# Applies password directly to qBittorrent.conf by generating PBKDF2 hash.
# This is more reliable than waiting for temp password from logs.
# Returns 0 on success, 1 on failure.
qbt_apply_password_to_config() {
  local password="$1"
  local conf_file="$2"

  if [[ -z "$password" || -z "$conf_file" ]]; then
    return 1
  fi

  if [[ ! -f "$conf_file" ]]; then
    return 1
  fi

  local pbkdf2_hash=""
  if ! pbkdf2_hash="$(qbt_generate_pbkdf2_hash "$password")"; then
    return 1
  fi

  if [[ -z "$pbkdf2_hash" ]]; then
    return 1
  fi

  # Remove existing password hash line and add new one
  # Use atomic approach: read, modify, write
  local conf_content=""
  if ! conf_content="$(cat "$conf_file" 2>/dev/null)"; then
    return 1
  fi

  # Remove any existing Password_PBKDF2 line
  conf_content="$(printf '%s\n' "$conf_content" | grep -v 'WebUI\\Password_PBKDF2' || true)"

  # Find [Preferences] section and add password after it, or append at end
  if printf '%s' "$conf_content" | grep -q '^\[Preferences\]'; then
    # Insert after [Preferences] line
    conf_content="$(printf '%s\n' "$conf_content" | awk -v hash="$pbkdf2_hash" '
      /^\[Preferences\]/ { print; print "WebUI\\Password_PBKDF2=\"" hash "\""; next }
      { print }
    ')"
  else
    # Append to end with [Preferences] section
    conf_content="${conf_content}"$'\n'"[Preferences]"$'\n'"WebUI\\Password_PBKDF2=\"${pbkdf2_hash}\""
  fi

  # Write back to config file
  if ! printf '%s\n' "$conf_content" > "$conf_file"; then
    return 1
  fi

  return 0
}

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

  msg "Starting $service..."
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
        msg "$service already running (no changes needed)"
      else
        msg "$service started"
      fi
    else
      warn "$service not running after docker compose up; inspect container logs"
      if [[ -n "$compose_output" ]]; then
        printf '%s\n' "$compose_output" | sed 's/^/    /'
      fi
    fi
  else
    warn "Failed to start $service"
    if [[ -n "$compose_output" ]]; then
      printf '%s\n' "$compose_output" | sed 's/^/    /'
    fi
  fi
  sleep 2
}

# Captures qBittorrent temporary password from logs and persists to .env
# qBittorrent 4.5.0+ log format:
#   "A temporary password is provided for this session: XXXXXXXX"
#   "The WebUI administrator password was not set. A temporary password is provided for this session: XXXXXXXX"
# The password is typically 8-16 alphanumeric characters (validated as 6-20 for flexibility).
sync_qbt_password_from_logs() {
  if [[ "${QBT_PASS}" != "adminadmin" ]]; then
    return
  fi

  msg "Detecting qBittorrent temporary password..."
  local attempts=0
  local detected=""
  local logs=""
  local max_attempts=30

  while ((attempts < max_attempts)); do
    # Use --tail to reduce I/O and ensure stable parsing with LC_ALL=C
    logs="$(LC_ALL=C docker logs --tail 200 qbittorrent 2>&1 || true)"

    # Modern format (qBittorrent 4.5.0+): "A temporary password is provided for this session: XXXXXXXX"
    # Regex breakdown:
    #   .*[Tt]emporary [Pp]assword  - Match up to "temporary password" (case-insensitive T/P)
    #   [^:]*:                       - Skip any text until the colon
    #   [[:space:]]*                 - Skip whitespace after colon
    #   \([^[:space:]]*\)            - Capture the password (first non-whitespace sequence)
    detected="$(printf '%s' "$logs" | LC_ALL=C sed -n 's/.*[Tt]emporary [Pp]assword[^:]*:[[:space:]]*\([^[:space:]]*\).*/\1/p' | tail -1)"

    # Strip any surrounding quotes if present
    detected="${detected#\"}"
    detected="${detected%\"}"
    detected="${detected#\'}"
    detected="${detected%\'}"

    # Validate: password should be 6-20 alphanumeric characters
    if [[ -n "$detected" && "$detected" =~ ^[A-Za-z0-9]{6,20}$ ]]; then
      QBT_PASS="$detected"
      persist_env_var QBT_PASS "${QBT_PASS}"
      msg "Saved qBittorrent temporary password to .env (QBT_PASS)"
      return
    fi

    detected=""
    sleep 2
    ((attempts++))
  done

  warn "Unable to automatically determine the qBittorrent password. Update QBT_PASS in .env manually."
  warn "Check 'docker logs qbittorrent' for a line containing 'temporary password'."
}

# Applies user-configured qBittorrent credentials when they differ from defaults.
# Called after qBittorrent starts to sync userr.conf QBT_USER/QBT_PASS with qBittorrent WebUI.
apply_qbt_credentials_from_config() {
  local desired_user="${1:-${QBT_USER:-admin}}"
  local desired_pass="${2:-${QBT_PASS:-adminadmin}}"
  local default_user="admin"
  local default_pass="adminadmin"

  # Check if there's anything to change
  local need_user_change=0
  local need_pass_change=0
  if [[ "$desired_user" != "$default_user" ]]; then
    need_user_change=1
  fi
  if [[ "$desired_pass" != "$default_pass" ]]; then
    need_pass_change=1
  fi

  if ((need_user_change == 0 && need_pass_change == 0)); then
    return 0
  fi

  # Check if qBittorrent is running
  if ! docker inspect qbittorrent --format '{{.State.Running}}' 2>/dev/null | grep -q "true"; then
    warn "qBittorrent not running, cannot apply credentials from config"
    return 1
  fi

  # Detect temp password from logs (qBittorrent generates this on first start)
  local temp_pass=""
  local attempts=0
  while ((attempts < 30)); do
    temp_pass="$(docker logs qbittorrent 2>&1 | grep -i "temporary password" | tail -1 | sed 's/.*temporary password[^:]*: *//' | awk '{print $1}' || true)"
    if [[ -n "$temp_pass" ]]; then
      break
    fi
    sleep 1
    ((attempts++))
  done

  # If no temp password found, qBittorrent might already have credentials set
  if [[ -z "$temp_pass" ]]; then
    # Try logging in with the desired credentials
    if QBT_USER="$desired_user" QBT_PASS="$desired_pass" qbt_api_login 2>/dev/null; then
      msg "qBittorrent credentials from config are already applied"
      persist_env_var QBT_USER "$desired_user"
      persist_env_var QBT_PASS "$desired_pass"
      return 0
    fi
    # Try with default username but desired password
    if QBT_USER="$default_user" QBT_PASS="$desired_pass" qbt_api_login 2>/dev/null; then
      msg "qBittorrent password already applied, setting username..."
      if ((need_user_change)) && declare -f qbt_set_username >/dev/null 2>&1; then
        if QBT_USER="$default_user" QBT_PASS="$desired_pass" qbt_set_username "$desired_user" 2>/dev/null; then
          msg "Successfully set qBittorrent username from userr.conf"
          persist_env_var QBT_USER "$desired_user"
        else
          warn "Failed to set qBittorrent username via API"
        fi
      fi
      persist_env_var QBT_PASS "$desired_pass"
      qbt_api_cleanup 2>/dev/null || true
      return 0
    fi
    # If that fails, we can't determine the current credentials - apply password directly via PBKDF2 hash
    msg "Cannot determine current credentials - applying password directly to config..."

    # Get the config file path using helper function
    local qbt_conf=""
    if declare -f arr_qbt_conf_path >/dev/null 2>&1; then
      qbt_conf="$(arr_qbt_conf_path)"
    elif [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
      qbt_conf="${ARR_DOCKER_DIR%/}/qbittorrent/qBittorrent/qBittorrent.conf"
    else
      warn "Cannot determine qBittorrent config path, cannot apply password"
      return 1
    fi

    if [[ ! -f "$qbt_conf" ]]; then
      warn "qBittorrent config file not found at $qbt_conf"
      return 1
    fi

    # Generate PBKDF2 hash and write directly to config (more reliable than temp password approach)
    if qbt_apply_password_to_config "$desired_pass" "$qbt_conf"; then
      msg "Password hash written to qBittorrent config"

      # Restart qBittorrent to apply the new password
      msg "Restarting qBittorrent to apply new password..."
      docker restart qbittorrent >/dev/null 2>&1 || true
      sleep 5

      # Verify the new password works
      local verify_attempts=0
      while ((verify_attempts < 10)); do
        if QBT_USER="$default_user" QBT_PASS="$desired_pass" qbt_api_login 2>/dev/null; then
          msg "Password successfully applied from userr.conf"
          persist_env_var QBT_PASS "$desired_pass"
          # Now apply username if needed
          if ((need_user_change)) && declare -f qbt_set_username >/dev/null 2>&1; then
            if qbt_set_username "$desired_user" 2>/dev/null; then
              msg "Successfully set qBittorrent username from userr.conf"
              persist_env_var QBT_USER "$desired_user"
            else
              warn "Failed to set qBittorrent username via API"
            fi
          fi
          qbt_api_cleanup 2>/dev/null || true
          return 0
        fi
        sleep 1
        ((verify_attempts++))
      done

      warn "Password was written but verification failed - qBittorrent may need manual restart"
      persist_env_var QBT_PASS "$desired_pass"
      return 0
    else
      warn "Failed to generate PBKDF2 hash (python3 required) - cannot apply password"
      return 1
    fi
  fi

  # If temp password matches desired password and no username change needed, just save
  if [[ "$temp_pass" == "$desired_pass" ]] && ((need_user_change == 0)); then
    persist_env_var QBT_PASS "$desired_pass"
    return 0
  fi

  # Login with default username and temp password
  msg "Applying qBittorrent credentials from userr.conf..."
  if ! QBT_USER="$default_user" QBT_PASS="$temp_pass" qbt_api_login 2>/dev/null; then
    warn "Failed to login with temporary password, cannot apply credentials from config"
    persist_env_var QBT_PASS "$temp_pass"
    return 1
  fi

  # Apply credentials via API - use qbt_set_credentials if available, otherwise individual functions
  if declare -f qbt_set_credentials >/dev/null 2>&1; then
    local new_user=""
    local new_pass=""
    if ((need_user_change)); then
      new_user="$desired_user"
    fi
    if ((need_pass_change)) || [[ "$temp_pass" != "$desired_pass" ]]; then
      new_pass="$desired_pass"
    fi

    if [[ -n "$new_user" || -n "$new_pass" ]]; then
      if QBT_USER="$default_user" QBT_PASS="$temp_pass" qbt_set_credentials "$new_user" "$new_pass" 2>/dev/null; then
        msg "Successfully set qBittorrent credentials from userr.conf"
        persist_env_var QBT_USER "$desired_user"
        persist_env_var QBT_PASS "$desired_pass"
        qbt_api_cleanup 2>/dev/null || true
        return 0
      else
        warn "Failed to set qBittorrent credentials via API"
        persist_env_var QBT_PASS "$temp_pass"
        return 1
      fi
    fi
  else
    # Fallback: use individual functions
    local success=1
    if ((need_pass_change)) || [[ "$temp_pass" != "$desired_pass" ]]; then
      if declare -f qbt_set_password >/dev/null 2>&1; then
        if QBT_USER="$default_user" QBT_PASS="$temp_pass" qbt_set_password "$desired_pass" 2>/dev/null; then
          msg "Successfully set qBittorrent password from userr.conf"
          persist_env_var QBT_PASS "$desired_pass"
          # Need to re-login with new password to set username
          if ((need_user_change)); then
            if ! QBT_USER="$default_user" QBT_PASS="$desired_pass" qbt_api_login 2>/dev/null; then
              warn "Failed to re-login after password change"
              success=0
            fi
          fi
        else
          warn "Failed to set qBittorrent password via API"
          persist_env_var QBT_PASS "$temp_pass"
          success=0
        fi
      else
        warn "qbt_set_password function not available"
        success=0
      fi
    fi

    if ((success && need_user_change)); then
      if declare -f qbt_set_username >/dev/null 2>&1; then
        # Re-login with new password before setting username
        if ! QBT_USER="$default_user" QBT_PASS="$desired_pass" qbt_api_login 2>/dev/null; then
          warn "Failed to re-login with new password, cannot set username"
        elif qbt_set_username "$desired_user" 2>/dev/null; then
          msg "Successfully set qBittorrent username from userr.conf"
          persist_env_var QBT_USER "$desired_user"
        else
          warn "Failed to set qBittorrent username via API"
        fi
      else
        warn "qbt_set_username function not available"
      fi
    fi
  fi

  qbt_api_cleanup 2>/dev/null || true
  return 0
}

# Legacy wrapper for backward compatibility
apply_qbt_password_from_config() {
  local desired_pass="${1:-${QBT_PASS:-}}"
  apply_qbt_credentials_from_config "${QBT_USER:-admin}" "$desired_pass"
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
      warn "Gluetun container '${name}' not found."
      return 1
    fi

    local state has_health health_status
    # Robust against caller IFS: enforce space splitting locally
    if arr_read_fields "$inspect_output" state has_health health_status; then
      :
    else
      ARR_GLUETUN_FAILURE_REASON="docker inspect returned empty/invalid output for ${name}"
      warn "docker inspect returned empty/invalid output; aborting readiness wait."
      return 1
    fi

    if [[ "$state" != "running" ]]; then
      case "$state" in
        restarting)
          if [[ "$last_state" != "$state" ]]; then
            warn "Gluetun is restarting; waiting for stability..."
          fi
          ;;
        created | starting)
          if [[ "$last_state" != "$state" ]]; then
            msg "Gluetun container reported state '${state}'. Waiting for it to run..."
          fi
          ;;
        exited | dead | removing | paused)
          ARR_GLUETUN_FAILURE_REASON="Gluetun state '${state}' (expected running)"
          warn "Gluetun state is '${state}' (expected running)."
          return 1
          ;;
        *)
          ARR_GLUETUN_FAILURE_REASON="Gluetun state '${state}' (expected running)"
          warn "Gluetun state is '${state}' (expected running)."
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
      msg "✅ Gluetun container is running"
    fi
    last_state="$state"

    if [[ "$has_health" == "true" ]]; then
      case "$health_status" in
        healthy)
          if [[ "$last_health" != "healthy" ]]; then
            msg "✅ Gluetun healthcheck reports healthy"
          fi
          ;;
        starting)
          if [[ "$last_health" != "starting" ]]; then
            msg "Gluetun healthcheck starting; waiting for healthy signal..."
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
          warn "Gluetun healthcheck reported '${health_status}'."
          return 1
          ;;
      esac
    else
      if ((reported_no_healthcheck == 0)); then
        msg "Gluetun has no Docker healthcheck; using tunnel/connectivity probes."
        reported_no_healthcheck=1
      fi
    fi
    last_health="$health_status"

    if arr_gluetun_tunnel_route_present "$name"; then
      if ((tunnel_announced == 0)); then
        msg "✅ VPN tunnel interface (tun0/wg0) present"
        tunnel_announced=1
      fi
    else
      if ((tunnel_warned == 0)); then
        warn "Waiting for VPN tunnel interface (tun0/wg0) inside Gluetun..."
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

    local dns_verified=0
    local dns_warned=0
    if docker exec "$name" sh -eu -c 'command -v nslookup >/dev/null 2>&1 && nslookup github.com >/dev/null 2>&1' 2>/dev/null; then
      dns_verified=1
    elif docker exec "$name" sh -eu -c 'command -v host >/dev/null 2>&1 && host github.com >/dev/null 2>&1' 2>/dev/null; then
      dns_verified=1
    elif docker exec "$name" sh -eu -c 'command -v getent >/dev/null 2>&1 && getent hosts github.com >/dev/null 2>&1' 2>/dev/null; then
      dns_verified=1
    fi

    if ((dns_verified)); then
      msg "✅ DNS resolution working inside VPN"
    else
      if ((dns_warned == 0)); then
        warn "Waiting for DNS resolution inside Gluetun..."
        dns_warned=1
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
      msg "✅ VPN connectivity confirmed via ${probe_url}"
      return 0
    fi

    local connectivity_rc=$?
    if ((connectivity_rc == 3)); then
      ARR_GLUETUN_FAILURE_REASON="${ARR_GLUETUN_CONNECTIVITY_FAILURE_REASON:-Gluetun connectivity probe missing curl/wget}"
      warn "Gluetun connectivity probe cannot run (missing curl/wget inside container)."
      return 1
    fi

    if ((connectivity_warned == 0)); then
      warn "Waiting for outbound connectivity through Gluetun tunnel..."
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
  warn "Gluetun did not become ready within ${max_wait}s."
  return 1
}

arr_port_guard_status_file() {
  # Primary: Use centralized path helper
  if declare -f arr_port_guard_status_path >/dev/null 2>&1; then
    arr_port_guard_status_path
    return
  fi

  # Fallback: Use gluetun helper for backward compatibility
  if declare -f gluetun_port_guard_status_file >/dev/null 2>&1; then
    gluetun_port_guard_status_file
    return
  fi

  if [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
    printf '%s\n' "${ARR_DOCKER_DIR%/}/gluetun/state/port-guard-status.json"
    return
  fi

  printf ''
}

arr_wait_for_port_guard_ready() {
  local default_timeout="${VPN_PORT_GUARD_STATUS_TIMEOUT:-90}"
  [[ "$default_timeout" =~ ^[1-9][0-9]*$ ]] || default_timeout=90
  local max_wait="${1:-$default_timeout}"
  local poll_delay="${2:-5}"

  local status_file=""
  status_file="$(arr_port_guard_status_file 2>/dev/null || printf '')"
  if [[ -z "$status_file" ]]; then
    warn "vpn-port-guard status path unavailable; skipping readiness wait"
    return 1
  fi

  local poll_seconds="${VPN_PORT_GUARD_POLL_SECONDS:-15}"
  [[ "$poll_seconds" =~ ^[0-9]+$ ]] || poll_seconds=15
  local freshness_window="$((poll_seconds < 60 ? 60 : poll_seconds + 60))"

  msg "Waiting for vpn-port-guard status file (timeout: ${max_wait}s, configurable via VPN_PORT_GUARD_STATUS_TIMEOUT)..."
  local start
  start="$(date +%s)"

  while true; do
    local now
    now="$(date +%s)"
    local age=$((now - start))
    if ((age > max_wait)); then
      warn "vpn-port-guard status file not ready within ${max_wait}s (VPN_PORT_GUARD_STATUS_TIMEOUT=${VPN_PORT_GUARD_STATUS_TIMEOUT:-90}); qBittorrent may start before port sync"
      return 1
    fi

    if [[ -f "$status_file" ]]; then
      local mtime=""
      mtime="$(stat -c %Y "$status_file" 2>/dev/null || printf '')"
      if [[ "$mtime" =~ ^[0-9]+$ ]]; then
        local staleness=$((now - mtime))
        if ((staleness <= freshness_window)); then
          msg "✅ vpn-port-guard status file ready (age ${staleness}s)"
          return 0
        fi
      fi
    fi

    sleep "$poll_delay"
  done
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

  local port_guard_status=""
  port_guard_status="$(arr_port_guard_status_file 2>/dev/null || printf '')"
  if [[ -f "$port_guard_status" ]]; then
    local vpn_status=""
    local forwarded_port="0"
    local forwarding_state="unavailable"
    local controller_mode=""
    local qbt_state="unknown"
    local pf_enabled=""
    if ! command -v jq >/dev/null 2>&1; then
      warn "jq is required to parse ${port_guard_status}; skipping vpn-port-guard summary"
      return
    fi
    vpn_status="$(jq -r '.vpn_status // empty' "$port_guard_status" 2>/dev/null || true)"
    forwarded_port="$(jq -r '.forwarded_port // 0' "$port_guard_status" 2>/dev/null || true)"
    forwarding_state="$(jq -r '.forwarding_state // "unavailable"' "$port_guard_status" 2>/dev/null || printf 'unavailable')"
    controller_mode="$(jq -r '.controller_mode // empty' "$port_guard_status" 2>/dev/null || printf '')"
    qbt_state="$(jq -r '.qbt_status // "unknown"' "$port_guard_status" 2>/dev/null || printf 'unknown')"
    pf_enabled="$(jq -r '.pf_enabled // empty' "$port_guard_status" 2>/dev/null || printf '')"
    if [[ -n "$vpn_status" ]]; then
      controller_mode="$(derive_controller_mode "$controller_mode" "$pf_enabled")"
      msg "vpn-port-guard: vpn=${vpn_status}, fwd=${forwarding_state}, port=${forwarded_port:-0}, mode=${controller_mode}, qbt=${qbt_state}"
    fi
  fi
}

# Orchestrates service startup: cleanup, validation, image pulls, health waits, summaries
start_stack() {

  cd "${ARR_STACK_DIR}" || die "Failed to change to ${ARR_STACK_DIR}"

  arr_clear_run_failure || true

  safe_cleanup

  if ! validate_images; then
    return 1
  fi

  install_vuetorrent

  msg "Starting Gluetun VPN container..."
  local compose_output_gluetun=""
  local -a gluetun_up_args=()
  if [[ "${ARR_GLUETUN_FORCE_RECREATE:-0}" == "1" ]]; then
    msg "Gluetun API key rotated; recreating container to apply new credentials"
    gluetun_up_args+=(--force-recreate)
  fi
  if ! compose_up_detached_capture compose_output_gluetun "${gluetun_up_args[@]}" gluetun; then
    warn "Failed to start Gluetun via docker compose"
    if [[ -n "$compose_output_gluetun" ]]; then
      printf '%s\n' "$compose_output_gluetun" | sed 's/^/    /'
    fi
    docker logs --tail=60 gluetun 2>&1 | sed 's/^/    /' || true
    arr_write_run_failure "VPN not running: failed to start Gluetun via docker compose." "VPN_NOT_RUNNING"
    return 1
  fi
  msg "Gluetun container started"

  step "🔍 Validating Gluetun readiness"
  if ! arr_wait_for_gluetun_ready gluetun 150 5; then
    local failure_reason
    failure_reason="${ARR_GLUETUN_FAILURE_REASON:-Gluetun did not become ready}"
    docker logs --tail=120 gluetun 2>&1 | sed 's/^/    /' || true
    arr_write_run_failure "VPN not running: ${failure_reason}." "VPN_NOT_RUNNING"
    return 1
  fi

  start_vpn_auto_reconnect_if_enabled
  service_start_sabnzbd

  msg "Starting vpn-port-guard..."
  ensure_qbt_webui_config_ready
  local compose_output_guard=""
  if ! compose_up_detached_capture compose_output_guard vpn-port-guard; then
    warn "Failed to start vpn-port-guard"
    if [[ -n "$compose_output_guard" ]]; then
      printf '%s\n' "$compose_output_guard" | sed 's/^/    /'
    fi
  else
    msg "vpn-port-guard started - waiting for initialization..."
    arr_wait_for_port_guard_ready 90 5 || true
  fi

  msg "Starting remaining services (respecting dependency order)..."
  local compose_output_all=""
  if ! compose_up_detached_capture compose_output_all; then
    warn "Some services may have failed to start"
    if [[ -n "$compose_output_all" ]]; then
      printf '%s\n' "$compose_output_all" | sed 's/^/    /'
    fi
  fi

  local settle_start
  settle_start="$(date +%s)"
  local -a created_services=()
  local services=(qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr)
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    services+=(sabnzbd)
  fi

  while true; do
    created_services=()
    local service
    for service in "${services[@]}"; do
      local container
      container="$(service_container_name "$service")"
      local status
      status="$(docker inspect "$container" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
      if [[ "$status" == "created" ]]; then
        created_services+=("$service")
      fi
    done

    if ((${#created_services[@]} == 0)); then
      break
    fi

    local now
    now="$(date +%s)"
    if ((now - settle_start >= 15)); then
      break
    fi

    sleep 2
  done

  if ((${#created_services[@]} > 0)); then
    msg "Force-starting services that were stuck in 'created' state..."
    for service in "${created_services[@]}"; do
      docker start "$(service_container_name "$service")" 2>/dev/null || true
    done
  fi

  ensure_qbt_config || true

  service_health_sabnzbd

  if ! arr_schedule_delayed_api_sync; then
    warn "arr_schedule_delayed_api_sync failed; API sync may be delayed or incomplete."
  fi

  msg "Services started - they may take a minute to be fully ready"
  show_service_status
}

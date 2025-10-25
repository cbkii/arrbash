# shellcheck shell=bash
# Purpose: Maintain runtime state for stack services including SABnzbd helpers and restart logic.
# Inputs: Consumes ARR_STACK_DIR, ARR_DOCKER_DIR, SABNZBD_ENABLED, and Compose project metadata.
# Outputs: Writes runtime state files, triggers service restarts, and prints health diagnostics.
# Exit codes: Functions return non-zero when runtime capture or service health checks fail.

if [[ -n "${__SERVICE_RUNTIME_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_RUNTIME_LOADED=1

service_runtime_compose() {
  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    return 1
  fi

  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    ( cd "$ARR_STACK_DIR" || return 1; "${DOCKER_COMPOSE_CMD[@]}" "$@" )
  else
    "${DOCKER_COMPOSE_CMD[@]}" "$@"
  fi
}

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

declare -a ARR_STACK_PREVIOUS_RUNNING_SERVICES=()
ARR_STACK_RUNTIME_STATE_CAPTURED=0
ARR_STACK_RUNTIME_STATE_RESTORED=0

arr_clear_stack_runtime_state() {
  ARR_STACK_PREVIOUS_RUNNING_SERVICES=()
  ARR_STACK_RUNTIME_STATE_CAPTURED=0
  ARR_STACK_RUNTIME_STATE_RESTORED=0
}

arr_capture_stack_runtime_state() {
  if [[ "${ARR_STACK_RUNTIME_STATE_CAPTURED:-0}" == "1" ]]; then
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local output
  local project
  project="$(arr_effective_project_name 2>/dev/null || printf '%s' "${STACK}")"

  output="$(docker ps \
    --filter "label=com.docker.compose.project=${project}" \
    --format '{{.Label "com.docker.compose.service"}}' 2>/dev/null || printf '')"

  local -a running=()
  if [[ -n "$output" ]]; then
    declare -A seen=()
    local service=""
    while IFS= read -r service; do
      [[ -z "$service" ]] && continue
      if [[ -z "${seen[$service]:-}" ]]; then
        running+=("$service")
        seen[$service]=1
      fi
    done <<<"$output"
  fi

  ARR_STACK_PREVIOUS_RUNNING_SERVICES=("${running[@]}")
  ARR_STACK_RUNTIME_STATE_CAPTURED=1
}

arr_restore_stack_runtime_state() {
  local exit_code="${1:-0}"

  if [[ "$exit_code" == "0" ]]; then
    arr_clear_stack_runtime_state
    return 0
  fi

  if [[ "${ARR_STACK_RUNTIME_STATE_CAPTURED:-0}" != "1" ]]; then
    return 0
  fi

  if [[ "${ARR_STACK_RUNTIME_STATE_RESTORED:-0}" == "1" ]]; then
    return 0
  fi

  if ((${#ARR_STACK_PREVIOUS_RUNNING_SERVICES[@]} == 0)); then
    arr_clear_stack_runtime_state
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker unavailable; unable to restore previously running services."
    arr_clear_stack_runtime_state
    return 0
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    if declare -f arr_resolve_compose_cmd >/dev/null 2>&1; then
      if ! arr_resolve_compose_cmd >/dev/null 2>&1; then
        warn "Docker Compose unavailable; unable to restore services automatically."
        arr_clear_stack_runtime_state
        return 0
      fi
    else
      warn "Docker Compose helper missing; unable to restore services automatically."
      arr_clear_stack_runtime_state
      return 0
    fi
  fi

  warn "Installer exited with status ${exit_code}; restoring previously running services."

  declare -A seen=()
  local -a restore_order=()
  local service=""

  for service in gluetun local_dns; do
    local item=""
    for item in "${ARR_STACK_PREVIOUS_RUNNING_SERVICES[@]}"; do
      if [[ "$item" == "$service" && -z "${seen[$service]:-}" ]]; then
        restore_order+=("$service")
        seen[$service]=1
      fi
    done
  done

  for service in "${ARR_STACK_PREVIOUS_RUNNING_SERVICES[@]}"; do
    if [[ -z "${seen[$service]:-}" ]]; then
      restore_order+=("$service")
      seen[$service]=1
    fi
  done

  for service in "${restore_order[@]}"; do
    if compose_service_is_running "$service"; then
      continue
    fi

    msg "Restarting ${service}"
    if ! service_runtime_compose up -d "$service" >/dev/null 2>&1; then
      warn "Failed to restart ${service}; check docker compose logs."
    fi
  done

  ARR_STACK_RUNTIME_STATE_RESTORED=1
  arr_clear_stack_runtime_state
}

restart_stack_service() {
  local service="$1"

  if [[ -z "$service" ]]; then
    return 0
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    if declare -f arr_resolve_compose_cmd >/dev/null 2>&1; then
      if ! arr_resolve_compose_cmd >/dev/null 2>&1; then
        warn "compose helper unavailable; cannot restart ${service}"
        return 1
      fi
    else
      warn "compose helper unavailable; cannot restart ${service}"
      return 1
    fi
  fi

  if ! service_runtime_compose restart "$service" >/dev/null 2>&1; then
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
  msg "Enabled (startup managed via docker compose)."
}

service_health_sabnzbd() {
  [[ "${SABNZBD_ENABLED:-0}" == "1" ]] || return 0
  local helper
  if ! helper="$(service_sab_helper_path)"; then
    warn "Helper script not found; skipping health check"
    return 0
  fi
  local version
  if version="$($helper version 2>/dev/null)"; then
    msg "API reachable (${version})"
  else
    warn "Health check failed (verify SABNZBD_HOST/SABNZBD_PORT or container status)"
  fi
}

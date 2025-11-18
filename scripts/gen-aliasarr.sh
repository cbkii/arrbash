# shellcheck shell=bash
# Renders helper alias bundle and injects optional VPN/configarr helpers if templates permit
write_aliases_file() {
  step "🛠️ Generating helper aliases file"

  local template_file="${REPO_ROOT}/scripts/gen-aliasarr.template.sh"
  if [[ -z "${ARR_STACK_DIR:-}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    ARR_STACK_DIR="$(arr_stack_dir)"
  fi
  local aliases_file="${ARR_STACK_DIR}/.aliasarr"
  local snapshot_file="${ARR_STACK_DIR}/.aliasarr.conf.snapshot"

  if [[ ! -f "$template_file" ]]; then
    warn "Alias template ${template_file} not found"
    return 0
  fi

  local tmp_file
  if ! tmp_file="$(arr_mktemp_file "${aliases_file}.XXXX" "$SECRET_FILE_MODE")"; then
    warn "Failed to create temporary aliases file"
    return 1
  fi

  ensure_dir "$ARR_STACK_DIR"

  local stack_dir_escaped env_file_escaped docker_dir_escaped arrconf_dir_escaped

  # Escape helpers for sed with '|' delimiter
  stack_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  stack_dir_escaped=${stack_dir_escaped//&/\&}
  stack_dir_escaped=${stack_dir_escaped//|/\|}

  # Resolve env file with fallbacks: ARR_ENV_FILE -> arr_env_file -> ${ARR_STACK_DIR}/.env
  local _env_file="${ARR_ENV_FILE:-}"
  if [[ -z "$_env_file" ]] && declare -f arr_env_file >/dev/null 2>&1; then
    _env_file="$(arr_env_file)"
  fi
  [[ -n "$_env_file" ]] || _env_file="${ARR_STACK_DIR%/}/.env"

  env_file_escaped=${_env_file//\\/\\\\}
  env_file_escaped=${env_file_escaped//&/\&}
  env_file_escaped=${env_file_escaped//|/\|}

  local docker_dir
  docker_dir="${ARR_DOCKER_DIR:-}"
  [[ -n "$docker_dir" ]] || docker_dir="$(arr_docker_data_root)"
  docker_dir_escaped=${docker_dir//\\/\\\\}
  docker_dir_escaped=${docker_dir_escaped//&/\&}
  docker_dir_escaped=${docker_dir_escaped//|/\|}

  local arrconf_dir
  arrconf_dir="${ARRCONF_DIR:-}"
  [[ -n "$arrconf_dir" ]] || arrconf_dir="$(arr_conf_dir)"
  arrconf_dir_escaped=${arrconf_dir//\\/\\\\}
  arrconf_dir_escaped=${arrconf_dir_escaped//&/\&}
  arrconf_dir_escaped=${arrconf_dir_escaped//|/\|}

  sed -e "s|__ARR_STACK_DIR__|${stack_dir_escaped}|g" \
    -e "s|__ARR_ENV_FILE__|${env_file_escaped}|g" \
    -e "s|__ARR_DOCKER_DIR__|${docker_dir_escaped}|g" \
    -e "s|__ARRCONF_DIR__|${arrconf_dir_escaped}|g" \
    "$template_file" >"$tmp_file"

  if grep -Eq '__ARR_[A-Z0-9_]+__' "$tmp_file"; then
    warn "Failed to replace all template placeholders in aliases file"
    arr_cleanup_temp_path "$tmp_file"
    return 1
  fi

  if mv "$tmp_file" "$aliases_file"; then
    arr_unregister_temp_path "$tmp_file"
  else
    arr_cleanup_temp_path "$tmp_file"
    return 1
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    if ! grep -Fq "arr.config.sync" "$aliases_file" 2>/dev/null; then
      {
        printf '\n# Configarr helper\n'
        cat <<'CONFIGARR_HELPER'
arr.config.sync() {
  (
    cd "${ARR_STACK_DIR}" || return
    local -a compose_cmd=()
    if ((${#DOCKER_COMPOSE_CMD[@]} > 0)); then
      compose_cmd=("${DOCKER_COMPOSE_CMD[@]}")
    elif docker compose version >/dev/null 2>&1; then
      compose_cmd=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
      compose_cmd=(docker-compose)
    else
      warn "Config sync: docker compose command not found"
      return 1
    fi
    "${compose_cmd[@]}" run --rm configarr
  )
}
CONFIGARR_HELPER
      } >>"$aliases_file"
    fi
  fi

  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    if ! grep -Fq "arr.sab.status" "$aliases_file" 2>/dev/null; then
      {
        printf '\n# SABnzbd helper aliases\n'
        cat <<'SAB_ALIAS_FUNCS'
arr.sab._helper() {
  local cmd="$1"
  shift || true
  local helper="${ARR_STACK_DIR}/scripts/sab-helper.sh"
  if [ ! -x "$helper" ] && [ -x "${ARR_STACK_DIR}/../scripts/stack-sab-helper.sh" ]; then
    helper="${ARR_STACK_DIR}/../scripts/stack-sab-helper.sh"
  fi
  if [ ! -x "$helper" ]; then
    warn "SAB helper not found: ${helper}"
    return 1
  fi
  ARR_STACK_DIR="${ARR_STACK_DIR}" bash "$helper" "$cmd" "$@"
}

arr.sab.status()   { arr.sab._helper status   "$@"; }
arr.sab.queue()    { arr.sab._helper queue    "$@"; }
arr.sab.history()  { arr.sab._helper history  "$@"; }
arr.sab.version()  { arr.sab._helper version  "$@"; }
arr.sab.pause()    { arr.sab._helper pause    "$@"; }
arr.sab.resume()   { arr.sab._helper resume   "$@"; }

arr.sab.delete() {
  if [ $# -lt 1 ]; then
    echo "Usage: arr.sab.delete <nzo_id>" >&2
    return 1
  fi
  arr.sab._helper delete "$@"
}

arr.sab.add.file() {
  if [ $# -lt 1 ]; then
    echo "Usage: arr.sab.add.file <path.nzb>" >&2
    return 1
  fi
  arr.sab._helper add-file "$@"
}

arr.sab.add.url() {
  if [ $# -lt 1 ]; then
    echo "Usage: arr.sab.add.url <url>" >&2
    return 1
  fi
  arr.sab._helper add-url "$@"
}

arr.sab.help() {
  cat <<'EOF'
arr.sab.status             SABnzbd status summary
arr.sab.queue              Raw queue JSON
arr.sab.history            Raw history JSON
arr.sab.version            SABnzbd version
arr.sab.pause              Pause all downloads
arr.sab.resume             Resume downloads
arr.sab.delete <nzo_id>    Delete queue item by ID
arr.sab.add.file <path>    Upload NZB file
arr.sab.add.url <url>      Submit NZB URL
EOF
}
SAB_ALIAS_FUNCS
      } >>"$aliases_file"
      {
        printf '\n# SABnzbd shortcuts\n'
        cat <<'SAB_SHORTCUTS'
sab-logs() { arr.logs sabnzbd "$@"; }
sab-shell() { arr.shell sabnzbd "$@"; }
open-sab() {
  local base
  base="$(_arr_service_base sabnzbd)"
  if [ -z "$base" ]; then
    printf 'Unable to resolve SABnzbd base URL\n' >&2
    return 1
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$base" >/dev/null 2>&1 &
    disown || true
  else
    printf '%s\n' "$base"
  fi
}
SAB_SHORTCUTS
      } >>"$aliases_file"
    fi
  fi

  if ! grep -Fq "arr.pf.port" "$aliases_file" 2>/dev/null; then
    warn "Port manager aliases missing from ${aliases_file}; regenerate aliases to enable arr.pf.* helpers"
  fi

  if ! grep -Fq "arr.vpn.auto.status" "$aliases_file" 2>/dev/null; then
    {
      printf '\n# VPN auto-reconnect helpers\n'
      cat <<'VPN_AUTO_ALIAS'
arr_vpn_auto_status() {
  local status_file
  status_file="$(_arr_vpn_auto_status_file)"
  if [ -f "$status_file" ]; then
    cat "$status_file"
  else
    warn "VPN auto status file not found: $status_file"
    return 1
  fi
}

arr_vpn_auto_force() {
  local flag
  flag="$(_arr_vpn_auto_override_path once)"
  if touch "$flag"; then
    msg "Override flag created: $flag"
  else
    warn "Failed to create override flag: $flag"
    return 1
  fi
}

arr_vpn_auto_pause() {
  local flag
  flag="$(_arr_vpn_auto_override_path pause)"
  if touch "$flag"; then
    msg "Pause flag created: $flag"
  else
    warn "Failed to create pause flag: $flag"
    return 1
  fi
}

arr_vpn_auto_resume() {
  local flag
  flag="$(_arr_vpn_auto_override_path pause)"
  if rm -f "$flag"; then
    msg "Pause flag removed (${flag})"
  else
    warn "Failed to remove pause flag: $flag"
    return 1
  fi
}

arr_vpn_auto_history() {
  local state_dir history
  state_dir="$(_arr_vpn_auto_state_dir)"
  history="${state_dir}/history.log"
  if [ -f "$history" ]; then
    tail -n 50 "$history"
  else
    warn "VPN auto history file not found: $history"
    return 1
  fi
}

arr_vpn_auto_watch() {
  local state_dir status_file files=()
  state_dir="$(_arr_vpn_auto_state_dir)"
  status_file="$(_arr_vpn_auto_status_file)"
  if [ -f "$status_file" ]; then
    files+=("$status_file")
  fi
  if [ -d "$state_dir" ]; then
    local candidate
    for candidate in "${state_dir}/daemon.log" "${state_dir}/state.json" "${state_dir}/history.log"; do
      if [ -f "$candidate" ]; then
        files+=("$candidate")
      fi
    done
  fi
  if [ ${#files[@]} -eq 0 ]; then
    warn "No VPN auto log files found under ${state_dir}"
    return 1
  fi
  tail -f "${files[@]}"
}

arr_vpn_auto_wake() {
  local flag
  flag="$(_arr_vpn_auto_override_path wake)"
  if touch "$flag"; then
    msg "Wake trigger created: $flag"
  else
    warn "Failed to touch wake trigger: $flag"
    return 1
  fi
}

arr_vpn_auto_enable() {
  local result
  if result="$(arr.env.set VPN_AUTO_RECONNECT_ENABLED 1 2>&1)"; then
    msg "${result}"
    arr_vpn_auto_wake >/dev/null 2>&1 || true
  else
    warn "Enable failed: ${result}"
    return 1
  fi
}

arr_vpn_auto_disable() {
  local result
  if result="$(arr.env.set VPN_AUTO_RECONNECT_ENABLED 0 2>&1)"; then
    msg "${result}"
    arr_vpn_auto_wake >/dev/null 2>&1 || true
  else
    warn "Disable failed: ${result}"
    return 1
  fi
}

arr_vpn_port_status() {
  local file
  file="$(_arr_pf_state_file)"
  if [ -f "$file" ]; then
    cat "$file"
  else
    warn "VPN port status file not found: $file"
    return 1
  fi
}

alias arr.vpn.auto.status='arr_vpn_auto_status'
alias arr.vpn.auto.force='arr_vpn_auto_force'
alias arr.vpn.auto.pause='arr_vpn_auto_pause'
alias arr.vpn.auto.resume='arr_vpn_auto_resume'
alias arr.vpn.auto.history='arr_vpn_auto_history'
alias arr.vpn.auto.watch='arr_vpn_auto_watch'
alias arr.vpn.auto.enable='arr_vpn_auto_enable'
alias arr.vpn.auto.disable='arr_vpn_auto_disable'
alias arr.vpn.auto.wake='arr_vpn_auto_wake'
alias arr.vpn.port.status='arr_vpn_port_status'
VPN_AUTO_ALIAS
    } >>"$aliases_file"
  fi

  ensure_file_mode "$aliases_file" "$ALIAS_HELPER_FILE_MODE"
  cp "$aliases_file" "$snapshot_file"
  ensure_nonsecret_file_mode "$snapshot_file"

  msg "✅ Helper aliases written to: $aliases_file"
  msg "   Source them with: source $aliases_file"
  msg "   Snapshot stored at: $snapshot_file"
}

update_alias_rc_block() {
  local alias_path="$1"

  local rc_path=""
  if ! rc_path="$(arr_shell_resolve_rc_path)"; then
    rc_path=""
  fi
  if [[ -z "${rc_path}" ]]; then
    warn "Unable to determine shell rc for alias installation"
    return 1
  fi

  if ! touch "${rc_path}" 2>/dev/null; then
    warn "Unable to update shell rc at ${rc_path}"
    return 1
  fi

  local header="# ARR Stack helper aliases"
  local repo_escaped alias_line source_line logs_line
  repo_escaped="$(arr_shell_escape_double_quotes "${REPO_ROOT}")"
  alias_line=$(printf "alias %s='cd \"%s\" && ./arr.sh'" "${STACK}" "${repo_escaped}")
  logs_line=$(printf "alias %s-logs='docker logs -f gluetun'" "${STACK}")
  source_line="[ -f \"${alias_path}\" ] && source \"${alias_path}\""

  local -a rc_lines=()
  if [[ -r "${rc_path}" ]] && mapfile -t rc_lines <"${rc_path}" 2>/dev/null; then
    :
  else
    rc_lines=()
  fi

  local -a filtered_lines=()
  local idx=0
  local total=${#rc_lines[@]}

  while ((idx < total)); do
    local line="${rc_lines[idx]}"
    if [[ "${line}" == "${header}" ]]; then
      ((idx++))
      if ((idx < total)) && [[ "${rc_lines[idx]}" == "alias ${STACK}="* ]]; then
        ((idx++))
      fi
      if ((idx < total)) && [[ "${rc_lines[idx]}" == "alias ${STACK}-logs="* ]]; then
        ((idx++))
      fi
      if ((idx < total)) && [[ "${rc_lines[idx]}" == *".aliasarr"* ]]; then
        ((idx++))
      fi
      if ((idx < total)) && [[ -z "${rc_lines[idx]}" ]]; then
        ((idx++))
      fi
      continue
    fi
    filtered_lines+=("${line}")
    ((idx++))
  done

  while ((${#filtered_lines[@]} > 0)) && [[ -z "${filtered_lines[-1]}" ]]; do
    unset 'filtered_lines[-1]'
  done

  if ((${#filtered_lines[@]} > 0)); then
    filtered_lines+=("")
  fi

  filtered_lines+=("${header}" "${alias_line}" "${logs_line}" "${source_line}")

  local tmp_rc=""
  if ! tmp_rc="$(arr_mktemp_file "${rc_path}.XXXX" "$NONSECRET_FILE_MODE")"; then
    warn "Failed to prepare temporary rc file for ${rc_path}"
    return 1
  fi

  {
    for line in "${filtered_lines[@]}"; do
      printf '%s\n' "${line}"
    done
  } >"${tmp_rc}"

  if mv "${tmp_rc}" "${rc_path}"; then
    arr_unregister_temp_path "${tmp_rc}"
    msg "Updated helper aliases in ${rc_path}"
    return 0
  fi

  arr_cleanup_temp_path "${tmp_rc}"
  warn "Failed to update helper aliases block in ${rc_path}"
  return 1
}

install_aliases() {
  if [[ -z "${ARR_STACK_DIR:-}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    ARR_STACK_DIR="$(arr_stack_dir)"
  fi
  local alias_path="${ARR_STACK_DIR}/.aliasarr"
  local snapshot_file="${ARR_STACK_DIR}/.aliasarr.conf.snapshot"
  if ! ensure_dir "$ARR_STACK_DIR"; then
    warn "Unable to create stack directory at ${ARR_STACK_DIR}"
    return 1
  fi
  local needs_render=0
  if [[ ! -f "$alias_path" ]]; then
    needs_render=1
  elif grep -q "__ARR_" "$alias_path" 2>/dev/null; then
    needs_render=1
  fi

  if [[ "$needs_render" -eq 1 ]]; then
    if ! write_aliases_file; then
      if [[ -f "${snapshot_file}" ]]; then
        cp "${snapshot_file}" "$alias_path"
        ensure_file_mode "$alias_path" "$ALIAS_HELPER_FILE_MODE"
      else
        warn "Unable to render helper aliases (${alias_path})"
        return 1
      fi
    fi
  fi

  ensure_file_mode "$alias_path" "$ALIAS_HELPER_FILE_MODE"

  update_alias_rc_block "${alias_path}" || true
  arr_mark_shell_reload_pending

  ensure_dir_mode "${ARR_STACK_DIR}/scripts" 755

  local diag_script="${ARR_STACK_DIR}/scripts/diagnose-vpn.sh"
  cat >"$diag_script" <<'DIAG'
#!/bin/bash
set -euo pipefail

ARR_STACK_DIR="__ARR_STACK_DIR__"
ARR_ENV_FILE="__ARR_ENV_FILE__"
SCRIPT_LIB_DIR="${ARR_STACK_DIR}/scripts"

if [[ -f "${SCRIPT_LIB_DIR}/stack-common.sh" ]]; then
  # shellcheck source=/dev/null
  . "${SCRIPT_LIB_DIR}/stack-common.sh"
else
  printf '[ERROR] Common helpers missing at %s\n' "${SCRIPT_LIB_DIR}/stack-common.sh" >&2
  exit 1
fi

load_env_file() {
  local file="$1"
  local line key value

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    if [[ "$line" != *=* ]]; then
      continue
    fi
    key="${line%%=*}"
    value="${line#*=}"
    value="${value%$'\r'}"
    value="$(unescape_env_value_from_compose "$value")"
    printf -v "$key" '%s' "$value"
    export "$key"
  done <"$file"
}

if [[ -f "$ARR_ENV_FILE" ]]; then
  load_env_file "$ARR_ENV_FILE"
fi

if [[ -z "${GLUETUN_API_KEY:-}" ]]; then
  log_warn "GLUETUN_API_KEY is empty in ${ARR_ENV_FILE}; control API calls will fail."
  log_warn "Run: ./arr.sh --rotate-api-key --yes; then source ${ARR_STACK_DIR}/.aliasarr"
  log_warn "Checked env file at: ${ARR_ENV_FILE} (stack dir: ${ARR_STACK_DIR})"
fi

GLUETUN_LIB="${ARR_STACK_DIR}/scripts/vpn-gluetun.sh"
if [[ -f "$GLUETUN_LIB" ]]; then
  # shellcheck source=/dev/null
  . "$GLUETUN_LIB"
else
  log_warn "Gluetun helper library missing at $GLUETUN_LIB"
fi

log_info "🔍 VPN Diagnostics Starting..."

GLUETUN_STATUS="$(docker inspect gluetun --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
log_info "Gluetun container: $GLUETUN_STATUS"

if [[ "$GLUETUN_STATUS" != "running" ]]; then
  log_warn "Gluetun is not running. Attempting to start..."
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d gluetun
  else
    log_warn "Docker Compose not available; please start Gluetun manually."
  fi
  sleep 30
fi

STATUS_FILE=""
if declare -f gluetun_port_guard_status_file >/dev/null 2>&1; then
  STATUS_FILE="$(gluetun_port_guard_status_file 2>/dev/null || printf '')"
fi
if [[ -z "$STATUS_FILE" ]]; then
  status_docker_root="${ARR_DOCKER_DIR:-}"
  if [[ -z "$status_docker_root" ]] && declare -f arr_docker_data_root >/dev/null 2>&1; then
    status_docker_root="$(arr_docker_data_root 2>/dev/null || printf '')"
  fi
  if [[ -z "$status_docker_root" ]]; then
    status_docker_root="${ARR_STACK_DIR%/}/docker"
  fi
  STATUS_FILE="${status_docker_root%/}/gluetun/state/port-guard-status.json"
  unset status_docker_root
fi

if [[ -f "$STATUS_FILE" ]]; then
  log_info "vpn-port-guard status file: $STATUS_FILE"
else
  log_warn "vpn-port-guard status file missing at $STATUS_FILE"
fi

read_status_field() {
  local key="$1"
  local default="$2"
  if [[ ! -f "$STATUS_FILE" ]]; then
    printf '%s' "$default"
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    if [[ -z "${__aliasarr_jq_warned:-}" ]]; then
      log_warn "jq is required to parse ${STATUS_FILE}; install jq for vpn-port-guard diagnostics"
      __aliasarr_jq_warned=1
    fi
    printf '%s' "$default"
    return
  fi

  local jq_err_file=""
  jq_err_file="$(mktemp "${TMPDIR:-/tmp}/aliasarr-jq.XXXXXX" 2>/dev/null || printf '')"

  local jq_output=""
  local jq_status=0
  local jq_error=""
  if [[ -n "$jq_err_file" ]]; then
    jq_output="$(jq -r --arg key "$key" '.[$key] // empty' "$STATUS_FILE" 2>"$jq_err_file")"
    jq_status=$?
    if [[ -s "$jq_err_file" ]]; then
      jq_error="$(<"$jq_err_file")"
    fi
    rm -f -- "$jq_err_file" 2>/dev/null || true
  else
    jq_output="$(jq -r --arg key "$key" '.[$key] // empty' "$STATUS_FILE" 2>/dev/null)"
    jq_status=$?
  fi

  if (( jq_status != 0 )); then
    if [[ -z "${__aliasarr_jq_parse_warned:-}" ]]; then
      jq_error=${jq_error//$'\n'/; }
      if [[ -n "$jq_error" ]]; then
        log_warn "Failed to parse ${STATUS_FILE} with jq: ${jq_error}"
      else
        log_warn "Failed to parse ${STATUS_FILE} with jq"
      fi
      __aliasarr_jq_parse_warned=1
    fi
    printf '%s' "$default"
    return
  fi

  if [[ -z "$jq_output" || "$jq_output" == "null" ]]; then
    printf '%s' "$default"
    return
  fi

  printf '%s' "$jq_output"
}

# vpn_status reflects the controller's tunnel health summary (matches vpn-auto-state.sh semantics).
VPN_STATUS="$(read_status_field vpn_status unknown)"
# forwarded_port carries the active Proton-assigned port, or 0 when unavailable.
FORWARDED_PORT="$(read_status_field forwarded_port 0)"
# qbt_status reports the controller's qBittorrent API connectivity status.
QBT_STATUS="$(read_status_field qbt_status unknown)"

STATUS_SNAPSHOT_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_info "vpn-port-guard status snapshot (UTC): ${STATUS_SNAPSHOT_TIME}"

log_info "vpn-port-guard: vpn_status=$VPN_STATUS, qbt_status=$QBT_STATUS, port=$FORWARDED_PORT"

if [[ "$VPN_STATUS" != "running" ]]; then
  log_warn "VPN tunnel not reported as running; torrents will remain paused"
fi

if [[ "$FORWARDED_PORT" =~ ^[1-9][0-9]*$ ]]; then
  log_info "✅ Forwarded port active: $FORWARDED_PORT"
else
  log_warn "Forwarded port unavailable"
  log_warn "Check 'docker logs vpn-port-guard --tail 100' for recent controller output"
fi

log_info "Checking service health..."
for service in qbittorrent sonarr radarr lidarr prowlarr bazarr; do
  STATUS="$(docker inspect "$service" --format '{{.State.Status}}' 2>/dev/null || echo "not found")"
  if [[ "$STATUS" == "running" ]]; then
    log_info "  $service: ✅ running"
  else
    log_warn "  $service: ❌ $STATUS"
  fi
done

log_info "Diagnostics complete!"
DIAG

  local diag_tmp
  if ! diag_tmp="$(arr_mktemp_file "${diag_script}.XXXX")"; then
    warn "Failed to create temporary diagnostic script"
    return 1
  fi

  # Escape stack dir
  local diag_dir_escaped
  diag_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  diag_dir_escaped=${diag_dir_escaped//&/\&}
  diag_dir_escaped=${diag_dir_escaped//|/\|}

  # Resolve env file with fallbacks: ARR_ENV_FILE -> arr_env_file -> ${ARR_STACK_DIR}/.env
  local diag_env_file="${ARR_ENV_FILE:-}"
  if [[ -z "$diag_env_file" ]] && declare -f arr_env_file >/dev/null 2>&1; then
    diag_env_file="$(arr_env_file)"
  fi
  [[ -n "$diag_env_file" ]] || diag_env_file="${ARR_STACK_DIR%/}/.env"

  # Escape env file for sed replacement
  diag_env_file=${diag_env_file//\\/\\\\}
  diag_env_file=${diag_env_file//&/\&}
  diag_env_file=${diag_env_file//|/\|}

  if ! sed -e "s|__ARR_STACK_DIR__|${diag_dir_escaped}|g" \
    -e "s|__ARR_ENV_FILE__|${diag_env_file}|g" \
    "$diag_script" >"$diag_tmp"; then
    arr_cleanup_temp_path "$diag_tmp"
    warn "Failed to render diagnostic script"
    return 1
  fi

  if mv "$diag_tmp" "$diag_script"; then
    arr_unregister_temp_path "$diag_tmp"
  else
    arr_cleanup_temp_path "$diag_tmp"
    warn "Failed to install diagnostic script"
    return 1
  fi
  ensure_file_mode "$diag_script" 755
  msg "Diagnostic script: ${diag_script}"
}

refresh_aliases() {
  step "🔄 Refreshing helper aliases"

  if [[ -z "${ARR_STACK_DIR:-}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    ARR_STACK_DIR="$(arr_stack_dir)"
  fi

  ensure_dir "$ARR_STACK_DIR"

  if ! install_aliases; then
    warn "Unable to regenerate helper aliases"
    return 1
  fi

  if reload_shell_rc --clear-env; then
    msg "♻️ Shell configuration reloaded"
  fi
}

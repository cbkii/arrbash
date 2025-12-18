# shellcheck shell=bash
# Renders helper alias bundle and injects optional VPN/configarr helpers if templates permit
write_aliases_file() {

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
  msg " Source them with: source $aliases_file"
  msg " Snapshot stored at: $snapshot_file"
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

# Generates a runtime-config-aware alias file without template placeholders.
# The generated file dynamically discovers configuration on each sourcing.
write_standalone_alias_file() {
  local output_file="$1"

  local tmp_file
  if ! tmp_file="$(arr_mktemp_file "${output_file}.XXXX" "${SECRET_FILE_MODE:-0600}")"; then
    warn "Failed to create temporary alias file"
    return 1
  fi

  cat >"$tmp_file" <<'ALIASARR_RUNTIME_HEADER'
#!/usr/bin/env bash
# shellcheck shell=bash disable=SC1090,SC2119,SC2120,SC2154,SC2155
# Runtime-config-aware ARR stack helper aliases
# Generated by arr.sh --alias
# This file dynamically discovers configuration on each sourcing.

# Determine source directory
_arr_alias_current_source_path() {
  if [ -n "${BASH_SOURCE[0]-}" ]; then
    printf '%s\n' "${BASH_SOURCE[0]}"
    return 0
  fi
  if [ -n "${ZSH_VERSION:-}" ]; then
    local zsh_source
    zsh_source=$(eval 'printf %s "${(%):-%N}"' 2>/dev/null || true)
    if [ -n "$zsh_source" ] && [ "$zsh_source" != "zsh" ]; then
      printf '%s\n' "$zsh_source"
      return 0
    fi
  fi
  if [ -n "${0:-}" ]; then
    printf '%s\n' "$0"
    return 0
  fi
  return 1
}

_arr_alias_source_dir() {
  local source_path
  source_path="$(_arr_alias_current_source_path 2>/dev/null || true)"
  if [ -z "$source_path" ]; then
    printf '%s\n' "$(pwd)"
    return 0
  fi
  if [ -d "$source_path" ]; then
    printf '%s\n' "$(cd "$source_path" && pwd)"
    return 0
  fi
  printf '%s\n' "$(cd "$(dirname "$source_path")" && pwd)"
}

# Discover ARR_STACK_DIR
if [ -z "${ARR_STACK_DIR:-}" ]; then
  ARR_STACK_DIR="$(_arr_alias_source_dir)"
fi

# Set default paths with runtime discovery
: "${ARR_ENV_FILE:=${ARR_STACK_DIR}/.env}"
: "${ARR_DOCKER_DIR:=${ARR_STACK_DIR}/dockarr}"
: "${ARRCONF_DIR:=${ARR_STACK_DIR}/arrconf}"

export ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR

# Load environment file if present
if [ -f "$ARR_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ARR_ENV_FILE" 2>/dev/null || true
  set +a
  
  # Ensure critical vars are set
  if [ -z "${GLUETUN_API_KEY:-}" ]; then
    export GLUETUN_API_KEY="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
  if [ -z "${GLUETUN_CONTROL_PORT:-}" ]; then
    export GLUETUN_CONTROL_PORT="$(grep '^GLUETUN_CONTROL_PORT=' "$ARR_ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
  if [ -z "${LOCALHOST_IP:-}" ]; then
    export LOCALHOST_IP="$(grep '^LOCALHOST_IP=' "$ARR_ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
fi

# Source user config if present
if [ -f "${ARRCONF_DIR}/userr.conf.defaults.sh" ]; then
  . "${ARRCONF_DIR}/userr.conf.defaults.sh"
fi
if [ -f "${ARRCONF_DIR}/userr.conf" ]; then
  . "${ARRCONF_DIR}/userr.conf"
fi

# Populate service list if available
if command -v arr_set_docker_services_list >/dev/null 2>&1; then
  arr_set_docker_services_list
fi

# Load Gluetun helpers if available
_arr_gluetun_lib="${ARR_STACK_DIR}/scripts/vpn-gluetun.sh"
if [ -f "${_arr_gluetun_lib}" ]; then
  . "${_arr_gluetun_lib}"
fi
unset _arr_gluetun_lib

# Define helper functions
if ! command -v msg >/dev/null 2>&1; then
  msg() { printf '%s\n' "$*"; }
fi

if ! command -v warn >/dev/null 2>&1; then
  warn() { printf '[WARN] %s\n' "$*" >&2; }
fi

if ! command -v step >/dev/null 2>&1; then
  step() { msg "$@"; }
fi

_arr_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

_arr_lowercase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# Read from .env file
_arr_env_get() {
  local key="$1"
  [[ -f "$ARR_ENV_FILE" ]] || return 1
  local value
  value="$(awk -F= -v k="$key" '$0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
    val=substr($0, index($0,"=")+1);
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", val);
    print val;
    exit
  }' "$ARR_ENV_FILE")"
  # Strip surrounding quotes if present
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  printf '%s' "$value"
}

_arr_loopback() {
  local host
  host="$(_arr_env_get LOCALHOST_IP 2>/dev/null || true)"
  if [ -z "$host" ]; then
    host="127.0.0.1"
  fi
  printf '%s' "$host"
}

# Resolve host (LAN_IP or fallback to loopback)
_arr_host() {
  local host
  host="$(_arr_env_get LAN_IP 2>/dev/null || true)"
  if [ -z "$host" ] || [ "$host" = "0.0.0.0" ]; then
    host="$(_arr_loopback)"
  fi
  printf '%s' "$host"
}

# Get service port with fallback to defaults
_arr_service_port() {
  local svc="$1"
  local env_var default_port value=""
  
  case "$svc" in
    qbittorrent)
      env_var="QBT_PORT"
      default_port="8080"
      ;;
    sonarr)
      env_var="SONARR_PORT"
      default_port="8989"
      ;;
    radarr)
      env_var="RADARR_PORT"
      default_port="7878"
      ;;
    lidarr)
      env_var="LIDARR_PORT"
      default_port="8686"
      ;;
    prowlarr)
      env_var="PROWLARR_PORT"
      default_port="9696"
      ;;
    bazarr)
      env_var="BAZARR_PORT"
      default_port="6767"
      ;;
    flaresolverr)
      env_var="FLARR_PORT"
      default_port="8191"
      ;;
    sabnzbd)
      env_var="SABNZBD_PORT"
      default_port="8081"
      ;;
    *)
      return 1
      ;;
  esac
  
  # Try environment variable, then fallback to default
  value="${!env_var:-}"
  if [ -z "$value" ]; then
    value="$(_arr_env_get "$env_var" 2>/dev/null || true)"
  fi
  if [ -z "$value" ]; then
    value="$default_port"
  fi
  
  printf '%s' "$value"
}

# Get service base URL with optional UrlBase from config.xml
_arr_service_base() {
  local svc="$1"
  local host port urlbase=""
  
  case "$svc" in
    qbittorrent | sonarr | radarr | lidarr | prowlarr | bazarr | flaresolverr)
      host="$(_arr_host)"
      ;;
    sabnzbd)
      host="${SABNZBD_HOST:-$(_arr_env_get SABNZBD_HOST 2>/dev/null || true)}"
      if [ -z "$host" ] || [ "$host" = "0.0.0.0" ]; then
        host="$(_arr_host)"
      fi
      ;;
    *)
      return 1
      ;;
  esac
  
  if ! port="$(_arr_service_port "$svc")"; then
    return 1
  fi
  
  # Try to read UrlBase from config.xml for *arr services
  case "$svc" in
    sonarr | radarr | lidarr | prowlarr | bazarr)
      local config_file="${ARR_DOCKER_DIR}/${svc}/config.xml"
      if [ -f "$config_file" ]; then
        urlbase="$(awk '/<UrlBase>/ {
          line=$0
          sub(/.*<UrlBase>[[:space:]]*/, "", line)
          sub(/[[:space:]]*<\/UrlBase>.*/, "", line)
          sub(/^[[:space:]]+/, "", line)
          sub(/[[:space:]]+$/, "", line)
          print line
          exit
        }' "$config_file" 2>/dev/null || true)"
      fi
      ;;
  esac
  
  printf 'http://%s:%s%s' "$host" "$port" "$urlbase"
}

# Extract API key from service config.xml
_arr_api_key() {
  local svc="$1"
  local file="${ARR_DOCKER_DIR}/${svc}/config.xml"
  local key
  
  [ -f "$file" ] || return 1
  
  key="$(awk '/<ApiKey>/ {
    line=$0
    sub(/.*<ApiKey>[[:space:]]*/, "", line)
    sub(/[[:space:]]*<\/ApiKey>.*/, "", line)
    sub(/^[[:space:]]+/, "", line)
    sub(/[[:space:]]+$/, "", line)
    print line
    exit
  }' "$file" 2>/dev/null || true)"
  
  [ -n "$key" ] || return 1
  printf '%s\n' "$key"
}

# Generic service API call helper
_arr_service_call() {
  local svc="$1"
  shift
  local method="$1"
  shift
  local path="$1"
  shift
  
  local base key
  base="$(_arr_service_base "$svc")"
  key="$(_arr_api_key "$svc")"
  
  if [ -z "$base" ]; then
    printf 'Error: Unable to resolve base URL for %s\n' "$svc" >&2
    printf 'Check that %s is configured and %s_PORT is set in .env\n' "$svc" "${svc^^}" >&2
    return 1
  fi
  
  if [ -z "$key" ]; then
    printf 'Error: API key not found for %s\n' "$svc" >&2
    printf 'Check: %s/%s/config.xml\n' "$ARR_DOCKER_DIR" "$svc" >&2
    return 1
  fi
  
  local -a curl_cmd=(curl -fsS -X "$method" -H "X-API-Key: ${key}")
  if [ "$method" = "POST" ] || [ "$method" = "PUT" ]; then
    curl_cmd+=(-H 'Content-Type: application/json')
  fi
  curl_cmd+=("$@")
  curl_cmd+=("${base}${path}")

  "${curl_cmd[@]}"
}

# JSON pretty-printer
_arr_pretty_json() {
  if command -v jq >/dev/null 2>&1; then
    jq '.'
  else
    cat
  fi
}

# URL encode helper
_arr_urlencode() {
  local string="$1"
  local strlen=${#string}
  local encoded=""
  local pos c o
  
  for ((pos = 0; pos < strlen; pos++)); do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9]) o="$c" ;;
      *) printf -v o '%%%02x' "'$c" ;;
    esac
    encoded+="$o"
  done
  printf '%s' "$encoded"
}

_arr_has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Gluetun API helpers
_arr_gluetun_port() {
  printf '%s' "${GLUETUN_CONTROL_PORT:-$(_arr_env_get GLUETUN_CONTROL_PORT 2>/dev/null || echo 8000)}"
}

_arr_gluetun_host() {
  local host
  host="${GLUETUN_CONTROL_HOST:-$(_arr_env_get GLUETUN_CONTROL_HOST 2>/dev/null || true)}"
  if [ -z "$host" ]; then
    host="$(_arr_loopback)"
  fi
  printf '%s' "$host"
}

_arr_gluetun_key() {
  if [ -n "${GLUETUN_API_KEY:-}" ]; then
    printf '%s' "$GLUETUN_API_KEY"
  else
    _arr_env_get GLUETUN_API_KEY 2>/dev/null || return 1
  fi
}

_arr_gluetun_base() {
  local host port
  host="$(_arr_gluetun_host)"
  port="$(_arr_gluetun_port)"
  printf 'http://%s:%s' "$host" "$port"
}

# Gluetun API call
_arr_gluetun_api() {
  local endpoint="$1"
  local method="${2:-GET}"
  local data="${3:-}"
  
  if ! _arr_has_cmd curl; then
    printf 'Error: curl is required for Gluetun API calls\n' >&2
    return 1
  fi
  
  local key port host url
  key="$(_arr_gluetun_key)"
  if [ -z "$key" ]; then
    printf 'Error: GLUETUN_API_KEY not found\n' >&2
    printf 'Run: ./arr.sh --rotate-api-key --yes\n' >&2
    return 1
  fi
  
  port="$(_arr_gluetun_port)"
  host="$(_arr_gluetun_host)"
  url="http://${host}:${port}${endpoint}"
  
  local -a curl_cmd=(curl -fsS -H "X-API-Key: ${key}")
  if [ "$method" != "GET" ]; then
    curl_cmd+=(-X "$method")
  fi
  if [ -n "$data" ]; then
    curl_cmd+=(-H "Content-Type: application/json" --data "$data")
  fi
  curl_cmd+=("$url")

  "${curl_cmd[@]}"
}

_arr_gluetun_status_endpoints() {
  local vpn_type
  vpn_type="$(_arr_lowercase "${VPN_TYPE:-openvpn}")"
  printf '/v1/%s/status\n' "$vpn_type"
}

_arr_gluetun_port_endpoints() {
  local vpn_type
  vpn_type="$(_arr_lowercase "${VPN_TYPE:-openvpn}")"
  printf '/v1/%s/portforwarded\n' "$vpn_type"
}

_arr_gluetun_restart_endpoints() {
  local vpn_type
  vpn_type="$(_arr_lowercase "${VPN_TYPE:-openvpn}")"
  printf '/v1/%s/actions/restart\n' "$vpn_type"
}

_arr_gluetun_try_endpoints() {
  local method="$1"
  local data="$2"
  shift 2 || true

  local base key
  key="$(_arr_gluetun_key)" || return 1
  base="$(_arr_gluetun_base)"

  local -a curl_cmd=(curl -sS -w '\n%{http_code}' -H "X-API-Key: ${key}" --connect-timeout 5 --max-time 8)
  if [ "$method" != "GET" ]; then
    curl_cmd+=(-X "$method")
  fi
  if [ -n "$data" ]; then
    curl_cmd+=(-H 'Content-Type: application/json' --data "$data")
  fi

  local endpoint response code body last_error=""
  for endpoint in "$@"; do
    [ -n "$endpoint" ] || continue
    local stderr_file
    stderr_file="$(mktemp)" || {
      last_error="Unable to create temp file for stderr capture"
      continue
    }
    response="$("${curl_cmd[@]}" "${base}${endpoint}" 2>"${stderr_file}")"
    local curl_status=$?
    local curl_stderr
    curl_stderr="$(cat "${stderr_file}")"
    rm -f "${stderr_file}"
    code="${response##*$'\n'}"
    body="${response%$'\n'"$code"}"

    if [ $curl_status -ne 0 ] && [ -z "$code" ] && [ -z "$last_error" ]; then
      last_error="${curl_stderr//$'\n'/ }"
    fi
    case "$code" in
      2??)
        printf '%s\n' "$body"
        return 0
        ;;
      404)
        continue
        ;;
      401|403)
        last_error="Authentication failed (HTTP ${code}) for ${endpoint}. Check GLUETUN_API_KEY."
        ;;
      "")
        last_error="Unable to reach Gluetun control API at ${base}${endpoint}"
        ;;
      *)
        last_error="HTTP ${code} from ${base}${endpoint}"
        ;;
    esac
  done

  if [ -n "$last_error" ]; then
    _arr_gluetun_last_error="$last_error"
  fi

  return 1
}

# qBittorrent API helpers
_arr_qbt_base() { _arr_service_base qbittorrent; }

_arr_qbt_login() {
  local base user pass cookie
  base="$(_arr_qbt_base)"
  
  user="${QBT_USER:-$(_arr_env_get QBT_USER 2>/dev/null || echo admin)}"
  pass="${QBT_PASS:-$(_arr_env_get QBT_PASS 2>/dev/null || echo adminadmin)}"
  
  # Use mktemp to create secure cookie file with 600 permissions
  if ! cookie="$(mktemp "${TMPDIR:-/tmp}/.qbt-cookie.XXXXXX" 2>/dev/null)"; then
    printf 'Error: Failed to create secure cookie file\n' >&2
    return 1
  fi
  chmod 600 "$cookie" 2>/dev/null || true
  
  if ! curl -fsS -c "$cookie" -b "$cookie" \
       -H "Referer: ${base}" \
       -d "username=${user}&password=${pass}" \
       "$base/api/v2/auth/login" >/dev/null 2>&1; then
    rm -f "$cookie" 2>/dev/null || true
    return 1
  fi
  
  printf '%s' "$cookie"
}

_arr_qbt_call() {
  local method="$1"
  shift
  local endpoint="$1"
  shift
  
  local base cookie
  base="$(_arr_qbt_base)"
  
  if [ -z "$base" ]; then
    printf 'Error: Unable to resolve qBittorrent base URL\n' >&2
    return 1
  fi
  
  cookie="$(_arr_qbt_login)"
  if [ -z "$cookie" ]; then
    printf 'Error: qBittorrent login failed\n' >&2
    printf 'Check QBT_USER/QBT_PASS in .env or userr.conf\n' >&2
    return 1
  fi
  
  local -a curl_cmd=(curl -fsS -b "$cookie" -X "$method")
  curl_cmd+=("$@")
  curl_cmd+=("${base}${endpoint}")
  
  local result
  result=$("${curl_cmd[@]}" 2>&1)
  local rc=$?
  
  rm -f "$cookie" 2>/dev/null || true
  
  if [ $rc -eq 0 ]; then
    printf '%s\n' "$result"
    return 0
  fi
  
  return $rc
}

#
# Service-specific aliases
#

# --- Radarr ---
arr.rad.url() { printf '%s\n' "$(_arr_service_base radarr)"; }
arr.rad.logs() { docker logs -f radarr; }
arr.rad.restart() { docker restart radarr; }

arr.rad.status() { _arr_service_call radarr GET /api/v3/system/status | _arr_pretty_json; }
arr.rad.health() { _arr_service_call radarr GET /api/v3/health | _arr_pretty_json; }
arr.rad.disk() { _arr_service_call radarr GET /api/v3/diskspace | _arr_pretty_json; }
arr.rad.movies.list() { _arr_service_call radarr GET /api/v3/movie | _arr_pretty_json; }
arr.rad.movies.get() { _arr_service_call radarr GET "/api/v3/movie/${1:?id}" | _arr_pretty_json; }
arr.rad.queue() { _arr_service_call radarr GET /api/v3/queue | _arr_pretty_json; }
arr.rad.profile.list() { _arr_service_call radarr GET /api/v3/qualityprofile | _arr_pretty_json; }

arr.rad.help() {
  cat <<'EOF'
Radarr v3 API helpers:
  arr.rad.url                Show base URL
  arr.rad.status             GET /api/v3/system/status
  arr.rad.health             GET /api/v3/health
  arr.rad.disk               GET /api/v3/diskspace
  arr.rad.movies.list        GET /api/v3/movie
  arr.rad.movies.get <id>    GET /api/v3/movie/<id>
  arr.rad.queue              GET /api/v3/queue
  arr.rad.profile.list       GET /api/v3/qualityprofile
  arr.rad.logs               Docker logs -f
  arr.rad.restart            Docker restart

Smoke test: arr.rad.status
EOF
}

# --- Sonarr ---
arr.son.url() { printf '%s\n' "$(_arr_service_base sonarr)"; }
arr.son.logs() { docker logs -f sonarr; }
arr.son.restart() { docker restart sonarr; }

arr.son.status() { _arr_service_call sonarr GET /api/v3/system/status | _arr_pretty_json; }
arr.son.health() { _arr_service_call sonarr GET /api/v3/health | _arr_pretty_json; }
arr.son.disk() { _arr_service_call sonarr GET /api/v3/diskspace | _arr_pretty_json; }
arr.son.series.list() { _arr_service_call sonarr GET /api/v3/series | _arr_pretty_json; }
arr.son.series.get() { _arr_service_call sonarr GET "/api/v3/series/${1:?id}" | _arr_pretty_json; }
arr.son.queue() { _arr_service_call sonarr GET /api/v3/queue | _arr_pretty_json; }
arr.son.profile.list() { _arr_service_call sonarr GET /api/v3/qualityprofile | _arr_pretty_json; }

arr.son.help() {
  cat <<'EOF'
Sonarr v3 API helpers:
  arr.son.url                Show base URL
  arr.son.status             GET /api/v3/system/status
  arr.son.health             GET /api/v3/health
  arr.son.disk               GET /api/v3/diskspace
  arr.son.series.list        GET /api/v3/series
  arr.son.series.get <id>    GET /api/v3/series/<id>
  arr.son.queue              GET /api/v3/queue
  arr.son.profile.list       GET /api/v3/qualityprofile
  arr.son.logs               Docker logs -f
  arr.son.restart            Docker restart

Smoke test: arr.son.status
EOF
}

# --- Lidarr ---
arr.lid.url() { printf '%s\n' "$(_arr_service_base lidarr)"; }
arr.lid.logs() { docker logs -f lidarr; }
arr.lid.restart() { docker restart lidarr; }

arr.lid.status() { _arr_service_call lidarr GET /api/v1/system/status | _arr_pretty_json; }
arr.lid.health() { _arr_service_call lidarr GET /api/v1/health | _arr_pretty_json; }

arr.lid.help() {
  cat <<'EOF'
Lidarr v1 API helpers:
  arr.lid.url                Show base URL
  arr.lid.status             GET /api/v1/system/status
  arr.lid.health             GET /api/v1/health
  arr.lid.logs               Docker logs -f
  arr.lid.restart            Docker restart

Smoke test: arr.lid.status
EOF
}

# --- Prowlarr ---
arr.prow.url() { printf '%s\n' "$(_arr_service_base prowlarr)"; }
arr.prow.logs() { docker logs -f prowlarr; }
arr.prow.restart() { docker restart prowlarr; }

arr.prow.status() { _arr_service_call prowlarr GET /api/v1/system/status | _arr_pretty_json; }
arr.prow.health() { _arr_service_call prowlarr GET /api/v1/health | _arr_pretty_json; }
arr.prow.indexers() { _arr_service_call prowlarr GET /api/v1/indexer | _arr_pretty_json; }
arr.prow.backups() { _arr_service_call prowlarr GET /api/v1/system/backup | _arr_pretty_json; }

arr.prow.help() {
  cat <<'EOF'
Prowlarr v1 API helpers:
  arr.prow.url               Show base URL
  arr.prow.status            GET /api/v1/system/status
  arr.prow.health            GET /api/v1/health
  arr.prow.backups           GET /api/v1/system/backup
  arr.prow.indexers          GET /api/v1/indexer
  arr.prow.backups           GET /api/v1/system/backup
  arr.prow.logs              Docker logs -f
  arr.prow.restart           Docker restart

Smoke test: arr.prow.status
EOF
}

# --- Bazarr ---
arr.baz.url() { printf '%s\n' "$(_arr_service_base bazarr)"; }
arr.baz.logs() { docker logs -f bazarr; }
arr.baz.restart() { docker restart bazarr; }

arr.baz.status() {
  local base key
  base="$(_arr_service_base bazarr)"
  key="$(_arr_api_key bazarr)"
  if [ -z "$key" ]; then
    printf 'Error: Bazarr API key not found\n' >&2
    return 1
  fi
  curl -fsS "${base}/api/system/status?apikey=${key}" | _arr_pretty_json
}

arr.baz.help() {
  cat <<'EOF'
Bazarr API helpers:
  arr.baz.url                Show base URL
  arr.baz.status             GET /api/system/status
  arr.baz.logs               Docker logs -f
  arr.baz.restart            Docker restart

Smoke test: arr.baz.status
EOF
}

# --- qBittorrent ---
arr.qbt.url() { printf '%s\n' "$(_arr_qbt_base)"; }
arr.qbt.logs() { docker logs -f qbittorrent; }
arr.qbt.restart() { docker restart qbittorrent; }

arr.qbt.version() { _arr_qbt_call GET /api/v2/app/version; }
arr.qbt.prefs() { _arr_qbt_call GET /api/v2/app/preferences | _arr_pretty_json; }
arr.qbt.transfer() { _arr_qbt_call GET /api/v2/transfer/info | _arr_pretty_json; }
arr.qbt.torrents.info() { _arr_qbt_call GET /api/v2/torrents/info | _arr_pretty_json; }
arr.qbt.torrents.pause() { _arr_qbt_call POST /api/v2/torrents/pause --data-urlencode "hashes=${1:-all}"; }
arr.qbt.torrents.resume() { _arr_qbt_call POST /api/v2/torrents/resume --data-urlencode "hashes=${1:-all}"; }

arr.qbt.port.get() {
  local json value=""
  json="$(_arr_qbt_call GET /api/v2/app/preferences 2>/dev/null)" || return 1
  if [ -n "$json" ] && command -v jq >/dev/null 2>&1; then
    value="$(printf '%s' "$json" | jq -r '.listen_port // empty' 2>/dev/null || true)"
  fi
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
  else
    printf 'unknown\n'
  fi
}

arr.qbt.port.set() {
  if [ -z "$1" ]; then
    printf 'Usage: arr.qbt.port.set <port>\n' >&2
    return 1
  fi
  # Validate port: must be integer between 1 and 65535
  if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    printf 'Error: Port must be an integer between 1 and 65535\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/app/setPreferences --data "json={\"listen_port\":$1}"
  printf 'Port set to %s\n' "$1"
}

arr.qbt.help() {
  cat <<'EOF'
qBittorrent Web API v2 helpers:
  arr.qbt.url                Show base URL
  arr.qbt.version            GET /api/v2/app/version
  arr.qbt.prefs              GET /api/v2/app/preferences
  arr.qbt.transfer           GET /api/v2/transfer/info
  arr.qbt.torrents.info      GET /api/v2/torrents/info
  arr.qbt.torrents.pause     POST /api/v2/torrents/pause
  arr.qbt.torrents.resume    POST /api/v2/torrents/resume
  arr.qbt.port.get           Get current listen port
  arr.qbt.port.set <port>    Set listen port
  arr.qbt.logs               Docker logs -f
  arr.qbt.restart            Docker restart

Smoke test: arr.qbt.version
EOF
}

# --- Gluetun / VPN ---
arr.vpn.status() {
  local -a endpoints=()
  while IFS= read -r ep; do
    endpoints+=("$ep")
  done < <(_arr_gluetun_status_endpoints)

  local status_payload
  if ! status_payload="$(_arr_gluetun_try_endpoints GET "" "${endpoints[@]}" 2>/dev/null)"; then
    printf 'Unable to query VPN status (check GLUETUN_API_KEY and Gluetun container)\n' >&2
    if [ -n "${_arr_gluetun_last_error:-}" ]; then
      printf '%s\n' "${_arr_gluetun_last_error}" >&2
    fi
    return 1
  fi

  printf '%s\n' "$status_payload" | _arr_pretty_json
}

arr.vpn.ip() {
  local ip_payload
  if ! ip_payload="$(_arr_gluetun_api /v1/publicip/ip 2>/dev/null)"; then
    printf 'Unable to query public IP\n' >&2
    return 1
  fi
  printf '%s\n' "$ip_payload" | _arr_pretty_json
}

arr.vpn.restart() {
  local -a endpoints=()
  while IFS= read -r ep; do
    endpoints+=("$ep")
  done < <(_arr_gluetun_restart_endpoints)

  if ! _arr_gluetun_try_endpoints PUT "" "${endpoints[@]}" >/dev/null 2>&1; then
    printf 'VPN restart failed\n' >&2
    if [ -n "${_arr_gluetun_last_error:-}" ]; then
      printf '%s\n' "${_arr_gluetun_last_error}" >&2
    fi
    return 1
  fi

  printf 'VPN restart initiated\n'
}

arr.vpn.port() {
  local -a endpoints=()
  while IFS= read -r ep; do
    endpoints+=("$ep")
  done < <(_arr_gluetun_port_endpoints)

  local payload
  if ! payload="$(_arr_gluetun_try_endpoints GET "" "${endpoints[@]}" 2>/dev/null)"; then
    printf 'Unable to query forwarded port\n' >&2
    if [ -n "${_arr_gluetun_last_error:-}" ]; then
      printf '%s\n' "${_arr_gluetun_last_error}" >&2
    fi
    return 1
  fi

  printf '%s\n' "$payload" | _arr_pretty_json
}

arr.vpn.help() {
  local vpn_type
  vpn_type="$(_arr_vpn_type)"
  cat <<EOF
Gluetun VPN helpers (VPN_TYPE=${vpn_type}):
  arr.vpn.status             GET /v1/${vpn_type}/status
  arr.vpn.ip                 GET /v1/publicip/ip
  arr.vpn.port               GET /v1/${vpn_type}/portforwarded
  arr.vpn.restart            PUT /v1/${vpn_type}/actions/restart

Smoke test: arr.vpn.status

Port forwarding helpers:
  arr.pf.port                Show current forwarded port
  arr.pf.sync                Sync forwarded port to qBittorrent
EOF
}

# --- Port Forward helpers ---
arr.pf.port() {
  local payload port
  local -a endpoints=()
  while IFS= read -r ep; do
    endpoints+=("$ep")
  done < <(_arr_gluetun_port_endpoints)

  if ! payload="$(_arr_gluetun_try_endpoints GET "" "${endpoints[@]}" 2>/dev/null)"; then
    printf 'Unable to query forwarded port\n' >&2
    if [ -n "${_arr_gluetun_last_error:-}" ]; then
      printf '%s\n' "${_arr_gluetun_last_error}" >&2
    fi
    return 1
  fi
  
  # Extract port from JSON
  if command -v jq >/dev/null 2>&1; then
    port="$(printf '%s' "$payload" | jq -r '.port // empty' 2>/dev/null || true)"
  fi
  
  if [ -z "$port" ]; then
    # Fallback: extract first number
    port="$(printf '%s' "$payload" | grep -oE '[0-9]+' | head -n1 || true)"
  fi
  
  if [ -n "$port" ] && [ "$port" != "0" ]; then
    printf '%s\n' "$port"
    return 0
  fi
  
  printf 'No forwarded port available\n' >&2
  return 1
}

arr.pf.sync() {
  local port
  if ! port="$(arr.pf.port 2>/dev/null)"; then
    printf 'Error: Unable to get forwarded port from Gluetun\n' >&2
    return 1
  fi
  
  printf 'Syncing port %s to qBittorrent...\n' "$port" >&2
  if arr.qbt.port.set "$port" >/dev/null 2>&1; then
    printf '✅ Port %s set successfully\n' "$port"
    return 0
  else
    printf 'Error: Failed to set qBittorrent port\n' >&2
    return 1
  fi
}

arr.pf.help() {
  cat <<'EOF'
Port forwarding helpers:
  arr.pf.port                Show current Gluetun forwarded port
  arr.pf.sync                Sync Gluetun port to qBittorrent

Usage:
  arr.pf.port                # Display forwarded port
  arr.pf.sync                # Sync to qBittorrent listen port
EOF
}

# --- FlareSolverr ---
arr.flarr.url() { printf '%s\n' "$(_arr_service_base flaresolverr)"; }
arr.flarr.logs() { docker logs -f flaresolverr; }
arr.flarr.restart() { docker restart flaresolverr; }

arr.flarr.help() {
  cat <<'EOF'
FlareSolverr helpers:
  arr.flarr.url              Show base URL
  arr.flarr.logs             Docker logs -f
  arr.flarr.restart          Docker restart
EOF
}

# --- SABnzbd ---
# SABnzbd uses API key as URL parameter, not header
# API format: /api?mode=<mode>&apikey=<key>&output=json

_arr_sab_api_key() {
  local key
  # Try environment variable first
  key="${SABNZBD_API_KEY:-$(_arr_env_get SABNZBD_API_KEY 2>/dev/null || true)}"
  if [ -n "$key" ]; then
    printf '%s' "$key"
    return 0
  fi
  
  # Try config file
  local config_file="${ARR_DOCKER_DIR}/sabnzbd/sabnzbd.ini"
  if [ -f "$config_file" ]; then
    key="$(awk -F= '/^api_key[[:space:]]*=/ {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
      print $2
      exit
    }' "$config_file" 2>/dev/null || true)"
  fi
  
  if [ -n "$key" ]; then
    printf '%s' "$key"
    return 0
  fi
  
  return 1
}

_arr_sab_call() {
  local mode="$1"
  shift
  
  local base key
  base="$(_arr_service_base sabnzbd)"
  key="$(_arr_sab_api_key)"
  
  if [ -z "$base" ]; then
    printf 'Error: Unable to resolve SABnzbd base URL\n' >&2
    return 1
  fi
  
  if [ -z "$key" ]; then
    printf 'Error: SABnzbd API key not found\n' >&2
    printf 'Set SABNZBD_API_KEY in .env or check %s/sabnzbd/sabnzbd.ini\n' "$ARR_DOCKER_DIR" >&2
    return 1
  fi
  
  local url="${base}/api?mode=${mode}&apikey=${key}&output=json"
  
  # Add any extra parameters with proper URL encoding
  while [ $# -gt 0 ]; do
    url="${url}&$(_arr_urlencode "$1")"
    shift
  done
  
  curl -fsS "$url"
}

arr.sab.url() { printf '%s\n' "$(_arr_service_base sabnzbd)"; }
arr.sab.logs() { docker logs -f sabnzbd; }
arr.sab.restart() { docker restart sabnzbd; }

arr.sab.status() { _arr_sab_call server_stats | _arr_pretty_json; }
arr.sab.version() { _arr_sab_call version | _arr_pretty_json; }
arr.sab.queue() { _arr_sab_call queue | _arr_pretty_json; }
arr.sab.history() { _arr_sab_call history | _arr_pretty_json; }

arr.sab.pause() {
  _arr_sab_call pause | _arr_pretty_json
  printf 'SABnzbd paused\n' >&2
}

arr.sab.resume() {
  _arr_sab_call resume | _arr_pretty_json
  printf 'SABnzbd resumed\n' >&2
}

arr.sab.help() {
  cat <<'EOF'
SABnzbd API helpers:
  arr.sab.url                Show base URL
  arr.sab.status             GET server stats
  arr.sab.version            GET version info
  arr.sab.queue              GET current queue
  arr.sab.history            GET download history
  arr.sab.pause              Pause downloads
  arr.sab.resume             Resume downloads
  arr.sab.logs               Docker logs -f
  arr.sab.restart            Docker restart

Smoke test: arr.sab.version
Note: Requires SABNZBD_API_KEY in .env or sabnzbd.ini
EOF
}

# --- General helpers ---
arr.logs() {
  if [ $# -eq 0 ]; then
    printf 'Usage: arr.logs <service>\n' >&2
    printf 'Available: gluetun, qbittorrent, sonarr, radarr, lidarr, prowlarr, bazarr, flaresolverr\n' >&2
    return 1
  fi
  docker logs -f "$@"
}

arr.restart() {
  if [ $# -eq 0 ]; then
    printf 'Usage: arr.restart <service>\n' >&2
    return 1
  fi
  docker restart "$@"
}

arr.shell() {
  if [ $# -eq 0 ]; then
    printf 'Usage: arr.shell <service>\n' >&2
    return 1
  fi
  docker exec -it "$1" /bin/bash || docker exec -it "$1" /bin/sh
}

# Main help
arr.help() {
  cat <<'EOF'
ARR Stack Helper Aliases

Service-specific helpers:
  arr.rad.help               Radarr helpers
  arr.son.help               Sonarr helpers
  arr.lid.help               Lidarr helpers
  arr.prow.help              Prowlarr helpers
  arr.baz.help               Bazarr helpers
  arr.qbt.help               qBittorrent helpers
  arr.sab.help               SABnzbd helpers
  arr.vpn.help               VPN/Gluetun helpers
  arr.pf.help                Port forwarding helpers
  arr.flarr.help             FlareSolverr helpers

Generic helpers:
  arr.logs <service>         Docker logs -f
  arr.restart <service>      Docker restart
  arr.shell <service>        Interactive shell

Quick tests:
  arr.rad.status             # Radarr system status
  arr.son.status             # Sonarr system status
  arr.qbt.version            # qBittorrent version
  arr.vpn.status             # VPN tunnel status
  arr.pf.port                # Current forwarded port

Configuration discovery:
  This alias file automatically discovers:
  - Stack directory from source location
  - .env file at \$ARR_STACK_DIR/.env
  - Service configs at \$ARR_DOCKER_DIR/<service>/config.xml
  - API keys from config files
  - UrlBase from service configs
  
  Override with environment variables if needed:
    ARR_STACK_DIR=/path/to/stack source .aliasarr
EOF
}

# Print initialization message
if [ "${ARR_ALIAS_QUIET:-0}" != "1" ]; then
  printf '✅ ARR stack aliases loaded. Run arr.help for usage.\n' >&2
fi
ALIASARR_RUNTIME_HEADER

  if mv "$tmp_file" "$output_file"; then
    arr_unregister_temp_path "$tmp_file"
    return 0
  else
    arr_cleanup_temp_path "$tmp_file"
    return 1
  fi
}

# Standalone alias installer that generates a runtime-config-aware .aliasarr
# without placeholder substitution. This function is idempotent and can be
# called independently via arr.sh --alias.
install_standalone_alias() {
  if [[ -z "${ARR_STACK_DIR:-}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    ARR_STACK_DIR="$(arr_stack_dir)"
  fi

  if [[ -z "${ARR_STACK_DIR:-}" ]]; then
    ARR_STACK_DIR="${HOME}/srv/arr"
  fi

  ensure_dir "$ARR_STACK_DIR" || {
    warn "Unable to create stack directory at ${ARR_STACK_DIR}"
    return 1
  }

  local alias_file="${ARR_STACK_DIR}/.aliasarr"
  msg "📝 Generating standalone alias file at: ${alias_file}"

  if ! write_standalone_alias_file "$alias_file"; then
    warn "Failed to generate standalone alias file"
    return 1
  fi

  ensure_file_mode "$alias_file" "${ALIAS_HELPER_FILE_MODE:-0640}"

  msg "✅ Standalone alias file generated: ${alias_file}"
  msg " Source it with: source ${alias_file}"
  msg " Or add to your shell rc: echo 'source ${alias_file}' >> ~/.bashrc"

  return 0
}

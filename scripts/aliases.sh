# shellcheck shell=bash
# Renders helper alias bundle and injects optional VPN/configarr helpers if templates permit
write_aliases_file() {
  msg "🛠️ Generating helper aliases file"

  local template_file="${REPO_ROOT}/.aliasarr"
  local aliases_file="${ARR_STACK_DIR}/.aliasarr"
  local configured_template="${REPO_ROOT}/.aliasarr.configured"

  if [[ ! -f "$template_file" ]]; then
    warn "Alias template ${template_file} not found"
    return 0
  fi

  local tmp_file
  if ! tmp_file="$(arrstack_mktemp_file "${aliases_file}.XXXX" "$SECRET_FILE_MODE")"; then
    warn "Failed to create temporary aliases file"
    return 1
  fi

  local stack_dir_escaped env_file_escaped docker_dir_escaped arrconf_dir_escaped
  stack_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  stack_dir_escaped=${stack_dir_escaped//&/\&}
  stack_dir_escaped=${stack_dir_escaped//|/\|}
  env_file_escaped=${ARR_ENV_FILE//\\/\\\\}
  env_file_escaped=${env_file_escaped//&/\&}
  env_file_escaped=${env_file_escaped//|/\|}
  docker_dir_escaped=${ARR_DOCKER_DIR//\\/\\\\}
  docker_dir_escaped=${docker_dir_escaped//&/\&}
  docker_dir_escaped=${docker_dir_escaped//|/\|}
  arrconf_dir_escaped=${ARRCONF_DIR//\\/\\\\}
  arrconf_dir_escaped=${arrconf_dir_escaped//&/\&}
  arrconf_dir_escaped=${arrconf_dir_escaped//|/\|}

  sed -e "s|__ARR_STACK_DIR__|${stack_dir_escaped}|g" \
    -e "s|__ARR_ENV_FILE__|${env_file_escaped}|g" \
    -e "s|__ARR_DOCKER_DIR__|${docker_dir_escaped}|g" \
    -e "s|__ARRCONF_DIR__|${arrconf_dir_escaped}|g" \
    "$template_file" >"$tmp_file"

  if grep -q "__ARR_" "$tmp_file"; then
    warn "Failed to replace all template placeholders in aliases file"
    rm -f "$tmp_file"
    return 1
  fi

  mv "$tmp_file" "$aliases_file"

  if [[ "${ENABLE_CONFIGARR:-0}" -eq 1 ]]; then
    if ! grep -Fq "alias arr.config.sync" "$aliases_file" 2>/dev/null; then
      {
        printf '\n# Configarr helper\n'
        printf "alias arr.config.sync='docker compose run --rm configarr'\n"
      } >>"$aliases_file"
    fi
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
    echo "[arr.vpn.auto.status] status file not found: $status_file" >&2
    return 1
  fi
}

arr_vpn_auto_force() {
  local flag
  flag="$(_arr_vpn_auto_override_path once)"
  if touch "$flag"; then
    echo "[arr.vpn.auto.force] override flag created: $flag"
  else
    echo "[arr.vpn.auto.force] failed to create $flag" >&2
    return 1
  fi
}

arr_vpn_auto_pause() {
  local flag
  flag="$(_arr_vpn_auto_override_path pause)"
  if touch "$flag"; then
    echo "[arr.vpn.auto.pause] pause flag created: $flag"
  else
    echo "[arr.vpn.auto.pause] failed to create $flag" >&2
    return 1
  fi
}

arr_vpn_auto_resume() {
  local flag
  flag="$(_arr_vpn_auto_override_path pause)"
  if rm -f "$flag"; then
    echo "[arr.vpn.auto.resume] pause flag removed (${flag})"
  else
    echo "[arr.vpn.auto.resume] failed to remove $flag" >&2
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
    echo "[arr.vpn.auto.history] history file not found: $history" >&2
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
    echo "[arr.vpn.auto.watch] no log files found under ${state_dir}" >&2
    return 1
  fi
  tail -f "${files[@]}"
}

arr_vpn_auto_wake() {
  local flag
  flag="$(_arr_vpn_auto_override_path wake)"
  if touch "$flag"; then
    echo "[arr.vpn.auto.wake] wake trigger created: $flag"
  else
    echo "[arr.vpn.auto.wake] failed to touch $flag" >&2
    return 1
  fi
}

arr_vpn_auto_enable() {
  local result
  if result="$(arr.env.set VPN_AUTO_RECONNECT_ENABLED 1 2>&1)"; then
    echo "[arr.vpn.auto.enable] ${result}"
    arr_vpn_auto_wake >/dev/null 2>&1 || true
  else
    echo "[arr.vpn.auto.enable] failed: ${result}" >&2
    return 1
  fi
}

arr_vpn_auto_disable() {
  local result
  if result="$(arr.env.set VPN_AUTO_RECONNECT_ENABLED 0 2>&1)"; then
    echo "[arr.vpn.auto.disable] ${result}"
    arr_vpn_auto_wake >/dev/null 2>&1 || true
  else
    echo "[arr.vpn.auto.disable] failed: ${result}" >&2
    return 1
  fi
}

arr_vpn_port_status() {
  local file
  file="$(_arr_pf_state_file)"
  if [ -f "$file" ]; then
    cat "$file"
  else
    echo "[arr.vpn.port.status] state file not found: $file" >&2
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

  ensure_secret_file_mode "$aliases_file"
  cp "$aliases_file" "$configured_template"
  ensure_nonsecret_file_mode "$configured_template"

  local legacy_alias_file="${ARR_STACK_DIR}/.arraliases"
  local legacy_configured="${REPO_ROOT}/.arraliases.configured"
  rm -f "$legacy_alias_file" "$legacy_configured"

  msg "✅ Helper aliases written to: $aliases_file"
  msg "   Source them with: source $aliases_file"
  msg "   Repo copy updated: $configured_template"
}

install_aliases() {
  local bashrc="${HOME}/.bashrc"
  local repo_escaped
  repo_escaped="$(arrstack_shell_escape_double_quotes "${REPO_ROOT}")"
  local alias_line
  alias_line=$(printf "alias arrstack='cd \"%s\" && ./arrstack.sh'" "${repo_escaped}")
  local source_line="# source ${ARR_STACK_DIR}/.aliasarr  # Optional helper functions"

  if [[ -w "$bashrc" ]]; then
    if ! grep -Fq "$alias_line" "$bashrc" 2>/dev/null; then
      {
        printf '\n# ARR Stack helper aliases\n'
        printf '%s\n' "$alias_line"
        printf "alias arrstack-logs='docker logs -f gluetun'\n"
        printf '%s\n' "$source_line"
      } >>"$bashrc"
      msg "Added aliases to ${bashrc}"
    fi
  fi

  local diag_script="${ARR_STACK_DIR}/diagnose-vpn.sh"
  cat >"$diag_script" <<'DIAG'
#!/bin/bash
set -euo pipefail

ARR_STACK_DIR="__ARR_STACK_DIR__"
ARR_ENV_FILE="${ARR_STACK_DIR}/.env"
SCRIPT_LIB_DIR="${ARR_STACK_DIR}/scripts"

if [[ -f "${SCRIPT_LIB_DIR}/common.sh" ]]; then
  # shellcheck source=/dev/null
  . "${SCRIPT_LIB_DIR}/common.sh"
else
  printf '[diagnose-vpn] ERROR: common helpers missing at %s\n' "${SCRIPT_LIB_DIR}/common.sh" >&2
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

GLUETUN_LIB="${ARR_STACK_DIR}/scripts/gluetun.sh"
if [[ -f "$GLUETUN_LIB" ]]; then
  # shellcheck source=/dev/null
  . "$GLUETUN_LIB"
else
  log_warn "Gluetun helper library missing at $GLUETUN_LIB"
  fetch_forwarded_port() { printf '0'; }
  fetch_public_ip() { printf ''; }
  ensure_proton_port_forwarding_ready() { return 1; }
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

log_info "Checking VPN connection..."
PUBLIC_IP="$(fetch_public_ip)"

if [[ -n "$PUBLIC_IP" ]]; then
  log_info "✅ VPN Connected: $PUBLIC_IP"
else
  log_warn "VPN not connected"
fi

log_info "Checking port forwarding..."
PF_PORT="$(fetch_forwarded_port 2>/dev/null || printf '0')"

if [[ "$PF_PORT" == "0" ]]; then
  ensure_proton_port_forwarding_ready || true
  PF_PORT="${PF_ENSURED_PORT:-$PF_PORT}"
fi

if [[ "$PF_PORT" != "0" ]]; then
  log_info "✅ Port forwarding active: Port $PF_PORT"
else
  log_warn "Port forwarding not working"
  log_warn "Review 'docker logs gluetun --tail 100 | grep update-qbt-port' for details"
fi

log_info "Checking service health..."
for service in qbittorrent sonarr radarr prowlarr bazarr; do
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
  if ! diag_tmp="$(arrstack_mktemp_file "${diag_script}.XXXX")"; then
    warn "Failed to create temporary diagnostic script"
    return 1
  fi
  local diag_dir_escaped
  diag_dir_escaped=${ARR_STACK_DIR//\\/\\\\}
  diag_dir_escaped=${diag_dir_escaped//&/\&}
  diag_dir_escaped=${diag_dir_escaped//|/\|}
  sed -e "s|__ARR_STACK_DIR__|${diag_dir_escaped}|g" "$diag_script" >"$diag_tmp"
  mv "$diag_tmp" "$diag_script"
  chmod 755 "$diag_script"
  msg "Diagnostic script: ${diag_script}"
}

refresh_aliases() {
  msg "🔄 Refreshing helper aliases"

  ensure_dir "$ARR_STACK_DIR"

  if ! write_aliases_file; then
    warn "Unable to regenerate helper aliases"
    return 1
  fi

  if reload_shell_rc; then
    msg "♻️ Shell configuration reloaded"
  else
    local alias_path="${ARR_STACK_DIR}/.aliasarr"
    warn "Could not automatically reload your shell configuration"
    warn "Run 'source ${alias_path}' manually to pick up the latest aliases"
  fi
}

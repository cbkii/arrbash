#!/usr/bin/env bash
# qBittorrent Helper - Manage authentication and access defaults

set -euo pipefail

# --- qBittorrent WebUI enforcement helpers (shared by init + host modes) ---

qbt_webui_conf_path_default="/config/qBittorrent.conf"
qbt_webui_restart_state="/tmp/qbt-webui-enforce.timestamp"
qbt_webui_restart_interval_default=60

qbt_webui_mktemp() {
  local base="$1"
  local tmp
  if ! tmp=$(mktemp "${base}.XXXXXX" 2>/dev/null); then
    printf '[qbt-helper] Failed to create temporary file near %s\n' "$base" >&2
    return 1
  fi
  printf '%s\n' "$tmp"
}

qbt_webui_ensure_conf() {
  local conf="$1"
  local dir
  dir="$(dirname -- "$conf")"
  mkdir -p "$dir"
  if [[ ! -f "$conf" ]]; then
    : >"$conf"
  fi
}

qbt_webui_strip_crlf() {
  local conf="$1"
  if [[ -s "$conf" ]] && LC_ALL=C grep -q $'\r' "$conf"; then
    local tmp
    if ! tmp=$(qbt_webui_mktemp "$conf"); then
      return 1
    fi
    tr -d '\r' <"$conf" >"$tmp"
    mv "$tmp" "$conf"
  fi
}

qbt_webui_ensure_preferences() {
  local conf="$1"
  if ! LC_ALL=C grep -q '^\[Preferences\]' "$conf" 2>/dev/null; then
    printf '\n[Preferences]\n' >>"$conf"
  fi
}

qbt_webui_upsert_pref() {
  local conf="$1"
  local key="$2"
  local value="$3"
  local tmp
  if ! tmp=$(qbt_webui_mktemp "$conf"); then
    return 1
  fi
  awk -v target="$key" -v desired="$value" '
    BEGIN {
      section = "";
      inserted = 0;
    }
    /^\[.*\]$/ {
      if (section == "[Preferences]" && !inserted) {
        print target "=" desired;
        inserted = 1;
      }
      section = $0;
      print;
      next;
    }
    {
      if (section == "[Preferences]" && $0 ~ "^" target "=") {
        if (!inserted) {
          print target "=" desired;
          inserted = 1;
        }
        next;
      }
      print;
    }
    END {
      if (section == "[Preferences]" && !inserted) {
        print target "=" desired;
        inserted = 1;
      }
      if (!inserted) {
        print "[Preferences]";
        print target "=" desired;
      }
    }
  ' "$conf" >"$tmp"
  mv "$tmp" "$conf"
}

qbt_webui_pref_value() {
  local conf="$1"
  local key="$2"

  [[ -f "$conf" ]] || return 1

  awk -v target="$key" '
    BEGIN {
      section="";
    }
    /^\[.*\]$/ {
      section=$0;
      next;
    }
    section == "[Preferences]" && index($0, target "=") == 1 {
      sub("^" target "=", "");
      gsub(/\r$/, "");
      print;
      exit 0;
    }
  ' "$conf"
}

qbt_webui_pref_equals() {
  local conf="$1"
  local key="$2"
  local expected="$3"
  local actual

  if ! actual="$(qbt_webui_pref_value "$conf" "$key" 2>/dev/null)"; then
    return 1
  fi

  [[ "$actual" == "$expected" ]]
}

qbt_webui_enforce() {
  local conf="${1:-${QBT_CONF_PATH:-${qbt_webui_conf_path_default}}}"
  local address="${2:-${QBT_BIND_ADDR:-0.0.0.0}}"
  local port="${3:-${QBT_INT_PORT:-8082}}"
  local old_umask

  if ! old_umask=$(umask); then
    old_umask=0022
  fi
  trap 'umask "$old_umask" >/dev/null 2>&1 || true' RETURN
  umask 077

  qbt_webui_ensure_conf "$conf" || return 1
  qbt_webui_strip_crlf "$conf" || return 1
  qbt_webui_ensure_preferences "$conf" || return 1
  qbt_webui_upsert_pref "$conf" 'WebUI\\Address' "$address" || return 1
  qbt_webui_upsert_pref "$conf" 'WebUI\\Port' "$port" || return 1

  if ! LC_ALL=C grep -E '^(WebUI\\Address|WebUI\\Port)=' "$conf" >/dev/null; then
    printf '[qbt-helper] Failed to assert WebUI prefs in %s\n' "$conf" >&2
    return 1
  fi

  chmod 600 "$conf" 2>/dev/null || true
}

qbt_webui_restart_service() {
  local service_dir="/run/s6/services/qbittorrent"

  if command -v s6-svc >/dev/null 2>&1 && [[ -d "$service_dir" ]]; then
    if ! s6-svc -r "$service_dir" >/dev/null 2>&1; then
      s6-svc -t "$service_dir" >/dev/null 2>&1 || true
    fi
    return 0
  fi

  if command -v pkill >/dev/null 2>&1; then
    pkill -TERM -f 'qbittorrent-nox' >/dev/null 2>&1 || true
  fi

  return 0
}

qbt_webui_rate_limited_restart() {
  local interval="${QBT_WEBUI_RESTART_INTERVAL:-${qbt_webui_restart_interval_default}}"
  local state_file="$qbt_webui_restart_state"
  local now last

  if [[ -z "$interval" || ! "$interval" =~ ^[0-9]+$ ]]; then
    interval="$qbt_webui_restart_interval_default"
  fi

  if [[ -f "$state_file" ]]; then
    if last="$(<"$state_file" 2>/dev/null)" && [[ "$last" =~ ^[0-9]+$ ]]; then
      if now="$(date +%s 2>/dev/null)"; then
        if (( now - last < interval )); then
          return 0
        fi
      fi
    fi
  fi

  if now="$(date +%s 2>/dev/null)"; then
    printf '%s\n' "$now" >"$state_file" 2>/dev/null || true
  fi

  qbt_webui_restart_service
}

qbt_webui_repair() {
  local conf="${QBT_CONF_PATH:-${qbt_webui_conf_path_default}}"
  local address="${QBT_BIND_ADDR:-0.0.0.0}"
  local port="${QBT_INT_PORT:-8082}"

  if qbt_webui_enforce "$conf" "$address" "$port"; then
    qbt_webui_rate_limited_restart
    return 0
  fi

  return 1
}

qbt_webui_healthcheck() {
  local enforce="${QBT_ENFORCE_WEBUI:-1}"
  local conf="${QBT_CONF_PATH:-${qbt_webui_conf_path_default}}"
  local address="${QBT_BIND_ADDR:-0.0.0.0}"
  local port="${QBT_INT_PORT:-8082}"
  local localhost="${LOCALHOST_IP:-127.0.0.1}"
  local repaired=0

  if [[ "$enforce" != "0" ]]; then
    qbt_webui_strip_crlf "$conf" || true

    if ! qbt_webui_pref_equals "$conf" 'WebUI\\Address' "$address" \
      || ! qbt_webui_pref_equals "$conf" 'WebUI\\Port' "$port"; then
      if qbt_webui_repair; then
        repaired=1
      fi
    fi
  fi

  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --connect-timeout 5 --max-time 8 "http://${localhost}:${port}/api/v2/app/version" >/dev/null 2>&1; then
      return 0
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -T 8 -O- "http://${localhost}:${port}/api/v2/app/version" >/dev/null 2>&1; then
      return 0
    fi
  fi

  if [[ "$enforce" != "0" && "$repaired" -eq 0 ]]; then
    if qbt_webui_repair; then
      repaired=1
    fi
  fi

  if ((repaired)); then
    return 1
  fi

  return 1
}

qbt_webui_init_hook() {
  if [[ "${QBT_ENFORCE_WEBUI:-1}" == "0" ]]; then
    return 0
  fi

  if ! qbt_webui_enforce; then
    printf '[qbt-helper] WebUI enforcement failed\n' >&2
    exit 1
  fi
}

if [[ "$(basename -- "$0")" == "00-qbt-webui" ]]; then
  case "${1:-init}" in
    init | "")
      qbt_webui_init_hook
      exit 0
      ;;
    healthcheck)
      qbt_webui_healthcheck
      exit $?
      ;;
    enforce)
      if qbt_webui_repair; then
        exit 0
      fi
      exit 1
      ;;
    *)
      printf '[qbt-helper] Unknown mode %s\n' "$1" >&2
      exit 1
      ;;
  esac
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}"
if ! STACK_DIR="$(cd "${STACK_DIR}" 2>/dev/null && pwd)"; then
  echo "Stack directory not found: ${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}" >&2
  exit 1
fi

ARR_STACK_DIR="$STACK_DIR"
export ARR_STACK_DIR

# shellcheck source=scripts/common.sh
. "${STACK_DIR}/scripts/common.sh"

if [[ -f "${STACK_DIR}/arrconf/userr.conf.defaults.sh" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "${STACK_DIR}/arrconf/userr.conf.defaults.sh"
fi

ENV_FILE="${ARR_ENV_FILE:-${STACK_DIR}/.env}"
CONTAINER_NAME="qbittorrent"

# Sources the stack .env so helper commands reflect deployed values
load_env() {
  [[ -f "$ENV_FILE" ]] || return

  local line key raw value
  while IFS= read -r line || [[ -n $line ]]; do
    line="${line//$'\r'/}"
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^[[:space:]]*export[[:space:]]+(.+)$ ]] && line="${BASH_REMATCH[1]}"
    [[ $line =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue

    key="${BASH_REMATCH[1]}"
    raw="${BASH_REMATCH[2]}"
    # Trim leading whitespace
    raw="${raw#"${raw%%[![:space:]]*}"}"
    value="$(unescape_env_value_from_compose "$raw")"

    if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      printf -v "$key" '%s' "$value"
      export "$key"
    else
      echo "Warning: Invalid environment variable name '$key' in $ENV_FILE, skipping." >&2
    fi
  done <"$ENV_FILE"
}

# Determines docker-data directory from env overrides or common defaults
resolve_docker_data() {
  local candidates=()

  if [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
    candidates+=("$ARR_DOCKER_DIR")
  fi
  if [[ -n "${ARR_DATA_ROOT:-}" ]]; then
    candidates+=("${ARR_DATA_ROOT%/}/docker-data")
  fi
  candidates+=("${STACK_DIR}/docker-data")

  local path
  for path in "${candidates[@]}"; do
    if [[ -n "$path" && -d "$path" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  return 1
}

# Extracts qBittorrent's latest temporary password from container logs
temporary_password() {
  docker logs "$CONTAINER_NAME" 2>&1 \
    | grep "temporary password" \
    | tail -1 \
    | sed 's/.*temporary password[^:]*: *//' \
    | awk '{print $1}'
}

# Chooses appropriate host/IP for WebUI links (LAN_IP fallback to localhost)
webui_host() {
  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" ]]; then
    printf '%s' "$LAN_IP"
  else
    printf '%s' "127.0.0.1"
  fi
}

# Returns exposed qBittorrent WebUI host port
webui_port() {
  local port="${QBT_PORT:-${QBT_INT_PORT:-8082}}"
  printf '%s' "$port"
}

# Builds LAN domain used behind Caddy for qBittorrent
webui_domain() {
  local suffix="${CADDY_DOMAIN_SUFFIX:-home.arpa}"
  suffix="${suffix#.}"
  printf 'qbittorrent.%s' "$suffix"
}

# Computes path to qBittorrent.conf within docker-data tree
config_file_path() {
  printf '%s/qbittorrent/qBittorrent.conf' "$DOCKER_DATA"
}

# Stops qBittorrent container quietly before config edits
stop_container() {
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Restarts qBittorrent container after config edits
start_container() {
  docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Derives /24 whitelist subnet from LAN_IP when present
derive_subnet() {
  if [[ -n "${LAN_IP:-}" && "$LAN_IP" != "0.0.0.0" ]]; then
    local IFS='.'
    read -r oct1 oct2 oct3 _ <<<"$LAN_IP"
    case "$oct1" in
      10)
        printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        ;;
      192)
        if [[ "$oct2" == "168" ]]; then
          printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        fi
        ;;
      172)
        if [[ "$oct2" =~ ^[0-9]+$ ]] && [ "$oct2" -ge 16 ] && [ "$oct2" -le 31 ]; then
          printf '%s.%s.%s.0/24\n' "$oct1" "$oct2" "$oct3"
        fi
        ;;
    esac
  fi
}

# Prints human-friendly access details and current auth state
show_info() {
  log_info "qBittorrent Access Information:"
  log_info "================================"
  log_info "LAN URL:  http://$(webui_domain)/"
  log_info "HTTPS:    https://$(webui_domain)/ (trust the Caddy internal CA)"
  log_info ""

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log_info "Username: admin"
    log_info "Password: ${temp_pass} (temporary - change this!)"
  else
    log_info "Username: ${QBT_USER:-admin}"
    log_info "Password: ${QBT_PASS:-Check logs or use 'reset' command}"
  fi

  log_info ""
  log_info "Remote clients must authenticate through Caddy using user '${CADDY_BASIC_AUTH_USER:-user}' and the password hashed in ${ARR_DOCKER_DIR}/caddy/Caddyfile."
}

# Resets qBittorrent credentials and surfaces the new temporary password
reset_auth() {
  log_info "Resetting qBittorrent authentication..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local backup
    backup="${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$cfg" "$backup"
    log_info "  Backed up config to $backup"
    sed -i '/WebUI\\Password_PBKDF2/d' "$cfg" || true
  else
    log_warn "Config file not found at $cfg; proceeding without backup"
  fi

  start_container
  sleep 5

  local temp_pass
  temp_pass=$(temporary_password || true)

  if [[ -n "$temp_pass" ]]; then
    log_info "Authentication reset. New temporary password: ${temp_pass}"
  else
    log_warn "Unable to detect temporary password automatically. Check 'docker logs qbittorrent'."
  fi
}

# Enables LAN subnet whitelist for WebUI by patching qBittorrent.conf
update_whitelist() {
  local subnet
  subnet=$(derive_subnet)

  if [[ -z "$subnet" ]]; then
    die "LAN_IP is not set to a private address; cannot derive whitelist subnet"
  fi

  log_info "Enabling LAN whitelist for passwordless access..."
  stop_container

  local cfg
  cfg=$(config_file_path)
  if [[ -f "$cfg" ]]; then
    local tmp
    if ! tmp=$(arr_mktemp_file); then
      die "Failed to create temporary whitelist file"
    fi
    awk '!(/^WebUI\\AuthSubnetWhitelistEnabled=/ || /^WebUI\\AuthSubnetWhitelist=/)' "$cfg" >"$tmp"
    {
      printf 'WebUI\\AuthSubnetWhitelistEnabled=true\n'
      printf 'WebUI\\AuthSubnetWhitelist=%s\n' "$subnet"
    } >>"$tmp"
    mv "$tmp" "$cfg"
    ensure_secret_file_mode "$cfg"
  else
    log_warn "Config file not found at $cfg; whitelist not updated"
  fi

  start_container
  log_info "LAN whitelist enabled for: $subnet"
}

# Applies WebUI binding defaults using the shared enforcer script
restore_webui_bindings() {
  local context="$1"
  local desired_port="${QBT_INT_PORT:-8082}"
  local address="${QBT_BIND_ADDR:-0.0.0.0}"
  local cfg rc=0

  cfg="$(config_file_path)"

  log_info "$context"
  stop_container

  if qbt_webui_enforce "$cfg" "$address" "$desired_port"; then
    ensure_secret_file_mode "$cfg"
    log_info "Updated qBittorrent WebUI configuration in ${cfg}"
  else
    log_warn "Failed to update qBittorrent WebUI configuration; check ${cfg} manually"
    rc=1
  fi

  start_container
  return "$rc"
}

# Reports detected drift in WebUI port/bind settings relative to stack defaults
diagnose_config() {
  local cfg
  cfg="$(config_file_path)"
  local host_port="${QBT_PORT:-${QBT_INT_PORT:-8082}}"
  local expected_container_port="${QBT_INT_PORT:-8082}"
  local expected_bind="${QBT_BIND_ADDR:-0.0.0.0}"

  if [[ ! -f "$cfg" ]]; then
    log_warn "Config file not found at $cfg; nothing to diagnose"
    return 0
  fi

  local ui_port=""
  ui_port="$(grep '^WebUI\\Port=' "$cfg" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"

  local ui_addr=""
  ui_addr="$(grep '^WebUI\\Address=' "$cfg" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"

  if [[ -n "$ui_port" ]]; then
    if [[ "$ui_port" != "$expected_container_port" ]]; then
      log_warn "WebUI internal port is ${ui_port} but expected ${expected_container_port}"
      log_info "Run 'qbt-helper.sh fix-port' to correct this"
    else
      log_info "WebUI internal port matches expected container default (${expected_container_port})"
    fi
  else
    log_warn "Unable to determine WebUI internal port from ${cfg}"
  fi

  if [[ -n "$ui_addr" ]]; then
    if [[ "$ui_addr" != "$expected_bind" ]]; then
      log_warn "WebUI bind address is ${ui_addr} but should be ${expected_bind}"
      log_info "Run 'qbt-helper.sh fix-addr' to correct this"
    else
      log_info "WebUI bind address matches expected container default (${expected_bind})"
    fi
  else
    log_warn "Unable to determine WebUI bind address from ${cfg}"
  fi

  if [[ -n "$ui_port" && "$ui_port" == "$expected_container_port" && "$host_port" != "$expected_container_port" ]]; then
    log_info "Host exposes qBittorrent WebUI on port ${host_port} (container remains on ${expected_container_port})"
  fi
}

# Forces WebUI port back to container default and restarts service
fix_webui_port() {
  local desired_port="${QBT_INT_PORT:-8082}"
  restore_webui_bindings "Restoring qBittorrent WebUI port to ${desired_port}"
}

# Forces WebUI bind address back to 0.0.0.0 for LAN access
fix_webui_address() {
  local address="${QBT_BIND_ADDR:-0.0.0.0}"
  restore_webui_bindings "Restoring qBittorrent WebUI bind address to ${address}"
}

# Executes the init hook inside the running container and restarts qBittorrent
force_webui_bindings() {
  local hook="/custom-cont-init.d/00-qbt-webui"
  local -a exec_env=(
    -e "QBT_INT_PORT=${QBT_INT_PORT:-8082}"
    -e "QBT_BIND_ADDR=${QBT_BIND_ADDR:-0.0.0.0}"
    -e "QBT_ENFORCE_WEBUI=1"
  )

  if [[ -n "${QBT_USER:-}" ]]; then
    exec_env+=(-e "QBT_USER=${QBT_USER}")
  fi
  if [[ -n "${QBT_PASS:-}" ]]; then
    exec_env+=(-e "QBT_PASS=${QBT_PASS}")
  fi

  log_info "Running qBittorrent WebUI init hook (${hook})..."
  if ! docker exec "${exec_env[@]}" "$CONTAINER_NAME" "$hook"; then
    log_warn "Init hook exited with an error; inspect 'docker logs ${CONTAINER_NAME}'"
  fi

  if docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1; then
    arr_resolve_compose_cmd
    if compose restart "$CONTAINER_NAME"; then
      log_info "Restarted ${CONTAINER_NAME} via docker compose"
    else
      log_warn "Failed to restart ${CONTAINER_NAME}; restart the container manually"
    fi
  else
    log_warn "Docker Compose v2 not detected; skipping container restart"
  fi
}

# Prints helper usage menu
usage() {
  local default_port="${QBT_INT_PORT:-8082}"
  local default_addr="${QBT_BIND_ADDR:-0.0.0.0}"
  cat <<USAGE
Usage: qbt-helper.sh {show|reset|whitelist|diagnose|fix-port|fix-addr|force|repair}
  show       Display current access information
  reset      Reset authentication (generates a new temporary password)
  whitelist  Enable passwordless access from the LAN subnet
  diagnose   Check for WebUI configuration drift
  fix-port   Restore WebUI port to container default (${default_port})
  fix-addr   Restore WebUI bind address to ${default_addr}
  force      Run WebUI init hook and restart the container
  repair     Alias for 'force'
USAGE
}

# Dispatches qbt-helper commands after loading environment context
main() {
  load_env

  DOCKER_DATA=$(resolve_docker_data) || die "Cannot find docker-data directory"
  export DOCKER_DATA

  case "${1:-show}" in
    show)
      show_info
      ;;
    reset)
      reset_auth
      ;;
    whitelist)
      update_whitelist
      ;;
    diagnose)
      diagnose_config
      ;;
    fix-port)
      fix_webui_port
      ;;
    fix-addr)
      fix_webui_address
      ;;
    force | repair)
      force_webui_bindings
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

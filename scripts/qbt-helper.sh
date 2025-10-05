#!/usr/bin/env bash
# qBittorrent Helper - Manage authentication and access defaults

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}"
if ! STACK_DIR="$(cd "${STACK_DIR}" 2>/dev/null && pwd)"; then
  echo "Stack directory not found: ${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}" >&2
  exit 1
fi

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

# Ensures specified config key is set to desired value (adding if missing)
ensure_qbt_config_setting() {
  local key="$1"
  local value="$2"
  local cfg="$3"

  if [[ -z "$key" || -z "$cfg" ]]; then
    return 1
  fi

  if [[ ! -f "$cfg" ]]; then
    log_warn "Config file not found at $cfg; cannot update ${key}"
    return 1
  fi

  local tmp
  if ! tmp=$(arr_mktemp_file "${cfg}.XXXXXX.tmp" "$SECRET_FILE_MODE"); then
    log_warn "Failed to create temporary file while updating ${cfg}"
    return 1
  fi

  awk -v target="$key" -v desired="$value" '
    BEGIN {
      OFS = "=";
      seen = 0;
    }
    {
      line = $0;
      if (index(line, "=") == 0) {
        print line;
        next;
      }
      split(line, kv, "=");
      if (kv[1] == target) {
        print target, desired;
        seen = 1;
      } else {
        print line;
      }
    }
    END {
      if (!seen) {
        print target, desired;
      }
    }
  ' "$cfg" >"$tmp"

  mv "$tmp" "$cfg"
  ensure_secret_file_mode "$cfg"
}

# Reports detected drift in WebUI port/bind settings relative to stack defaults
diagnose_config() {
  local cfg
  cfg="$(config_file_path)"
  local host_port="${QBT_PORT:-${QBT_INT_PORT:-8082}}"
  local expected_container_port="${QBT_INT_PORT:-8082}"

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
    if [[ "$ui_addr" != "0.0.0.0" ]]; then
      log_warn "WebUI bind address is ${ui_addr} but should be 0.0.0.0"
      log_info "Run 'qbt-helper.sh fix-addr' to correct this"
    else
      log_info "WebUI bind address matches expected container default (0.0.0.0)"
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
  log_info "Restoring qBittorrent WebUI port to ${desired_port}"
  stop_container

  local cfg
  cfg="$(config_file_path)"

  if ensure_qbt_config_setting "WebUI\\Port" "${desired_port}" "$cfg"; then
    log_info "Updated WebUI port in ${cfg}"
  else
    log_warn "Failed to update WebUI port; check ${cfg} manually"
  fi

  start_container
}

# Forces WebUI bind address back to 0.0.0.0 for LAN access
fix_webui_address() {
  log_info "Restoring qBittorrent WebUI bind address to 0.0.0.0"
  stop_container

  local cfg
  cfg="$(config_file_path)"

  if ensure_qbt_config_setting "WebUI\\Address" "0.0.0.0" "$cfg"; then
    log_info "Updated WebUI bind address in ${cfg}"
  else
    log_warn "Failed to update WebUI bind address; check ${cfg} manually"
  fi

  start_container
}

# Prints helper usage menu
usage() {
  local default_port="${QBT_INT_PORT:-8082}"
  cat <<USAGE
Usage: qbt-helper.sh {show|reset|whitelist|diagnose|fix-port|fix-addr}
  show       Display current access information
  reset      Reset authentication (generates a new temporary password)
  whitelist  Enable passwordless access from the LAN subnet
  diagnose   Check for WebUI configuration drift
  fix-port   Restore WebUI port to container default (${default_port})
  fix-addr   Restore WebUI bind address to 0.0.0.0
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
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

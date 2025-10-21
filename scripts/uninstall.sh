#!/usr/bin/env bash

usage() {
  cat <<'USAGE'
Usage: ./scripts/uninstall.sh [options]

Options:
  --yes                 Assume "yes" to all prompts and run non-interactively
  --stack-dir PATH      Override detected stack directory (defaults to current config)
  --help                Show this help message

This script removes the ARR stack, stops Docker services, cleans installer assets,
reverts shell customisations, and restores host DNS where applicable.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

COMMON_LIB="${REPO_ROOT}/scripts/common.sh"
if [[ -f "$COMMON_LIB" ]]; then
  # shellcheck source=scripts/common.sh
  . "$COMMON_LIB"
else
  printf '[arr.uninstall] missing required module: %s\n' "$COMMON_LIB" >&2
  exit 1
fi

USERCONF_LIB="${REPO_ROOT}/scripts/userconf.sh"
if [[ -f "$USERCONF_LIB" ]]; then
  # shellcheck source=scripts/userconf.sh
  . "$USERCONF_LIB"
else
  die "Missing helper library: ${USERCONF_LIB}"
fi

for arg in "$@"; do
  case "$arg" in
    --help|-h)
      usage
      exit 0
      ;;
  esac
done

arr_escalate_privileges "$@" || exit $?

set -Eeuo pipefail

ASSUME_YES="${ASSUME_YES:-0}"
STACK_DIR_OVERRIDE=""

while (($#)); do
  case "$1" in
    --yes)
      ASSUME_YES=1
      shift
      ;;
    --stack-dir)
      if [[ $# -lt 2 ]]; then
        die "--stack-dir requires a path argument"
      fi
      STACK_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

if [[ -n "${STACK_DIR_OVERRIDE}" ]]; then
  ARR_STACK_DIR="${STACK_DIR_OVERRIDE}"
fi

DEFAULTS_PATH="${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
if [[ -f "$DEFAULTS_PATH" ]]; then
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "$DEFAULTS_PATH"
fi

REPO_CANON="$(arr_canonical_path "${REPO_ROOT}")"

resolve_primary_user() {
  local resolved_user=""
  local resolved_home=""

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    resolved_user="${SUDO_USER}"
    resolved_home="$(getent passwd "${SUDO_USER}" 2>/dev/null | awk -F: 'NR==1 {print $6}' || true)"
  else
    resolved_user="${USER:-$(id -un 2>/dev/null || printf 'root')}"
    resolved_home="${HOME:-$(getent passwd "${resolved_user}" 2>/dev/null | awk -F: 'NR==1 {print $6}' || true)}"
  fi

  if [[ -z "${resolved_home}" ]]; then
    resolved_home="$(getent passwd "${resolved_user}" 2>/dev/null | awk -F: 'NR==1 {print $6}' || true)"
  fi

  PRIMARY_USER="${resolved_user}"
  PRIMARY_HOME="${resolved_home%/}"
}

resolve_primary_user

if [[ -z "${PRIMARY_HOME}" ]]; then
  warn "Unable to resolve home directory for ${PRIMARY_USER}; shell rc cleanup will be skipped."
fi

ARR_USERCONF_PATH="${ARR_USERCONF_PATH:-}"
ARR_USERCONF_OVERRIDE_PATH="${ARR_USERCONF_OVERRIDE_PATH:-}"
arr_resolve_userconf_paths ARR_USERCONF_PATH ARR_USERCONF_OVERRIDE_PATH

source_user_conf() {
  local conf_path="$1"
  [[ -f "$conf_path" ]] || return 0

  local errlog
  errlog="$(mktemp)"
  local prev_trap
  prev_trap="$(trap -p ERR 2>/dev/null || true)"
  trap - ERR
  set +e
  # shellcheck disable=SC1090
  . "$conf_path" 2>"$errlog"
  local status=$?
  set -e
  if [[ -n "$prev_trap" ]]; then
    eval "$prev_trap"
  else
    trap - ERR
  fi
  if ((status != 0)); then
    warn "Failed to source user configuration (${conf_path}); aborting uninstall."
    if [[ -s "$errlog" ]]; then
      cat "$errlog" >&2 || true
    fi
    rm -f "$errlog"
    exit "$status"
  fi
  rm -f "$errlog"
}

source_user_conf "${ARR_USERCONF_PATH}" || true

apply_env_overrides() {
  local file="$1"
  [[ -f "$file" ]] || return 0

  local value=""
  if value="$(get_env_kv "STACK" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    STACK="$value"
  fi
  if value="$(get_env_kv "ARR_STACK_DIR" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARR_STACK_DIR="$value"
  fi
  if value="$(get_env_kv "ARRCONF_DIR" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARRCONF_DIR="$value"
  fi
  if value="$(get_env_kv "ARR_DOCKER_DIR" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARR_DOCKER_DIR="$value"
  fi
  if value="$(get_env_kv "ARR_ENV_FILE" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARR_ENV_FILE="$value"
  fi
  if value="$(get_env_kv "ARR_LOG_DIR" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARR_LOG_DIR="$value"
  fi
  if value="$(get_env_kv "ARR_USERCONF_PATH" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ARR_USERCONF_PATH="$value"
  fi
  if value="$(get_env_kv "LAN_IP" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    LAN_IP="$value"
  fi
  if value="$(get_env_kv "LAN_DOMAIN_SUFFIX" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    LAN_DOMAIN_SUFFIX="$value"
  fi
  if value="$(get_env_kv "ENABLE_LOCAL_DNS" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    ENABLE_LOCAL_DNS="$value"
  fi
  if value="$(get_env_kv "DNS_DISTRIBUTION_MODE" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    DNS_DISTRIBUTION_MODE="$value"
  fi
  if value="$(get_env_kv "UPSTREAM_DNS_SERVERS" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    UPSTREAM_DNS_SERVERS="$value"
  fi
  if value="$(get_env_kv "UPSTREAM_DNS_1" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    UPSTREAM_DNS_1="$value"
  fi
  if value="$(get_env_kv "UPSTREAM_DNS_2" "$file" 2>/dev/null || true)" && [[ -n "$value" ]]; then
    UPSTREAM_DNS_2="$value"
  fi
}

collect_env_candidates() {
  declare -a candidates=()
  local candidate=""

  candidate="$(arr_env_file)"
  [[ -n "$candidate" ]] && candidates+=("$candidate")

  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    candidates+=("${ARR_STACK_DIR%/}/.env")
  fi

  local default_stack
  default_stack="$(arr_stack_dir)"
  if [[ -n "$default_stack" ]]; then
    candidates+=("${default_stack%/}/.env")
  fi

  if [[ -n "${ARR_DATA_ROOT:-}" ]]; then
    candidates+=("${ARR_DATA_ROOT%/}/${STACK}/.env")
  fi

  declare -A seen=()
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" ]] || continue
    local canon
    canon="$(arr_canonical_path "$candidate")"
    if [[ -f "$canon" && -z "${seen[$canon]:-}" ]]; then
      apply_env_overrides "$canon"
      seen[$canon]=1
    fi
  done
}

collect_env_candidates

ARR_STACK_DIR="$(arr_stack_dir)"
ARRCONF_DIR="$(arr_conf_dir)"
ARR_DOCKER_DIR="$(arr_docker_data_root)"
ARR_ENV_FILE="$(arr_env_file)"
ARR_LOG_DIR="$(arr_log_dir)"
ARR_USERCONF_PATH="$(arr_userconf_path)"
STACK="${STACK:-arr}"
STACK_LABEL="[${STACK}]"

LAN_IP="${LAN_IP:-}"
LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX:-}"
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS:-}"
DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE:-}"
UPSTREAM_DNS_SERVERS="${UPSTREAM_DNS_SERVERS:-}"
UPSTREAM_DNS_1="${UPSTREAM_DNS_1:-}"
UPSTREAM_DNS_2="${UPSTREAM_DNS_2:-}"

add_unique_path() {
  local path="$1"
  [[ -n "$path" ]] || return 0
  local canon
  canon="$(arr_canonical_path "$path")"
  [[ -e "$canon" ]] || return 0
  if [[ -n "$REPO_CANON" && "$canon" == "$REPO_CANON"* ]]; then
    if [[ "$canon" != "$REPO_CANON" ]]; then
      warn "Skipping removal of ${canon} (inside repository)."
    else
      warn "Skipping removal of repository root ${canon}."
    fi
    return 0
  fi
  if [[ -z "${REMOVAL_SEEN[$canon]:-}" ]]; then
    REMOVAL_PATHS+=("$canon")
    REMOVAL_SEEN[$canon]=1
  fi
}

declare -a REMOVAL_PATHS=()
declare -A REMOVAL_SEEN=()

add_unique_path "$ARR_STACK_DIR"
if [[ "${ARRCONF_DIR}" != "${ARR_STACK_DIR}" ]]; then
  add_unique_path "$ARRCONF_DIR"
fi
if [[ "${ARR_DOCKER_DIR}" != "${ARR_STACK_DIR}" && "${ARR_DOCKER_DIR}" != "${ARRCONF_DIR}" ]]; then
  add_unique_path "$ARR_DOCKER_DIR"
fi
if [[ -n "$ARR_LOG_DIR" && "$ARR_LOG_DIR" != "$ARR_STACK_DIR" ]]; then
  add_unique_path "$ARR_LOG_DIR"
fi
if [[ -n "$ARR_ENV_FILE" ]]; then
  env_dir_uninstall="$(dirname "$ARR_ENV_FILE")"
  if [[ ! -d "$env_dir_uninstall" || "$env_dir_uninstall" != "$ARR_STACK_DIR" ]]; then
    add_unique_path "$ARR_ENV_FILE"
  fi
fi
if [[ -n "$ARR_USERCONF_PATH" ]]; then
  conf_dir_uninstall="$(dirname "$ARR_USERCONF_PATH")"
  if [[ "$conf_dir_uninstall" != "$ARRCONF_DIR" ]]; then
    add_unique_path "$ARR_USERCONF_PATH"
  fi
fi

resolve_project_name() {
  local project="${COMPOSE_PROJECT_NAME:-}"
  if [[ -n "$project" ]]; then
    printf '%s\n' "$project"
    return
  fi

  local -a env_candidates=()
  local candidate=""
  candidate="$(arr_env_file)"
  if [[ -n "${ARR_ENV_FILE:-}" ]]; then
    env_candidates+=("${ARR_ENV_FILE}")
    if [[ "${ARR_ENV_FILE}" != "$candidate" ]]; then
      env_candidates+=("$candidate")
    fi
  elif [[ -n "$candidate" ]]; then
    env_candidates+=("$candidate")
  fi

  for candidate in "${env_candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      local value
      if value="$(get_env_kv "COMPOSE_PROJECT_NAME" "$candidate" 2>/dev/null || true)" && [[ -n "$value" ]]; then
        project="$value"
        break
      fi
    fi
  done

  if [[ -z "$project" && -n "$ARR_STACK_DIR" ]]; then
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
    project="$STACK"
  fi

  printf '%s\n' "$project"
}

resolve_alias_targets() {
  ALIAS_RC_FILES=()
  ALIAS_HELPER_PATH="${ARR_STACK_DIR}/.aliasarr"
  [[ -n "$PRIMARY_HOME" ]] || return
  local bashrc="${PRIMARY_HOME}/.bashrc"
  local zshrc="${PRIMARY_HOME}/.zshrc"
  if [[ -f "$bashrc" ]]; then
    ALIAS_RC_FILES+=("$bashrc")
  fi
  if [[ -f "$zshrc" ]]; then
    ALIAS_RC_FILES+=("$zshrc")
  fi
}

resolve_alias_targets

install_file_with_privileges() {
  local src="$1"
  local dest="$2"
  local mode="${3:-}"
  local preserve_uid=""
  local preserve_gid=""
  local preserve_mode=""

  if [[ -z "$src" || -z "$dest" ]]; then
    return 1
  fi

  local dest_dir
  dest_dir="$(dirname "$dest")"

  if [[ -e "$dest" ]] && have_command stat; then
    preserve_uid="$(stat -c '%u' "$dest" 2>/dev/null || printf '')"
    preserve_gid="$(stat -c '%g' "$dest" 2>/dev/null || printf '')"
    preserve_mode="$(stat -c '%a' "$dest" 2>/dev/null || printf '')"
  fi

  if [[ ! -d "$dest_dir" ]]; then
    if mkdir -p "$dest_dir" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo mkdir -p "$dest_dir" 2>/dev/null || return 1
    else
      return 1
    fi
  fi

  if cp -f "$src" "$dest" 2>/dev/null; then
    :
  elif command -v sudo >/dev/null 2>&1; then
    sudo cp -f "$src" "$dest" 2>/dev/null || return 1
  else
    return 1
  fi

  if [[ -n "$preserve_uid" && -n "$preserve_gid" ]]; then
    if chown "${preserve_uid}:${preserve_gid}" "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chown "${preserve_uid}:${preserve_gid}" "$dest" 2>/dev/null || warn "Could not restore ownership on ${dest}"
    else
      warn "Could not restore ownership on ${dest}"
    fi
  fi

  if [[ -n "$mode" ]]; then
    if chmod "$mode" "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chmod "$mode" "$dest" 2>/dev/null || return 1
    else
      return 1
    fi
  elif [[ -n "$preserve_mode" ]]; then
    if chmod "$preserve_mode" "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chmod "$preserve_mode" "$dest" 2>/dev/null || warn "Could not restore mode on ${dest}"
    else
      warn "Could not restore mode on ${dest}"
    fi
  fi

  return 0
}

HOSTS_BLOCK_PRESENT=0
HOSTS_BLOCK_IP=""

detect_managed_hosts_metadata() {
  local hosts_file="/etc/hosts"
  [[ -f "$hosts_file" ]] || return 0

  while IFS= read -r line; do
    if [[ "$line" == *"${STACK}-managed"* ]]; then
      local trimmed
      trimmed="$(trim_string "$line")"
      if [[ "$trimmed" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})[[:space:]].*#[[:space:]]+${STACK}-managed[[:space:]]+(.+)$ ]]; then
        HOSTS_BLOCK_PRESENT=1
        HOSTS_BLOCK_IP="${BASH_REMATCH[1]}"
        break
      fi
      if [[ "$trimmed" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})[[:space:]].*#[[:space:]]+${STACK}-managed$ ]]; then
        HOSTS_BLOCK_PRESENT=1
        HOSTS_BLOCK_IP="${BASH_REMATCH[1]}"
        break
      fi
    fi
  done <"$hosts_file"
}

detect_managed_hosts_metadata

LAN_IP_EFFECTIVE="${LAN_IP:-}"
if [[ -z "$LAN_IP_EFFECTIVE" || "$LAN_IP_EFFECTIVE" == "0.0.0.0" ]]; then
  if [[ -n "$HOSTS_BLOCK_IP" ]]; then
    LAN_IP_EFFECTIVE="$HOSTS_BLOCK_IP"
  fi
fi

remove_managed_hosts_entries() {
  local hosts_file="/etc/hosts"
  [[ -f "$hosts_file" ]] || return 1

  if ! grep -qi "${STACK}-managed" "$hosts_file" 2>/dev/null; then
    return 1
  fi

  local tmp
  tmp="$(arr_mktemp_file "${hosts_file}.XXXXXX" 644)" || return 2

  if have_command python3; then
    if ! python3 - "$hosts_file" "$tmp" "$STACK" <<'PY'
import os
import sys

src, dst, stack = sys.argv[1:4]
begin = f"# >>> {stack}-managed hosts >>>"
end = f"# <<< {stack}-managed hosts <<<"
marker = f"{stack}-managed"

try:
    with open(src, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
except OSError:
    sys.exit(1)

skip = False
out = []
marker_lower = marker.lower()
for line in lines:
    stripped = line.rstrip("\n")
    if stripped == begin:
        skip = True
        continue
    if stripped == end:
        skip = False
        continue
    if marker_lower in stripped.lower():
        continue
    if not skip:
        out.append(line)

try:
    with open(dst, "w", encoding="utf-8") as fh:
        fh.writelines(out)
except OSError:
    sys.exit(1)
PY
    then
      rm -f "$tmp"
      return 2
    fi
  else
    if ! awk -v begin="# >>> ${STACK}-managed hosts >>>" \
      -v end="# <<< ${STACK}-managed hosts <<<" \
      -v marker="${STACK}-managed" '
      BEGIN {
        skip = 0
        marker_lower = tolower(marker)
      }
      {
        line = $0
        stripped = gensub(/[[:space:]]+$/, "", "g", line)
        if (stripped == begin) {
          skip = 1
          next
        }
        if (stripped == end) {
          skip = 0
          next
        }
        if (index(tolower(line), marker_lower) > 0) {
          next
        }
        if (!skip) {
          print line
        }
      }
    ' "$hosts_file" >"$tmp"; then
      rm -f "$tmp"
      return 2
    fi
  fi

  if ! install_file_with_privileges "$tmp" "$hosts_file" 644; then
    rm -f "$tmp"
    return 2
  fi

  rm -f "$tmp"
  return 0
}

verify_hosts_removal() {
  local hosts_file="/etc/hosts"
  [[ -f "$hosts_file" ]] || return 0

  if grep -qi "${STACK}-managed" "$hosts_file" 2>/dev/null; then
    warn "  Managed entries for ${STACK} still present in /etc/hosts"
    return 1
  fi

  msg "  Verified /etc/hosts no longer contains ${STACK}-managed entries"
  return 0
}

restore_docker_daemon_dns() {
  local daemon_json="/etc/docker/daemon.json"

  if [[ ! -e "$daemon_json" ]]; then
    return 1
  fi

  local backup=""
  local candidate
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    backup="$candidate"
    break
  done < <(ls -1t "${daemon_json}.${STACK}"*.bak 2>/dev/null || true)

  local tmp=""
  if [[ -n "$backup" && -f "$backup" ]]; then
    tmp="$(arr_mktemp_file "${daemon_json}.XXXXXX" 644)" || return 2
    if ! cp -f "$backup" "$tmp" 2>/dev/null; then
      if command -v sudo >/dev/null 2>&1; then
        sudo cp -f "$backup" "$tmp" 2>/dev/null || {
          rm -f "$tmp"
          return 2
        }
      else
        rm -f "$tmp"
        return 2
      fi
    fi
  else
    if [[ -z "$LAN_IP_EFFECTIVE" || "$LAN_IP_EFFECTIVE" == "0.0.0.0" ]]; then
      return 1
    fi
    tmp="$(arr_mktemp_file "${daemon_json}.XXXXXX" 644)" || return 2
    if have_command python3; then
      if ! LAN_IP_VALUE="$LAN_IP_EFFECTIVE" python3 - "$daemon_json" "$tmp" <<'PY'
import json
import os
import sys

src, dst = sys.argv[1:3]
lan_ip = os.environ.get("LAN_IP_VALUE", "")

try:
    with open(src, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except FileNotFoundError:
    data = {}
except json.JSONDecodeError:
    data = {}

changed = False
if isinstance(data, dict) and "dns" in data:
    dns_value = data.get("dns")
    if isinstance(dns_value, list):
        filtered = [entry for entry in dns_value if entry != lan_ip]
        if len(filtered) != len(dns_value):
            changed = True
        dns_value = [entry for entry in filtered if entry]
        if dns_value:
            data["dns"] = dns_value
        else:
            data.pop("dns", None)
            changed = True

if not changed:
    sys.exit(1)

with open(dst, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
PY
      then
        rm -f "$tmp"
        return 1
      fi
    elif have_command jq; then
      if ! jq --arg lan "$LAN_IP_EFFECTIVE" 'if (.dns // []) | type == "array" then
          (.dns |= map(select(. != $lan))) | if (.dns | length) == 0 then del(.dns) else . end
        else
          empty
        end' "$daemon_json" 2>/dev/null >"$tmp"; then
        rm -f "$tmp"
        return 1
      fi
      if cmp -s "$daemon_json" "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
      fi
    else
      rm -f "$tmp"
      return 2
    fi
  fi

  if ! install_file_with_privileges "$tmp" "$daemon_json" 644; then
    rm -f "$tmp"
    return 2
  fi

  rm -f "$tmp"
  return 0
}

verify_docker_dns_state() {
  local daemon_json="/etc/docker/daemon.json"

  if [[ ! -f "$daemon_json" ]]; then
    msg "  Docker daemon.json absent; no DNS overrides remain"
    return 0
  fi

  if [[ -z "$LAN_IP_EFFECTIVE" || "$LAN_IP_EFFECTIVE" == "0.0.0.0" ]]; then
    warn "  Unable to verify Docker DNS removal (LAN_IP unknown)"
    return 1
  fi

  if have_command python3; then
    if LAN_IP_VALUE="$LAN_IP_EFFECTIVE" python3 - "$daemon_json" <<'PY'
import json
import os
import sys

daemon = sys.argv[1]
lan_ip = os.environ.get("LAN_IP_VALUE", "")

try:
    with open(daemon, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(1)

dns_value = data.get("dns")
if isinstance(dns_value, list) and lan_ip in dns_value:
    sys.exit(1)

sys.exit(0)
PY
    then
      msg "  Verified Docker daemon.json no longer references ${LAN_IP_EFFECTIVE}"
      return 0
    fi
  elif have_command jq; then
    if jq -e --arg lan "$LAN_IP_EFFECTIVE" '(.dns // []) | index($lan) | not' "$daemon_json" >/dev/null 2>&1; then
      msg "  Verified Docker daemon.json no longer references ${LAN_IP_EFFECTIVE}"
      return 0
    fi
  fi

  warn "  Docker daemon.json still references ${LAN_IP_EFFECTIVE}; review manually"
  return 1
}

verify_dns_rollback_state() {
  local resolv="/etc/resolv.conf"
  local service="systemd-resolved.service"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
      msg "  systemd-resolved is enabled"
    else
      warn "  systemd-resolved is not enabled; verify DNS configuration"
    fi
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      msg "  systemd-resolved is running"
    else
      warn "  systemd-resolved is not running"
    fi
  fi

  if [[ -f "$resolv" ]]; then
    if grep -Fq "Generated by ${STACK} host-dns-setup" "$resolv" 2>/dev/null; then
      warn "  /etc/resolv.conf still contains ${STACK} host-dns-setup marker"
    else
      msg "  /etc/resolv.conf no longer contains ${STACK} host-dns-setup marker"
    fi
  fi
}

needs_dns_rollback() {
  local marker="/etc/resolv.conf"
  if [[ -f "$marker" ]]; then
    if grep -Fq "Generated by ${STACK} host-dns-setup" "$marker" 2>/dev/null; then
      return 0
    fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
      return 0
    fi
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

CADDY_CA_TARGETS=()
if [[ -n "$STACK" ]]; then
  CADDY_CA_TARGETS+=("/usr/local/share/ca-certificates/${STACK}-caddy-ca.crt")
  CADDY_CA_TARGETS+=("/usr/local/share/ca-certificates/${STACK}-caddy-ca.pem")
fi

step "Detected installation state"
msg "  Stack name: ${STACK}"
msg "  Stack directory: ${ARR_STACK_DIR:-<unknown>}"
msg "  Config directory: ${ARRCONF_DIR:-<unknown>}"
msg "  Docker data root: ${ARR_DOCKER_DIR:-<unknown>}"
msg "  Environment file: ${ARR_ENV_FILE:-<unknown>}"
msg "  User config: ${ARR_USERCONF_PATH:-<unknown>}"
if [[ -n "${PRIMARY_HOME}" ]]; then
  msg "  Shell config home: ${PRIMARY_HOME}"
fi

if ((${#REMOVAL_PATHS[@]} == 0)); then
  warn "No managed files or directories were detected."
fi

if [[ "$ASSUME_YES" != "1" ]]; then
  printf '%s Proceed with removing the ARR stack and related assets? [y/N]: ' "$STACK_LABEL"
  if ! read -r response; then
    die "Failed to read confirmation input"
  fi
  case "${response,,}" in
    y|yes) ;;
    *)
      msg "Uninstall aborted."
      exit 0
      ;;
  esac
fi

compose_command=()
detect_compose_command() {
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1 || docker compose -v >/dev/null 2>&1; then
      compose_command=(docker compose)
      return 0
    fi
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    if docker-compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1; then
      compose_command=(docker-compose)
      return 0
    fi
  fi
  compose_command=()
  return 1
}

step "Stopping Docker services"
if detect_compose_command && [[ -f "${ARR_STACK_DIR}/docker-compose.yml" ]]; then
  msg "  Using compose command: ${compose_command[*]}"
  (
    set +e
    cd "$ARR_STACK_DIR" 2>/dev/null || exit 0
    "${compose_command[@]}" down --remove-orphans --volumes >/dev/null 2>&1
  ) || warn "Docker compose teardown may not have completed cleanly."
else
  warn "Compose command unavailable or docker-compose.yml missing; skipping compose teardown."
fi

if command -v docker >/dev/null 2>&1; then
  project_name="$(resolve_project_name)"
  if [[ -n "$project_name" ]]; then
    mapfile -t arr_containers < <(docker ps -a --filter "label=com.docker.compose.project=${project_name}" --format '{{.ID}}' 2>/dev/null || true)
    if ((${#arr_containers[@]} > 0)); then
      docker rm -f "${arr_containers[@]}" >/dev/null 2>&1 || warn "Failed to remove compose containers (${project_name})."
    fi
  fi
else
  warn "Docker command not available; container cleanup skipped."
fi

if needs_dns_rollback; then
  step "Restoring system DNS"
  if ! bash "${REPO_ROOT}/scripts/host-dns-rollback.sh" >/dev/null 2>&1; then
    warn "Host DNS rollback reported issues. Review scripts/host-dns-rollback.sh output manually."
  else
    msg "  systemd-resolved re-enabled and /etc/resolv.conf restored."
  fi
  verify_dns_rollback_state
fi

step "Reverting managed host entries"
hosts_cleanup_status=0
if ! remove_managed_hosts_entries; then
  hosts_cleanup_status=$?
fi
case "$hosts_cleanup_status" in
  0)
    msg "  Removed ${STACK}-managed block from /etc/hosts"
    verify_hosts_removal
    ;;
  1)
    if [[ "$HOSTS_BLOCK_PRESENT" == "1" ]]; then
      warn "  Unable to locate removable ${STACK}-managed hosts block"
    else
      msg "  No ${STACK}-managed hosts entries detected"
    fi
    ;;
  2)
    warn "  Failed to update /etc/hosts; remove ${STACK}-managed entries manually"
    ;;
esac

step "Restoring Docker DNS configuration"
docker_dns_status=0
if ! restore_docker_daemon_dns; then
  docker_dns_status=$?
fi
case "$docker_dns_status" in
  0)
    msg "  Restored /etc/docker/daemon.json DNS settings"
    verify_docker_dns_state
    ;;
  1)
    if [[ -z "$LAN_IP_EFFECTIVE" || "$LAN_IP_EFFECTIVE" == "0.0.0.0" ]]; then
      warn "  LAN_IP unknown; unable to automatically confirm Docker DNS overrides"
    else
      msg "  No Docker DNS overrides detected"
    fi
    ;;
  2)
    warn "  Unable to restore Docker DNS settings; inspect /etc/docker/daemon.json manually"
    ;;
esac

step "Removing installer files"
for path in "${REMOVAL_PATHS[@]}"; do
  if [[ -e "$path" ]]; then
    rm -rf "$path" 2>/dev/null || warn "Unable to remove ${path}"
  fi
done

if [[ -n "${ARR_STACK_DIR}" ]]; then
  parent_dir_cleanup="$(dirname "$ARR_STACK_DIR")"
  if [[ -d "$parent_dir_cleanup" ]]; then
    rmdir "$parent_dir_cleanup" 2>/dev/null || true
  fi
fi
if [[ -n "${ARR_DATA_ROOT:-}" ]]; then
  rmdir "${ARR_DATA_ROOT}" 2>/dev/null || true
fi

remove_alias_block() {
  local rc_file="$1"
  local alias_path="$2"
  [[ -f "$rc_file" ]] || return 1
  if ! grep -Fq "# ARR Stack helper aliases" "$rc_file" 2>/dev/null; then
    return 1
  fi
  local restore_uid=""
  local restore_gid=""
  local restore_mode=""
  if have_command stat; then
    restore_uid="$(stat -c '%u' "$rc_file" 2>/dev/null || printf '')"
    restore_gid="$(stat -c '%g' "$rc_file" 2>/dev/null || printf '')"
    restore_mode="$(stat -c '%a' "$rc_file" 2>/dev/null || printf '')"
  fi

  local updated=1
  if have_command python3; then
    if python3 - "$rc_file" "$STACK" "$alias_path" <<'PY'
import re
import sys
path, stack, alias_path = sys.argv[1:4]
try:
    data = open(path, 'r', encoding='utf-8').read()
except OSError:
    sys.exit(1)
pattern = (r"\n# ARR Stack helper aliases\n"
           + rf"alias {re.escape(stack)}='[^\n]*'\n"
           + rf"alias {re.escape(stack)}-logs='[^\n]*'\n"
           + rf"\[ -f \"{re.escape(alias_path)}\" \] && source \"{re.escape(alias_path)}\"\n?")
new_data, count = re.subn(pattern, '\n', data)
if count:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_data)
    sys.exit(0)
sys.exit(1)
PY
    then
      updated=0
    fi
  fi

  if ((updated != 0)); then
    if sed -i '/^# ARR Stack helper aliases$/,/^$/d' "$rc_file"; then
      updated=0
    else
      return 1
    fi
  fi

  if ((updated == 0)); then
    if [[ -n "$restore_uid" && -n "$restore_gid" ]]; then
      chown "${restore_uid}:${restore_gid}" "$rc_file" 2>/dev/null || warn "Unable to restore ownership on ${rc_file}"
    fi
    if [[ -n "$restore_mode" ]]; then
      chmod "$restore_mode" "$rc_file" 2>/dev/null || warn "Unable to restore permissions on ${rc_file}"
    fi
  fi

  return $updated
}

if [[ -n "${ALIAS_HELPER_PATH}" && -n "${PRIMARY_HOME}" ]]; then
  step "Cleaning shell aliases"
  removed_any=0
  for rc in "${ALIAS_RC_FILES[@]}"; do
    if remove_alias_block "$rc" "$ALIAS_HELPER_PATH"; then
      msg "  Removed ARR alias block from ${rc}"
      removed_any=1
    fi
  done
  if [[ -f "$ALIAS_HELPER_PATH" ]]; then
    rm -f "$ALIAS_HELPER_PATH" 2>/dev/null || true
  fi
  legacy_alias_file="${ARR_STACK_DIR}/.arraliases"
  if [[ -f "$legacy_alias_file" ]]; then
    rm -f "$legacy_alias_file" 2>/dev/null || true
  fi
  if [[ "$removed_any" != 1 ]]; then
    msg "  No ARR alias blocks found in shell rc files."
  fi
fi

remove_caddy_ca() {
  local target="$1"
  [[ -f "$target" ]] || return 1
  if [[ $EUID -eq 0 ]]; then
    rm -f "$target"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo rm -f "$target"
    return $?
  fi
  warn "Run manually to remove ${target} (requires root)."
  return 1
}

ca_removed=0
for target in "${CADDY_CA_TARGETS[@]}"; do
  if [[ -f "$target" ]]; then
    if remove_caddy_ca "$target"; then
      msg "Removed Caddy CA certificate at ${target}"
      ca_removed=1
    fi
  fi
done

if ((ca_removed)); then
  if command -v update-ca-certificates >/dev/null 2>&1; then
    if [[ $EUID -eq 0 ]]; then
      update-ca-certificates >/dev/null 2>&1 || warn "update-ca-certificates failed"
    elif command -v sudo >/dev/null 2>&1; then
      sudo update-ca-certificates >/dev/null 2>&1 || warn "update-ca-certificates via sudo failed"
    else
      warn "Run update-ca-certificates manually to refresh trust store."
    fi
  else
    warn "update-ca-certificates not found; refresh your system trust store manually."
  fi
fi

msg "ARR stack uninstall complete."
exit 0

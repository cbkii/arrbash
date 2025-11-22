#!/usr/bin/env bash

usage() {
  cat <<'USAGE'
Usage: ./scripts/stack-uninstall.sh [options]

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

COMMON_LIB="${REPO_ROOT}/scripts/stack-common.sh"
if [[ -f "$COMMON_LIB" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "$COMMON_LIB"
else
  printf '[ERROR] Missing required module: %s\n' "$COMMON_LIB" >&2
  exit 1
fi

USERCONF_LIB="${REPO_ROOT}/scripts/env-userconf.sh"
if [[ -f "$USERCONF_LIB" ]]; then
  # shellcheck source=scripts/env-userconf.sh
  . "$USERCONF_LIB"
else
  die "Missing helper library: ${USERCONF_LIB}"
fi

for arg in "$@"; do
  case "$arg" in
    --help | -h)
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
    --help | -h)
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
  set +u
  . "$DEFAULTS_PATH"
  set -u
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

arr_resolve_userconf_paths ARR_USERCONF_PATH ARR_USERCONF_OVERRIDE_PATH

source_user_conf() {
  local conf_path="$1"
  [[ -f "$conf_path" ]] || return 0

  local errlog=""
  if ! errlog="$(arr_mktemp_file "/tmp/arr-uninstall-userconf.XXXXXX" 600)"; then
    warn "Unable to create temporary log for sourcing ${conf_path}; aborting uninstall."
    exit 1
  fi

  local prev_trap
  prev_trap="$(trap -p ERR 2>/dev/null || true)"
  trap - ERR
  set +e
  set +u
  # shellcheck disable=SC1090
  . "$conf_path" 2>"$errlog"
  local status=$?
  set -u
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
    arr_cleanup_temp_path "$errlog"
    exit "$status"
  fi

  arr_cleanup_temp_path "$errlog"
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
    canon="$(arr_canonical_path "$candidate" 2>/dev/null || true)"
    if [[ -z "$canon" ]]; then
      continue
    fi
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

is_protected_removal_path() {
  local path="$1"
  case "$path" in
    '' | / | /bin | /boot | /etc | /home | /lib | /lib64 | /opt | /root | /sbin | /usr | /usr/local | /var)
      return 0
      ;;
  esac
  return 1
}

add_unique_path() {
  local path="$1"
  [[ -n "$path" ]] || return 0
  local canon
  canon="$(arr_canonical_path "$path" 2>/dev/null || true)"
  if [[ -z "$canon" ]]; then
    warn "Skipping removal target ${path} (unable to resolve canonical path)."
    return 0
  fi
  if is_protected_removal_path "$canon"; then
    warn "Skipping removal of protected path ${canon}."
    return 0
  fi
  if [[ "$canon" == "/" ]]; then
    warn "Skipping removal of root directory /."
    return 0
  fi
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
  if declare -f arr_stack_dir >/dev/null 2>&1; then
    ALIAS_HELPER_PATH="$(arr_stack_dir)/.aliasarr"
  else
    ALIAS_HELPER_PATH="${ARR_STACK_DIR}/.aliasarr"
  fi
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
    if mkdir -p -- "$dest_dir" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo mkdir -p -- "$dest_dir" 2>/dev/null || return 1
    else
      return 1
    fi
  fi

  if cp -f -- "$src" "$dest" 2>/dev/null; then
    :
  elif command -v sudo >/dev/null 2>&1; then
    sudo cp -f -- "$src" "$dest" 2>/dev/null || return 1
  else
    return 1
  fi

  if [[ -n "$preserve_uid" && -n "$preserve_gid" ]]; then
    if chown "${preserve_uid}:${preserve_gid}" -- "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chown "${preserve_uid}:${preserve_gid}" -- "$dest" 2>/dev/null || warn "Could not restore ownership on ${dest}"
    else
      warn "Could not restore ownership on ${dest}"
    fi
  fi

  if [[ -n "$mode" ]]; then
    if chmod "$mode" -- "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chmod "$mode" -- "$dest" 2>/dev/null || return 1
    else
      return 1
    fi
  elif [[ -n "$preserve_mode" ]]; then
    if chmod "$preserve_mode" -- "$dest" 2>/dev/null; then
      :
    elif command -v sudo >/dev/null 2>&1; then
      sudo chmod "$preserve_mode" -- "$dest" 2>/dev/null || warn "Could not restore mode on ${dest}"
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

  local tmp status
  tmp="$(arr_mktemp_file "${hosts_file}.XXXXXX" 644)" || return 2
  status=0

  if awk -v begin="# >>> ${STACK}-managed hosts >>>" \
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
    if cmp -s "$hosts_file" "$tmp" 2>/dev/null; then
      status=1
    elif ! install_file_with_privileges "$tmp" "$hosts_file" 644; then
      status=2
    fi
  else
    status=2
  fi

  arr_cleanup_temp_path "$tmp"
  return $status
}

verify_hosts_removal() {
  local hosts_file="/etc/hosts"
  [[ -f "$hosts_file" ]] || return 0

  if grep -qi "${STACK}-managed" "$hosts_file" 2>/dev/null; then
    warn "Managed entries for ${STACK} still present in /etc/hosts"
    return 1
  fi

  msg "Verified /etc/hosts no longer contains ${STACK}-managed entries"
  return 0
}

step "Detected installation state"
msg "Stack name: ${STACK}"
msg "Stack directory: ${ARR_STACK_DIR:-<unknown>}"
msg "Config directory: ${ARRCONF_DIR:-<unknown>}"
msg "Docker data root: ${ARR_DOCKER_DIR:-<unknown>}"
msg "Environment file: ${ARR_ENV_FILE:-<unknown>}"
msg "User config: ${ARR_USERCONF_PATH:-<unknown>}"
if [[ -n "${PRIMARY_HOME}" ]]; then
  msg "Shell config home: ${PRIMARY_HOME}"
fi

if ((${#REMOVAL_PATHS[@]} == 0)); then
  warn "No managed files or directories were detected."
fi

prompt_confirmation() {
  local prompt="$1"
  local response=""

  if [[ "$ASSUME_YES" == "1" ]]; then
    return 0
  fi

  if [[ -t 0 ]]; then
    printf '%s ' "$prompt"
    if ! read -r response; then
      return 2
    fi
  elif [[ -t 1 && -r /dev/tty ]]; then
    printf '%s ' "$prompt" >/dev/tty || true
    if ! read -r response </dev/tty; then
      return 2
    fi
  else
    warn "No interactive terminal available; re-run with --yes to skip confirmation."
    return 2
  fi

  case "${response,,}" in
    y | yes)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

if [[ "$ASSUME_YES" != "1" ]]; then
  prompt_confirmation "${STACK_LABEL} Proceed with removing the ARR stack and related assets? [y/N]:"
  confirmation_status=$?
  case "$confirmation_status" in
    0) ;;
    1)
      msg "Uninstall aborted."
      exit 0
      ;;
    *)
      die "Failed to read confirmation input; use --yes to skip prompts."
      ;;
  esac
fi

remove_path_with_privileges() {
  local target="$1"
  [[ -n "$target" ]] || return 1

  local canon
  canon="$(arr_canonical_path "$target" 2>/dev/null || true)"
  if [[ -z "$canon" ]]; then
    warn "Unable to resolve canonical path for ${target}; skipping removal."
    return 1
  fi
  if is_protected_removal_path "$canon"; then
    warn "Refusing to remove protected path ${canon}."
    return 1
  fi
  if [[ "$canon" == "/" ]]; then
    warn "Refusing to remove ${target}; resolved path is root directory."
    return 1
  fi

  if rm -rf -- "$target" 2>/dev/null; then
    return 0
  fi

  if command -v sudo >/dev/null 2>&1; then
    if sudo rm -rf -- "$target" 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

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
  msg "Using compose command: ${compose_command[*]}"
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

step "Reverting managed host entries"
hosts_cleanup_status=0
if ! remove_managed_hosts_entries; then
  hosts_cleanup_status=$?
fi
case "$hosts_cleanup_status" in
  0)
    msg "Removed ${STACK}-managed block from /etc/hosts"
    verify_hosts_removal
    ;;
  1)
    if [[ "$HOSTS_BLOCK_PRESENT" == "1" ]]; then
      warn "Unable to locate removable ${STACK}-managed hosts block"
    else
      msg "No ${STACK}-managed hosts entries detected"
    fi
    ;;
  2)
    warn "Failed to update /etc/hosts; remove ${STACK}-managed entries manually"
    ;;
esac

step "Removing installer files"
for path in "${REMOVAL_PATHS[@]}"; do
  if [[ -e "$path" ]]; then
    if ! remove_path_with_privileges "$path"; then
      warn "Unable to remove ${path}"
    fi
  fi
done

# The rmdir calls are removed to avoid unintended side effects on shared parent directories.

remove_alias_block() {
  local rc_file="$1"
  local alias_path="$2"
  [[ -f "$rc_file" ]] || return 1
  if ! grep -Fq "# ARR Stack helper aliases" "$rc_file" 2>/dev/null; then
    return 1
  fi
  local tmp=""
  tmp="$(arr_mktemp_file "${rc_file}.XXXXXX" 600)" || return 2

  if ! awk -v stack="$STACK" -v alias_path="$alias_path" '
    BEGIN {
      last_blank = 0
      pattern = "\\[ -f \"" alias_path "\" \\] && source \"" alias_path "\"[[:space:]]*$"
    }
    {
      if ($0 ~ /^# ARR Stack helper aliases[[:space:]]*$/) {
        next
      }
      if ($0 ~ ("^alias " stack "='")) {
        next
      }
      if ($0 ~ ("^alias " stack "-logs='")) {
        next
      }
      if ($0 ~ pattern) {
        next
      }
      if ($0 ~ /^[[:space:]]*$/) {
        if (last_blank) {
          next
        }
        last_blank = 1
        print
        next
      }
      last_blank = 0
      print
    }
  ' "$rc_file" >"$tmp"; then
    arr_cleanup_temp_path "$tmp"
    return 2
  fi

  if cmp -s "$rc_file" "$tmp" 2>/dev/null; then
    arr_cleanup_temp_path "$tmp"
    return 1
  fi

  if ! install_file_with_privileges "$tmp" "$rc_file"; then
    arr_cleanup_temp_path "$tmp"
    return 2
  fi

  arr_cleanup_temp_path "$tmp"
  return 0
}

if [[ -n "${ALIAS_HELPER_PATH}" && -n "${PRIMARY_HOME}" ]]; then
  step "Cleaning shell aliases"
  removed_any=0
  for rc in "${ALIAS_RC_FILES[@]}"; do
    if remove_alias_block "$rc" "$ALIAS_HELPER_PATH"; then
      msg "Removed ARR alias block from ${rc}"
      removed_any=1
    fi
  done
  if [[ -f "$ALIAS_HELPER_PATH" ]]; then
    remove_path_with_privileges "$ALIAS_HELPER_PATH" || true
  fi
  if [[ "$removed_any" != 1 ]]; then
    msg "No ARR alias blocks found in shell rc files."
  fi
fi

msg "ARR stack uninstall complete."
exit 0

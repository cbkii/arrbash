#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
set -Eeuo pipefail

# Secure default file creation; allow opt-out for legacy setups
if [[ "${ARR_DISABLE_UMASK:-0}" != "1" ]]; then
  umask 027
fi

# Reports failing location before exiting to speed triage of installer faults
arr_err_trap() {
  local rc=$?
  trap - ERR
  local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  local line="${BASH_LINENO[0]:-${LINENO}}"
  printf '[arrstack] error at %s:%s (status=%s)\n' "${src}" "${line}" "${rc}" >&2
  exit "${rc}"
}

# Install trap early so sourcing failures have context
trap 'arr_err_trap' ERR

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
if [ -f "${REPO_ROOT}/arrconf/userr.conf.defaults.sh" ]; then
  # shellcheck source=arrconf/userr.conf.defaults.sh disable=SC1091
  . "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
fi

# Resolve and optionally constrain user config
ARR_USERCONF_PATH="${ARR_USERCONF_PATH:-${ARR_BASE:-${HOME}/srv}/userr.conf}"
_expected_base="${ARR_BASE:-${HOME}/srv}"
_canon_base="$(readlink -f "${_expected_base}" 2>/dev/null || printf '%s' "${_expected_base}")"
_canon_userconf="$(readlink -f "${ARR_USERCONF_PATH}" 2>/dev/null || printf '%s' "${ARR_USERCONF_PATH}")"
ARR_USERCONF_PATH="${_canon_userconf}"

_arr_timezone_before="${TIMEZONE:-}"

# Returns 0 if the given variable name is readonly, 1 otherwise
arr_var_is_readonly() {
  local varname=$1 out
  # Ensure it's a variable that exists (not a function); bail if missing.
  out=$(declare -p -- "$varname" 2>/dev/null) || return 1
  # Bash prints like: "declare -r name=…", "declare -rx name=…", "declare -ar name=…"
  [[ $out == declare\ -*r* ]] && return 0
  return 1
}

declare -a _arr_env_override_order=()
declare -A _arr_env_overrides=()
declare -A _arr_env_override_seen=()
if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
  while IFS= read -r _arr_env_var; do
    [[ -n "${_arr_env_var}" ]] || continue
    if [[ -z "${_arr_env_override_seen[${_arr_env_var}]+x}" ]]; then
      _arr_env_override_order+=("${_arr_env_var}")
      _arr_env_override_seen["${_arr_env_var}"]=1
    fi
  done < <(arr_collect_all_expected_env_keys)
else
  while read -r _arr_env_line; do
    _arr_env_var="${_arr_env_line%%=*}"
    if [[ "${_arr_env_var}" == ARR_* ]]; then
      if [[ -z "${_arr_env_override_seen[${_arr_env_var}]+x}" ]]; then
        _arr_env_override_order+=("${_arr_env_var}")
        _arr_env_override_seen["${_arr_env_var}"]=1
      fi
    fi
  done < <(env)
fi
unset -v _arr_env_override_seen _arr_env_rest 2>/dev/null || :

for _arr_env_var in "${_arr_env_override_order[@]}"; do
  if [[ "$(declare -p -- "$_arr_env_var" 2>/dev/null)" == "declare -x "* ]]; then
    if [[ ${!_arr_env_var+x} ]]; then
      _arr_env_overrides["${_arr_env_var}"]="${!_arr_env_var}"
    else
      _arr_env_overrides["${_arr_env_var}"]=""
    fi
  fi
done
unset _arr_env_var

for _arr_env_var in "${_arr_env_override_order[@]}"; do
  if [[ -v "_arr_env_overrides[${_arr_env_var}]" ]]; then
    if [[ "${_arr_env_var}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
      if ! arr_var_is_readonly "${_arr_env_var}"; then
        readonly "${_arr_env_var}" 2>/dev/null || :
      fi
    else
      printf '[arrstack] WARN: Skipping readonly guard for invalid environment variable name: %s (must start with letter or underscore and contain only alphanumeric characters and underscores)\n' "${_arr_env_var}" >&2
    fi
  fi
done
unset _arr_env_var

if [[ "${ARR_USERCONF_ALLOW_OUTSIDE:-0}" != "1" ]]; then
  if [[ "${_canon_userconf}" != "${_canon_base}/userr.conf" ]]; then
    if [[ "${ARR_USERCONF_STRICT:-0}" == "1" ]]; then
      printf '[arrstack] user config path outside base (%s): %s (strict mode)\n' "${_canon_base}" "${_canon_userconf}" >&2
      exit 1
    else
      printf '[arrstack] WARN: user config outside expected base (%s): %s\n' "${_canon_base}" "${_canon_userconf}" >&2
    fi
  fi
fi

if [[ -f "${ARR_USERCONF_PATH}" ]]; then
  _arr_userr_conf_errlog="$(mktemp)"
  # Save current ERR trap (if any), then disable while sourcing user config
  _prev_err_trap="$(trap -p ERR 2>/dev/null || true)"
  trap - ERR
  set +e
  # shellcheck source=/dev/null
  . "${ARR_USERCONF_PATH}" 2>"${_arr_userr_conf_errlog}"
  _arr_userr_conf_status=$?
  set -e
  # Restore previous ERR trap exactly as it was
  if [[ -n "${_prev_err_trap}" ]]; then
    eval "${_prev_err_trap}"
  else
    trap - ERR
  fi
  unset _prev_err_trap

  if ((_arr_userr_conf_status != 0)); then
    if [[ -s "${_arr_userr_conf_errlog}" ]] && ! grep -v "readonly variable" "${_arr_userr_conf_errlog}" >/dev/null; then
      :
    else
      printf '[arrstack] Failed to source user config (status=%s): %s\n' "${_arr_userr_conf_status}" "${ARR_USERCONF_PATH}" >&2
      # Replay captured stderr to aid debugging
      cat "${_arr_userr_conf_errlog}" >&2 || :
      rm -f "${_arr_userr_conf_errlog}"
      exit "${_arr_userr_conf_status}"
    fi
  fi
  rm -f "${_arr_userr_conf_errlog}"
  unset _arr_userr_conf_status _arr_userr_conf_errlog
fi
for _arr_env_var in "${_arr_env_override_order[@]}"; do
  if [[ -v "_arr_env_overrides[${_arr_env_var}]" ]]; then
    if arr_var_is_readonly "${_arr_env_var}"; then
      continue
    fi
    # Validate variable name format before assignment
    if [[ "${_arr_env_var}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
      printf -v "${_arr_env_var}" '%s' "${_arr_env_overrides[${_arr_env_var}]}"
      export "${_arr_env_var}"
    else
      printf '[arrstack] WARN: Skipping invalid environment variable name: %s\n' "${_arr_env_var}" >&2
    fi
  fi
done
unset _arr_env_var

_arr_userconf_timezone_override=0
if [[ -n "${TIMEZONE:-}" ]]; then
  if [[ "${TIMEZONE}" != "${_arr_timezone_before:-}" ]]; then
    _arr_userconf_timezone_override=1
  elif [[ -f "${ARR_USERCONF_PATH}" ]]; then
    if grep -Eq '^[[:space:]]*(export|readonly|typeset|declare)?([[:space:]]+-[[:alnum:]]+)*[[:space:]]*TIMEZONE[[:space:]]*=' "${ARR_USERCONF_PATH}" 2>/dev/null; then
      _arr_userconf_timezone_override=1
    fi
  fi
fi

if ((_arr_userconf_timezone_override)); then
  ARR_TIMEZONE_AUTO_SOURCE="provided"
  ARR_TIMEZONE_AUTO_FALLBACK=0
  ARR_TIMEZONE_DETECTED_VALUE=""
else
  if [[ -z "${TIMEZONE:-}" ]]; then
    if declare -f arr_detect_timezone >/dev/null 2>&1; then
      TIMEZONE="$(arr_detect_timezone)"
      ARR_TIMEZONE_DETECTED_VALUE="${TIMEZONE:-}"
      ARR_TIMEZONE_AUTO_SOURCE="detected"
    fi
  fi
fi

if [[ -z "${ARR_TIMEZONE_DETECTED_VALUE:-}" && "${ARR_TIMEZONE_AUTO_SOURCE:-}" == "detected" ]]; then
  ARR_TIMEZONE_DETECTED_VALUE="${TIMEZONE:-}"
fi
export ARR_TIMEZONE_DETECTED_VALUE

unset _arr_env_override_order _arr_env_overrides

unset _canon_userconf _canon_base _expected_base
unset _arr_timezone_before _arr_userconf_timezone_override

if [[ "${ARR_HARDEN_READONLY:-0}" == "1" ]]; then
  readonly REPO_ROOT ARR_USERCONF_PATH
fi

SCRIPT_LIB_DIR="${REPO_ROOT}/scripts"
if [[ "${ARR_HARDEN_READONLY:-0}" == "1" ]]; then
  readonly SCRIPT_LIB_DIR
fi
modules=(
  "common.sh"
  "defaults.sh"
  "network.sh"
  "config.sh"
  "permissions.sh"
  "preflight.sh"
  "preserve.sh"
  "files.sh"
  "migrations.sh"
  "vpn-auto-reconnect.sh"
  "services.sh"
  "apikeys.sh"
  "aliases.sh"
  "dns.sh"
  "summary.sh"
  "shell.sh"
)
for module in "${modules[@]}"; do
  f="${SCRIPT_LIB_DIR}/${module}"
  if [[ ! -f "${f}" ]]; then
    if [[ "${ARR_ALLOW_MISSING_MODULES:-0}" == "1" ]]; then
      printf '[arrstack] WARN: missing module (continuing due to ARR_ALLOW_MISSING_MODULES=1): %s\n' "${f}" >&2
      continue
    fi
    printf '[arrstack] missing required module: %s\n' "${f}" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "${f}"
done

arr_setup_defaults

# Prints CLI contract; keep aligned with docs/operations.md flag list
help() {
  cat <<'USAGE'
Usage: ./arrstack.sh [options]

Options:
  --yes                 Run non-interactively and assume yes to prompts
  --enable-caddy        Enable the optional Caddy reverse proxy (sets ENABLE_CADDY=1)
  --enable-sab          Enable SABnzbd for this run (sets SABNZBD_ENABLED=1)
  --rotate-api-key      Force regeneration of the Gluetun API key
  --rotate-caddy-auth   Force regeneration of the Caddy basic auth credentials
  --sync-api-keys       Force Sonarr/Radarr/Prowlarr API key sync into Configarr secrets
  --no-auto-api-sync    Disable automatic Configarr API key sync for this run
  --setup-host-dns      Run the host DNS takeover helper during installation
  --refresh-aliases     Regenerate helper aliases and reload your shell
  --help                Show this help message
USAGE
}

GLUETUN_LIB="${REPO_ROOT}/scripts/gluetun.sh"
if [[ -f "${GLUETUN_LIB}" ]]; then
  # shellcheck source=scripts/gluetun.sh disable=SC1091,SC1094
  . "${GLUETUN_LIB}"
else
  warn "Gluetun helper library not found at ${GLUETUN_LIB}"
fi

# Drives the orchestrated install/update flow while honoring run flags and sidecars
main() {
  local IFS=$'\n\t'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        # shellcheck disable=SC2034 # used by scripts/preflight.sh
        ASSUME_YES=1
        shift
        ;;
      --enable-caddy)
        ENABLE_CADDY=1
        shift
        ;;
      --enable-sab)
        SABNZBD_ENABLED=1
        shift
        ;;
      --rotate-api-key)
        # shellcheck disable=SC2034 # consumed in scripts/files.sh
        FORCE_ROTATE_API_KEY=1
        shift
        ;;
      --rotate-caddy-auth)
        # shellcheck disable=SC2034 # consumed in scripts/files.sh
        FORCE_REGEN_CADDY_AUTH=1
        shift
        ;;
      --sync-api-keys)
        FORCE_SYNC_API_KEYS=1
        shift
        ;;
      --no-auto-api-sync)
        DISABLE_AUTO_API_KEY_SYNC=1
        shift
        ;;
      --setup-host-dns)
        SETUP_HOST_DNS=1
        shift
        ;;
      --refresh-aliases)
        REFRESH_ALIASES=1
        shift
        ;;
      --help | -h)
        help
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done

  if [[ "${REFRESH_ALIASES:-0}" == "1" ]]; then
    refresh_aliases
    return 0
  fi

  init_logging

  # Pre-hydrate preserved configuration so preflight checks reflect the
  # ports and credentials we intend to reuse during this run.
  hydrate_qbt_host_port_from_env_file
  hydrate_qbt_webui_port_from_config
  hydrate_sab_api_key_from_config

  preflight
  check_network_requirements
  mkdirs
  run_one_time_migrations
  safe_cleanup
  generate_api_key
  write_env
  write_compose
  preflight_compose_interpolation
  validate_compose_or_die
  write_gluetun_control_assets
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    ensure_caddy_auth
    write_caddy_assets
    validate_caddy_config
  else
    msg "Skipping Caddy assets (ENABLE_CADDY=0)"
  fi
  sync_gluetun_library
  sync_vpn_auto_reconnect_assets
  write_qbt_helper_script
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    write_sab_helper_script
  fi
  write_qbt_config
  if ! write_aliases_file; then
    warn "Helper aliases file could not be generated"
  fi
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    configure_local_dns_entries
  fi
  if [[ "${SETUP_HOST_DNS:-0}" == "1" ]]; then
    run_host_dns_setup
  fi
  write_configarr_assets
  verify_permissions
  install_aliases
  start_stack

  # shellcheck disable=SC2034 # consumed by scripts/summary.sh
  API_KEYS_SYNCED_DETAILS=""
  API_KEYS_SYNCED_PLACEHOLDERS=0

  # shellcheck disable=SC2034 # values consumed by scripts/summary.sh
  if [[ "${FORCE_SYNC_API_KEYS:-0}" == "1" ]]; then
    arr_sync_arr_api_keys 1 || true
  elif [[ "${DISABLE_AUTO_API_KEY_SYNC:-0}" == "1" ]]; then
    API_KEYS_SYNCED_STATUS="disabled"
    API_KEYS_SYNCED_MESSAGE="Configarr API key sync skipped (--no-auto-api-sync)."
    if [[ -f "${ARR_DOCKER_DIR}/configarr/secrets.yml" ]] && grep -Fq 'REPLACE_WITH_' "${ARR_DOCKER_DIR}/configarr/secrets.yml" 2>/dev/null; then
      API_KEYS_SYNCED_PLACEHOLDERS=1
    fi
  elif [[ -n "${ARR_SCHEDULED_API_SYNC_DELAY:-}" ]]; then
    API_KEYS_SYNCED_STATUS="scheduled"
    API_KEYS_SYNCED_MESSAGE="Configarr API key sync scheduled to run in ${ARR_SCHEDULED_API_SYNC_DELAY} seconds."
  else
    arr_sync_arr_api_keys 0 || true
  fi

  export ARR_SAB_API_KEY_STATE="${ARR_SAB_API_KEY_STATE:-empty}"
  export ARR_SAB_API_KEY_SOURCE="${ARR_SAB_API_KEY_SOURCE:-}"

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" && "${ENABLE_CADDY:-0}" == "1" ]]; then
    local doctor_script="${REPO_ROOT}/scripts/doctor.sh"
    if [[ -x "${doctor_script}" ]]; then
      msg "🩺 Running LAN diagnostics"
      export ARR_INTERNAL_PORT_CONFLICTS="${ARR_INTERNAL_PORT_CONFLICTS:-0}"
      export ARR_INTERNAL_PORT_CONFLICT_DETAIL="${ARR_INTERNAL_PORT_CONFLICT_DETAIL:-}"
      if ! LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" \
        LAN_IP="${LAN_IP}" \
        ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS}" \
        LOCAL_DNS_STATE="${LOCAL_DNS_STATE}" \
        LOCAL_DNS_STATE_REASON="${LOCAL_DNS_STATE_REASON}" \
        LOCALHOST_IP="${LOCALHOST_IP}" \
        DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE}" \
        GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT}" \
        EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS}" \
        bash "${doctor_script}"; then
        warn "LAN diagnostics reported issues"
      fi
    else
      warn "Doctor script missing or not executable at ${doctor_script}"
    fi
  elif [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    msg "🩺 Skipping LAN diagnostics (ENABLE_CADDY=0)"
  fi

  msg "Installation completed at $(date)"
  show_summary
}

if [[ "${ARR_NO_MAIN:-0}" != "1" ]]; then
  main "$@"
fi

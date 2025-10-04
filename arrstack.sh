#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables
set -Eeuo pipefail

# Secure default file creation; allow opt-out for legacy setups
if [[ "${ARRSTACK_DISABLE_UMASK:-0}" != "1" ]]; then
  umask 027
fi

# Reports failing location before exiting to speed triage of installer faults
arrstack_err_trap() {
  local rc=$?
  trap - ERR
  local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  local line="${BASH_LINENO[0]:-${LINENO}}"
  printf '[arrstack] error at %s:%s (status=%s)\n' "${src}" "${line}" "${rc}" >&2
  exit "${rc}"
}

# Install trap early so sourcing failures have context
trap 'arrstack_err_trap' ERR

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

declare -a _arrstack_env_override_order=()
declare -A _arrstack_env_overrides=()
declare -A _arrstack_env_override_seen=()
if declare -f arrstack_collect_all_expected_env_keys >/dev/null 2>&1; then
  while IFS= read -r _arrstack_env_var; do
    [[ -n "${_arrstack_env_var}" ]] || continue
    if [[ -z "${_arrstack_env_override_seen[${_arrstack_env_var}]+x}" ]]; then
      _arrstack_env_override_order+=("${_arrstack_env_var}")
      _arrstack_env_override_seen["${_arrstack_env_var}"]=1
    fi
  done < <(arrstack_collect_all_expected_env_keys)
else
  while read -r _arrstack_env_line; do
    _arrstack_env_var="${_arrstack_env_line%%=*}"
    if [[ "${_arrstack_env_var}" == ARR_* || "${_arrstack_env_var}" == ARRSTACK_* ]]; then
      if [[ -z "${_arrstack_env_override_seen[${_arrstack_env_var}]+x}" ]]; then
        _arrstack_env_override_order+=("${_arrstack_env_var}")
        _arrstack_env_override_seen["${_arrstack_env_var}"]=1
      fi
    fi
  done < <(env)
fi
unset _arrstack_env_override_seen _arrstack_env_rest

for _arrstack_env_var in "${_arrstack_env_override_order[@]}"; do
  if [[ "$(declare -p -- "$_arrstack_env_var" 2>/dev/null)" == "declare -x "* ]]; then
    if [[ ${!_arrstack_env_var+x} ]]; then
      _arrstack_env_overrides["${_arrstack_env_var}"]="${!_arrstack_env_var}"
    else
      _arrstack_env_overrides["${_arrstack_env_var}"]=""
    fi
  fi
done
unset _arrstack_env_var

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

if [[ -f "${_canon_userconf}" ]]; then
  # shellcheck source=/dev/null
  . "${_canon_userconf}"
fi

for _arrstack_env_var in "${_arrstack_env_override_order[@]}"; do
  if [[ -v "_arrstack_env_overrides[${_arrstack_env_var}]" ]]; then
    if arrstack_var_is_readonly "${_arrstack_env_var}"; then
      continue
    fi
    # Variable name validation is redundant; Bash enforces valid names
    printf -v "${_arrstack_env_var}" '%s' "${_arrstack_env_overrides[${_arrstack_env_var}]}"
    export "${_arrstack_env_var}"
  fi
done
unset _arrstack_env_var

unset _arrstack_env_override_order _arrstack_env_overrides

ARR_USERCONF_PATH="${_canon_userconf}"
unset _canon_userconf _canon_base _expected_base

if [[ "${ARRSTACK_HARDEN_READONLY:-0}" == "1" ]]; then
  readonly REPO_ROOT ARR_USERCONF_PATH
fi

SCRIPT_LIB_DIR="${REPO_ROOT}/scripts"
if [[ "${ARRSTACK_HARDEN_READONLY:-0}" == "1" ]]; then
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
    if [[ "${ARRSTACK_ALLOW_MISSING_MODULES:-0}" == "1" ]]; then
      printf '[arrstack] WARN: missing module (continuing due to ARRSTACK_ALLOW_MISSING_MODULES=1): %s\n' "${f}" >&2
      continue
    fi
    printf '[arrstack] missing required module: %s\n' "${f}" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "${f}"
done

arrstack_setup_defaults

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
    arrstack_sync_arr_api_keys 1 || true
  elif [[ "${DISABLE_AUTO_API_KEY_SYNC:-0}" == "1" ]]; then
    API_KEYS_SYNCED_STATUS="disabled"
    API_KEYS_SYNCED_MESSAGE="Configarr API key sync skipped (--no-auto-api-sync)."
    if [[ -f "${ARR_DOCKER_DIR}/configarr/secrets.yml" ]] && grep -Fq 'REPLACE_WITH_' "${ARR_DOCKER_DIR}/configarr/secrets.yml" 2>/dev/null; then
      API_KEYS_SYNCED_PLACEHOLDERS=1
    fi
  elif [[ -n "${ARRSTACK_SCHEDULED_API_SYNC_DELAY:-}" ]]; then
    API_KEYS_SYNCED_STATUS="scheduled"
    API_KEYS_SYNCED_MESSAGE="Configarr API key sync scheduled to run in ${ARRSTACK_SCHEDULED_API_SYNC_DELAY} seconds."
  else
    arrstack_sync_arr_api_keys 0 || true
  fi

  export ARRSTACK_SAB_API_KEY_STATE="${ARRSTACK_SAB_API_KEY_STATE:-empty}"
  export ARRSTACK_SAB_API_KEY_SOURCE="${ARRSTACK_SAB_API_KEY_SOURCE:-}"

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" && "${ENABLE_CADDY:-0}" == "1" ]]; then
    local doctor_script="${REPO_ROOT}/scripts/doctor.sh"
    if [[ -x "${doctor_script}" ]]; then
      msg "🩺 Running LAN diagnostics"
      export ARRSTACK_INTERNAL_PORT_CONFLICTS="${ARRSTACK_INTERNAL_PORT_CONFLICTS:-0}"
      export ARRSTACK_INTERNAL_PORT_CONFLICT_DETAIL="${ARRSTACK_INTERNAL_PORT_CONFLICT_DETAIL:-}"
      if ! LAN_DOMAIN_SUFFIX="${LAN_DOMAIN_SUFFIX}" \
        LAN_IP="${LAN_IP}" \
        ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS}" \
        LOCAL_DNS_SERVICE_ENABLED="${LOCAL_DNS_SERVICE_ENABLED}" \
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

if [[ "${ARRSTACK_NO_MAIN:-0}" != "1" ]]; then
  main "$@"
fi

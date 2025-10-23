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
  local label="[${STACK:-arr}]"
  printf '%s error at %s:%s (status=%s)\n' "${label}" "${src}" "${line}" "${rc}" >&2
  if [[ -n "${ARR_TRACE_FILE:-}" ]]; then
    printf 'Trace log: %s\n' "${ARR_TRACE_FILE}" >&2
  fi
  exit "${rc}"
}

# Install trap early so sourcing failures have context
trap 'arr_err_trap' ERR

arr_main_cleanup_dispatch() {
  local rc="${1:-$?}"

  if declare -f arr_restore_stack_runtime_state >/dev/null 2>&1; then
    arr_restore_stack_runtime_state "${rc}"
  fi

  if declare -f arr_global_cleanup >/dev/null 2>&1; then
    arr_global_cleanup
  fi
}

arr_main_exit_trap() {
  local rc=$?
  trap - EXIT

  if [[ "${ARR_MAIN_INTERRUPTED:-0}" == "1" ]]; then
    exit "${rc}"
  fi

  arr_main_cleanup_dispatch "${rc}"
  exit "${rc}"
}

arr_main_signal_trap() {
  local signal="$1"
  local code="$2"

  trap - "${signal}"
  ARR_MAIN_INTERRUPTED=1
  arr_main_cleanup_dispatch "${code}"
  exit "${code}"
}

trap 'arr_main_signal_trap INT 130' INT
trap 'arr_main_signal_trap TERM 143' TERM
trap 'arr_main_signal_trap HUP 129' HUP
trap 'arr_main_signal_trap QUIT 131' QUIT
trap 'arr_main_exit_trap' EXIT

ARR_MAIN_TRAP_INSTALLED=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

declare -a _arr_canonical_config_vars=()
declare -a _arr_env_override_order=()
declare -A _arr_env_overrides=()

_arr_defaults_file="${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
if [[ -f "${_arr_defaults_file}" ]]; then
  if mapfile -t _arr_canonical_config_vars < <(
    REPO_ROOT="${REPO_ROOT}" "${BASH:-bash}" -Eeuo pipefail - <<'EOS'
set -Eeuo pipefail
if [[ -f "${REPO_ROOT}/arrconf/userr.conf.defaults.sh" ]]; then
  # shellcheck source=arrconf/userr.conf.defaults.sh disable=SC1091
  . "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
  if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
    arr_collect_all_expected_env_keys
  fi
fi
EOS
  ); then
    :
  else
    _arr_canonical_config_vars=()
  fi
fi

# -- Canonical env normalisation: snapshot, unset (non-exported only), and (if needed) re-exec with a sanitised env --
if ((${#_arr_canonical_config_vars[@]})); then
  declare -A _arr_env_override_seen=()
  declare -A _arr_env_exported=()
  _arr_need_reexec=0
  _arr_reexec_env_unset=()

  # 1) Snapshot values + export flags. Do NOT unset exported vars yet (avoid transient inconsistencies).
  #    Safely unset only non-exported vars now; handle readonly via re-exec.
  for _arr_env_var in "${_arr_canonical_config_vars[@]}"; do
    [[ -n "${_arr_env_var}" ]] || continue
    [[ -z "${_arr_env_override_seen[${_arr_env_var}]:-}" ]] || continue
    _arr_env_override_seen["${_arr_env_var}"]=1

    if [[ -v "${_arr_env_var}" ]]; then
      _arr_env_overrides["${_arr_env_var}"]="${!_arr_env_var}"
      # Record if originally exported
      if [[ "$(declare -p -- "${_arr_env_var}" 2>/dev/null)" == "declare -x "* ]]; then
        _arr_env_exported["${_arr_env_var}"]=1
        # If we must re-exec, drop this name from the child env
        _arr_reexec_env_unset+=("${_arr_env_var}")
      fi
      _arr_env_override_order+=("${_arr_env_var}")
    fi

    # Detect readonly; if readonly, schedule re-exec (cannot unset/overwrite in this shell).
    if _arr_decl="$(declare -p -- "${_arr_env_var}" 2>/dev/null)"; then
      if [[ "$_arr_decl" == *" -r"* || "$_arr_decl" == declare\ -r* || "$_arr_decl" == declare\ -xr* || "$_arr_decl" == *" -xr"* ]]; then
        _arr_need_reexec=1
        continue
      fi
    fi

    # Only unset non-exported variables now to avoid transient loss from the process environment.
    if [[ -z "${_arr_env_exported[${_arr_env_var}]:-}" ]]; then
      set +e; unset -v "${_arr_env_var}"; set -e
    fi
  done
  unset _arr_env_override_seen _arr_env_var _arr_decl

  # 2) If any were readonly, re-exec in a sanitised environment with those names removed.
  if (( _arr_need_reexec )) && [[ -z "${ARR_REEXEC_SANITIZED_ENV:-}" ]]; then
    _arr_env_cmd=(env -i)
    # Preserve minimal runtime env
    for _k in PATH HOME USER SHELL LANG LC_ALL TERM; do
      [[ -v $_k ]] && _arr_env_cmd+=("$_k=${!_k}")
    done
    # Remove exported readonly names from the child environment
    for _name in "${_arr_reexec_env_unset[@]}"; do
      _arr_env_cmd+=("-u" "${_name}")
    done
    # Preseed exported overrides so precedence can re-apply correctly after re-exec
    _arr_preseed_payload=""
    for _name in "${_arr_env_override_order[@]}"; do
      if [[ -n "${_arr_env_exported[${_name}]:-}" ]]; then
        _arr_preseed_payload+=$(printf '%s=%q\n' "${_name}" "${_arr_env_overrides[$_name]}")
        _arr_preseed_payload+=$'\n'
      fi
    done
    _arr_env_cmd+=("ARR_REEXEC_SANITIZED_ENV=1")
    [[ -n "$_arr_preseed_payload" ]] && _arr_env_cmd+=("ARR_PRESEED_EXPORTS=${_arr_preseed_payload}")
    exec "${_arr_env_cmd[@]}" bash "$0" "$@"
  fi

  # 3) If re-exec’d, re-hydrate exported env (if any) before normal precedence evaluation.
  if [[ -n "${ARR_REEXEC_SANITIZED_ENV:-}" && -n "${ARR_PRESEED_EXPORTS:-}" ]]; then
    # shellcheck disable=SC2016
    while IFS= read -r _line; do
      [[ -z "$_line" ]] && continue
      eval "export ${_line}"
    done <<<"${ARR_PRESEED_EXPORTS}"
    unset ARR_PRESEED_EXPORTS
  fi
fi

USERCONF_LIB="${REPO_ROOT}/scripts/userconf.sh"
LOG_LIB="${REPO_ROOT}/scripts/logging.sh"
if [[ -f "${USERCONF_LIB}" ]]; then
  # shellcheck source=scripts/userconf.sh
  . "${USERCONF_LIB}"
else
  printf '[arr] missing required module: %s\n' "${USERCONF_LIB}" >&2
  exit 1
fi

if [[ -f "${LOG_LIB}" ]]; then
  # shellcheck source=scripts/logging.sh disable=SC1091
  . "${LOG_LIB}"
fi

COMMON_LIB="${REPO_ROOT}/scripts/common.sh"
if [[ -f "${COMMON_LIB}" ]]; then
  # shellcheck source=scripts/common.sh
  . "${COMMON_LIB}"
else
  printf '[arr] missing required module: %s\n' "${COMMON_LIB}" >&2
  exit 1
fi

arr_apply_env_overrides() {
  local _arr_env_var=""
  local _arr_warn_tag="${STACK_TAG:-[arr]}"
  local _arr_declaration=""

  for _arr_env_var in "${_arr_env_override_order[@]:-}"; do
    if [[ -z "${_arr_env_var}" ]]; then
      continue
    fi
    if [[ ! "${_arr_env_var}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
      printf '%s WARN: Skipping invalid environment variable name: %s\n' "${_arr_warn_tag}" "${_arr_env_var}" >&2
      continue
    fi
    if [[ -v "_arr_env_overrides[${_arr_env_var}]" ]]; then
      if declare -f arr_var_is_readonly >/dev/null 2>&1; then
        if arr_var_is_readonly "${_arr_env_var}"; then
          continue
        fi
      else
        if _arr_declaration="$(declare -p -- "${_arr_env_var}" 2>/dev/null)"; then
          _arr_declaration="${_arr_declaration#declare }"
          _arr_declaration="${_arr_declaration%% *}"
          if [[ "${_arr_declaration}" == -*r* ]]; then
            continue
          fi
        fi
      fi
      printf -v "${_arr_env_var}" '%s' "${_arr_env_overrides[${_arr_env_var}]}"
      export "${_arr_env_var?}"
    fi
  done
}

if [[ -f "${_arr_defaults_file}" ]]; then
  # shellcheck source=arrconf/userr.conf.defaults.sh disable=SC1091
  . "${_arr_defaults_file}"
fi

if ((${#_arr_env_overrides[@]})); then
  arr_apply_env_overrides

  if [[ -f "${_arr_defaults_file}" ]]; then
    for _arr_env_var in "${_arr_canonical_config_vars[@]:-}"; do
      [[ -n "${_arr_env_var}" ]] || continue
      if [[ -v "_arr_env_overrides[${_arr_env_var}]" ]]; then
        continue
      fi
      unset -v "${_arr_env_var}" 2>/dev/null || :
    done
    unset _arr_env_var
    # shellcheck source=arrconf/userr.conf.defaults.sh disable=SC1091
    . "${_arr_defaults_file}"
  fi
fi

unset _arr_canonical_config_vars
unset _arr_defaults_file

STACK="${STACK:-arr}"
STACK_UPPER="${STACK_UPPER:-${STACK^^}}"
STACK_TAG="[${STACK}]"

# Resolve and optionally constrain user config
arr_resolve_userconf_paths ARR_USERCONF_PATH ARR_USERCONF_OVERRIDE_PATH

_expected_base="$(arr_expand_path_tokens "${ARR_DATA_ROOT}")"
_canon_base="$(arr_canonical_path "${_expected_base}")"
_canon_userconf="${ARR_USERCONF_PATH}"

declare -a ARR_RUNTIME_ENV_GUARDS=()

if [[ "${ARR_USERCONF_ALLOW_OUTSIDE:-0}" != "1" ]]; then
  if [[ -z "${ARR_USERCONF_OVERRIDE_PATH:-}" && -n "${_canon_base}" ]]; then
    if ! [[ "${_canon_userconf}" == "${_canon_base}" || "${_canon_userconf}" == "${_canon_base}/"* ]]; then
      if [[ "${ARR_USERCONF_STRICT:-0}" == "1" ]]; then
        printf '%s user config path outside base (%s): %s (strict mode)\n' "${STACK_TAG}" "${_canon_base}" "${_canon_userconf}" >&2
        exit 1
      else
        printf '%s WARN: user config outside expected base (%s): %s\n' "${STACK_TAG}" "${_canon_base}" "${_canon_userconf}" >&2
      fi
    fi
  fi
fi

if [[ -f "${_canon_userconf}" ]]; then
  if ! _arr_userr_conf_errlog="$(mktemp 2>/dev/null)"; then
    die "Failed to allocate temp file for user config diagnostics"
  fi
  arr_register_temp_path "${_arr_userr_conf_errlog}"
  # Save current ERR trap (if any), then disable while sourcing user config
  _prev_err_trap="$(trap -p ERR 2>/dev/null || true)"
  trap - ERR
  set +e
  # shellcheck source=/dev/null
  . "${_canon_userconf}" 2>"${_arr_userr_conf_errlog}"
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
      printf '%s Failed to source user config (status=%s): %s\n' "${STACK_TAG}" "${_arr_userr_conf_status}" "${_canon_userconf}" >&2
      # Replay captured stderr to aid debugging
      cat "${_arr_userr_conf_errlog}" >&2 || :
      arr_cleanup_temp_path "${_arr_userr_conf_errlog}"
      exit "${_arr_userr_conf_status}"
    fi
  fi
  arr_cleanup_temp_path "${_arr_userr_conf_errlog}"
  unset _arr_userr_conf_status _arr_userr_conf_errlog
fi
arr_apply_env_overrides

for _arr_env_var in "${_arr_env_override_order[@]}"; do
  if [[ -v "_arr_env_overrides[${_arr_env_var}]" ]]; then
    ARR_RUNTIME_ENV_GUARDS+=("${_arr_env_var}")
  fi
done
unset _arr_env_var

unset _arr_env_override_order _arr_env_overrides

ARR_USERCONF_PATH="${_canon_userconf}"
unset _canon_userconf _canon_base _expected_base

arr_lock_effective_vars() {
  local var
  declare -A _arr_guard_seen=()

  for var in "${ARR_RUNTIME_ENV_GUARDS[@]:-}"; do
    [[ -n "${var}" ]] || continue
    if [[ -n "${_arr_guard_seen[${var}]+x}" ]]; then
      continue
    fi
    _arr_guard_seen["${var}"]=1
    if [[ ! "${var}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
      printf '%s WARN: Skipping readonly guard for invalid environment variable name: %s (must start with letter or underscore and contain only alphanumeric characters and underscores)\n' "${STACK_TAG}" "${var}" >&2
      continue
    fi
    if arr_var_is_readonly "${var}"; then
      continue
    fi
    readonly "${var}" 2>/dev/null || :
  done

  unset _arr_guard_seen
}

if [[ "${ARR_HARDEN_READONLY:-0}" == "1" ]]; then
  readonly REPO_ROOT ARR_USERCONF_PATH
fi

SCRIPT_LIB_DIR="${REPO_ROOT}/scripts"
if [[ "${ARR_HARDEN_READONLY:-0}" == "1" ]]; then
  readonly SCRIPT_LIB_DIR
fi

YAML_EMIT_LIB="${REPO_ROOT}/scripts/yaml-emit.sh"
if [[ -f "${YAML_EMIT_LIB}" ]]; then
  # shellcheck source=scripts/yaml-emit.sh
  . "${YAML_EMIT_LIB}"
else
  printf '%s missing emission helper library: %s\n' "${STACK_TAG}" "${YAML_EMIT_LIB}" >&2
  exit 1
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
    printf '%s missing required module: %s\n' "${STACK_TAG}" "${f}" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  . "${f}"
done

arr_setup_defaults

# Prints CLI contract; keep aligned with docs/operations.md flag list
help() {
  cat <<'USAGE'
Usage: ./arr.sh [options]

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
  --force-unlock        Remove an existing installer lock before continuing
  --uninstall           Remove the ARR stack and revert host changes
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
  # Keep custom IFS local and restore it before calling deeper helpers
  local OLDIFS="${IFS}"
  local IFS=$'\n\t'
  local RUN_UNINSTALL=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --trace)
        ARR_TRACE=1
        shift
        ;;
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
      --force-unlock)
        ARR_FORCE_UNLOCK=1
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
      --uninstall)
        RUN_UNINSTALL=1
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

  # Restore default word splitting so callees are not impacted
  IFS="${OLDIFS}"

  arr_lock_effective_vars

  if [[ "${RUN_UNINSTALL}" == "1" ]]; then
    local -a uninstall_args=()
    if [[ "${ASSUME_YES:-0}" == "1" ]]; then
      uninstall_args+=("--yes")
    fi
    exec "${REPO_ROOT}/scripts/uninstall.sh" "${uninstall_args[@]}"
  fi

  if [[ "${ARR_TRACE:-0}" == "1" ]] && declare -f arr_trace_start >/dev/null 2>&1; then
    arr_trace_start
  fi

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
  arr_capture_stack_runtime_state || true
  check_network_requirements
  mkdirs
  run_one_time_migrations
  safe_cleanup
  generate_api_key
  prepare_env_context
  local env_target="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
  local template_path="${REPO_ROOT}/.env.template"
  local user_conf_path="${ARR_USERCONF_PATH:-${ARRCONF_DIR}/userr.conf}"
  if ! "${REPO_ROOT}/scripts/gen-env.sh" "${template_path}" "${env_target}" "${user_conf_path}"; then
    die "Failed to generate ${env_target}"
  fi
  write_compose
  validate_generated_paths
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

  msg "Installation completed at $(arr_date_local '+%Y-%m-%d %H:%M:%S %Z')"
  show_summary
}

if [[ "${ARR_NO_MAIN:-0}" != "1" ]]; then
  main "$@"
fi

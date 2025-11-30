#!/usr/bin/env bash
# shellcheck shell=bash
# Lightweight Gluetun helper library used by stack scripts.
# Provides helpers for control API access plus Proton/OpenVPN and WireGuard checks.
# shellcheck disable=SC2250

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

if [[ -f "${REPO_ROOT}/scripts/gluetun-api.sh" ]]; then
  # shellcheck source=scripts/gluetun-api.sh
  . "${REPO_ROOT}/scripts/gluetun-api.sh"
fi

: "${GLUETUN_CONTROL_URL:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"
: "${GLUETUN_CONTROL_TIMEOUT:=8}"

# --- Gluetun image helpers ---------------------------------------------------

gluetun_version_requires_auth_config() {
  local image="${GLUETUN_IMAGE:-}"

  if [[ -z "${image}" ]]; then
    return 1
  fi

  local tag="${image##*:}"
  local normalized
  normalized="${tag#v}"
  normalized="${normalized%%[^0-9.]*}"

  local major="" minor=""
  if [[ -n "${normalized}" ]]; then
    IFS='.' read -r major minor _ <<<"${normalized}"
  fi

  if [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]]; then
    if ((major > 3 || (major == 3 && minor >= 40))); then
      return 0
    fi
    return 1
  fi

  if [[ "${tag}" == "latest" || "${tag}" == "edge" || "${tag}" == "testing" || "${image}" == "qmcgaw/gluetun" ]]; then
    return 0
  fi

  return 0
}

# --- Filesystem helpers ------------------------------------------------------

gluetun_data_root() {
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    arr_gluetun_dir
    return
  fi

  local docker_root="${ARR_DOCKER_DIR:-}"
  if [[ -z "$docker_root" ]] && declare -f arr_docker_data_root >/dev/null 2>&1; then
    docker_root="$(arr_docker_data_root 2>/dev/null || printf '')"
  fi

  if [[ -z "$docker_root" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      docker_root="${ARR_STACK_DIR%/}/dockarr"
    elif [[ -n "${ARR_DATA_ROOT:-}" ]]; then
      docker_root="${ARR_DATA_ROOT%/}/${STACK:-arr}/dockarr"
    elif [[ -n "${HOME:-}" ]]; then
      docker_root="${HOME%/}/srv/${STACK:-arr}/dockarr"
    else
      docker_root="/srv/${STACK:-arr}/dockarr"
    fi
  fi

  printf '%s/gluetun' "${docker_root%/}"
}

gluetun_wireguard_config_path() {
  printf '%s/wireguard/wg0.conf' "$(gluetun_data_root)"
}

gluetun_wireguard_natpmp_enabled() {
  local config_path="${1:-}"
  if [[ -z "$config_path" ]]; then
    config_path="$(gluetun_wireguard_config_path)"
  fi

  if [[ -z "$config_path" || ! -f "$config_path" ]]; then
    return 2
  fi

  if LC_ALL=C grep -qi 'nat[-_]*pmp' "$config_path" 2>/dev/null; then
    return 0
  fi
  return 1
}

# shellcheck disable=SC2120
gluetun_require_wireguard_natpmp() {
  local config_path="${1:-}"
  if [[ -z "$config_path" ]]; then
    config_path="$(gluetun_wireguard_config_path)"
  fi

  if ! gluetun_wireguard_natpmp_enabled "$config_path"; then
    warn "WireGuard config at ${config_path} does not include NAT-PMP; Proton port forwarding will fail"
    warn "Download a new Proton WireGuard config with NAT-PMP enabled before continuing"
    return 1
  fi

  return 0
}

# --- Control API wrappers ----------------------------------------------------
# Note: These functions delegate to gluetun-api.sh for consolidated API access

gluetun_control_status() {
  gluetun_api_status "$@"
}

gluetun_control_forwarded_port() {
  gluetun_api_forwarded_port "$@"
}

gluetun_wait_for_forwarding() {
  local timeout="${1:-120}"
  gluetun_wait_until_ready "$timeout"
}

# Convenience helper for scripts needing the shared controller status file
# path within the host filesystem.
gluetun_port_guard_status_file() {
  if declare -f arr_port_guard_status_path >/dev/null 2>&1; then
    arr_port_guard_status_path
    return
  fi

  local root
  if declare -f arr_gluetun_state_dir >/dev/null 2>&1; then
    root="$(arr_gluetun_state_dir 2>/dev/null || printf '')"
    if [[ -n "$root" ]]; then
      printf '%s/port-guard-status.json' "${root%/}"
      return
    fi
  fi

  root="$(gluetun_data_root)"
  printf '%s/state/port-guard-status.json' "${root%/}"
}

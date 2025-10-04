#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/common.sh
source "${REPO_ROOT}/scripts/common.sh"
# shellcheck source=scripts/network.sh
source "${REPO_ROOT}/scripts/network.sh"
# shellcheck source=scripts/preflight.sh
source "${REPO_ROOT}/scripts/preflight.sh"
# shellcheck source=arrconf/userr.conf.defaults.sh
source "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"

run_case() {
  local name="$1"
  shift
  local -a overrides=("$@")
  local status=0

  (
    set -Eeuo pipefail
    ARRSTACK_WARNED_CADDY_LAN_UNKNOWN=0
    GLUETUN_CONTROL_PORT="8000"
    LOCALHOST_IP="127.0.0.1"
    EXPOSE_DIRECT_PORTS=0
    SPLIT_VPN=0
    ENABLE_CADDY=1
    SABNZBD_ENABLED=0
    SABNZBD_USE_VPN=0
    CADDY_HTTP_PORT="80"
    CADDY_HTTPS_PORT="443"
    ARR_USERCONF_PATH="${REPO_ROOT}/arrconf/userr.conf"

    for expr in "${overrides[@]}"; do
      eval "$expr"
    done

    local -a requirements=()
    collect_port_requirements requirements

    local expected_host="*"
    if [[ -n "${LAN_IP:-}" && "${LAN_IP}" != "0.0.0.0" ]]; then
      expected_host="${LAN_IP}"
    fi

    local http_found=0
    local https_found=0
    local entry
    for entry in "${requirements[@]}"; do
      case "$entry" in
        "tcp|${CADDY_HTTP_PORT}|Caddy HTTP|${expected_host}")
          http_found=1
          ;;
        "tcp|${CADDY_HTTPS_PORT}|Caddy HTTPS|${expected_host}")
          https_found=1
          ;;
      esac
    done

    if ((http_found == 0)); then
      echo "[${name}] expected Caddy HTTP requirement missing" >&2
      exit 1
    fi
    if ((https_found == 0)); then
      echo "[${name}] expected Caddy HTTPS requirement missing" >&2
      exit 1
    fi
  ) || status=$?

  if ((status == 0)); then
    printf '[%s] OK\n' "$name"
  else
    printf '[%s] FAIL\n' "$name" >&2
  fi
  return "$status"
}

main() {
  local -a cases=(
    "lan_unknown:LAN_IP=0.0.0.0 CADDY_HTTP_PORT=$((80 + 18000)) CADDY_HTTPS_PORT=$((443 + 18000))"
    "lan_known:LAN_IP=192.168.55.12 CADDY_HTTP_PORT=$((80 + 8008)) CADDY_HTTPS_PORT=$((443 + 8000))"
  )

  local rc=0
  local entry
  for entry in "${cases[@]}"; do
    local name="${entry%%:*}"
    local exprs_string="${entry#*:}"
    IFS=' ' read -r -a exprs <<<"${exprs_string}"
    if ! run_case "$name" "${exprs[@]}"; then
      rc=1
    fi
  done

  return "$rc"
}

main "$@"

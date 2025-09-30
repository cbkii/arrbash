#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARR_STACK_DIR="${ARR_STACK_DIR:-${REPO_ROOT}}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"
# shellcheck source=scripts/vpn-auto-reconnect.sh
. "${REPO_ROOT}/scripts/vpn-auto-reconnect.sh"

print_usage() {
  cat <<'USAGE'
Usage: vpn-auto-reconnect-daemon.sh [--once]
  --once    Run a single monitoring iteration and exit
USAGE
}

run_once() {
  if ! vpn_auto_reconnect_process_once; then
    log_warn "[vpn-auto] iteration reported errors"
    return 1
  fi
  return 0
}

main() {
  local once=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --once)
        once=1
        shift
        ;;
      --help|-h)
        print_usage
        return 0
        ;;
      *)
        print_usage >&2
        return 1
        ;;
    esac
  done

  if ((once)); then
    run_once
    return $?
  fi

  log_info "[vpn-auto] daemon starting"
  while true; do
    local interval
    vpn_auto_reconnect_load_env
    interval="$(vpn_auto_reconnect_check_interval_seconds 2>/dev/null || printf '1200')"
    if ! [[ "$interval" =~ ^[0-9]+$ ]]; then
      interval=1200
    fi
    if ((interval <= 0)); then
      interval=1200
    fi

    if ! run_once; then
      log_warn "[vpn-auto] iteration failed"
    fi

    sleep "$interval"
  done
}

main "$@"

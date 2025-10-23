#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARR_STACK_DIR="${ARR_STACK_DIR:-${REPO_ROOT}}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"
# shellcheck source=scripts/vpn-auto-stack.sh
. "${REPO_ROOT}/scripts/vpn-auto-stack.sh"

# Prints daemon usage/help text
print_usage() {
  cat <<'USAGE'
Usage: vpn-auto-reconnect-daemon.sh [--once]
  --once    Run a single monitoring iteration and exit
USAGE
}

# Executes a single reconnect evaluation cycle using configured interval
run_once() {
  local interval_once
  interval_once="$(vpn_auto_reconnect_check_interval_seconds 2>/dev/null || printf '1200')"
  if ! [[ "$interval_once" =~ ^[0-9]+$ ]]; then
    interval_once=1200
  fi
  VPN_AUTO_RECONNECT_CURRENT_INTERVAL="$interval_once"
  if ! vpn_auto_reconnect_process_once; then
    log_warn "[vpn-auto] iteration reported errors"
    return 1
  fi
  return 0
}

# Event loop handling CLI flags, wake triggers, and periodic execution
main() {
  local once=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --once)
        once=1
        shift
        ;;
      --help | -h)
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
    VPN_AUTO_RECONNECT_CURRENT_INTERVAL="$interval"

    if ! run_once; then
      log_warn "[vpn-auto] iteration failed"
    fi
    local wake_window=60
    if ((interval < wake_window)); then
      wake_window="$interval"
    fi
    local slept=0
    local wake_triggered=0
    local wake_step=5
    local wake_file
    wake_file="$(vpn_auto_reconnect_wake_file 2>/dev/null || printf '')"
    while ((slept < wake_window)); do
      if [[ -n "$wake_file" && -f "$wake_file" ]]; then
        vpn_auto_reconnect_consume_wake
        wake_triggered=1
        log_info "[vpn-auto] wake file detected; running early"
        break
      fi
      local chunk=$wake_step
      if ((wake_window - slept < wake_step)); then
        chunk=$((wake_window - slept))
      fi
      sleep "$chunk"
      slept=$((slept + chunk))
    done
    if ((wake_triggered)); then
      continue
    fi
    local remaining=$((interval - wake_window))
    if ((remaining > 0)); then
      sleep "$remaining"
    fi
  done
}

main "$@"

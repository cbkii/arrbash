#!/usr/bin/env bash
# Health check script for vpn-port-guard container
# Returns 0 if healthy, 1 if unhealthy

set -euo pipefail

# Source the status file location
: "${CONTROLLER_STATUS_FILE:=/gluetun_state/port-guard-status.json}"
: "${CONTROLLER_EVENTS_FILE:=/gluetun_state/port-guard-events.log}"

# Health check criteria:
# 1. Status file must exist and be readable
# 2. Status file must have been updated in the last 60 seconds
# 3. Status file must be valid JSON

if [[ ! -f "${CONTROLLER_STATUS_FILE}" ]]; then
  printf 'UNHEALTHY: Status file not found (%s)\n' "${CONTROLLER_STATUS_FILE}" >&2
  exit 1
fi

if [[ ! -r "${CONTROLLER_STATUS_FILE}" ]]; then
  printf 'UNHEALTHY: Status file not readable (%s)\n' "${CONTROLLER_STATUS_FILE}" >&2
  exit 1
fi

# Check if jq is available
if ! command -v jq >/dev/null 2>&1; then
  printf 'UNHEALTHY: jq not available for health check\n' >&2
  exit 1
fi

# Verify status file is valid JSON
if ! jq empty "${CONTROLLER_STATUS_FILE}" 2>/dev/null; then
  printf 'UNHEALTHY: Status file contains invalid JSON\n' >&2
  exit 1
fi

# Check last update time
last_update="$(jq -r '.last_update_epoch // 0' "${CONTROLLER_STATUS_FILE}" 2>/dev/null || printf '0')"
current_time="$(date +%s 2>/dev/null || printf '0')"

if [[ "${last_update}" =~ ^[0-9]+$ ]] && [[ "${current_time}" =~ ^[0-9]+$ ]]; then
  time_since_update=$((current_time - last_update))
  
  # Allow up to 60 seconds since last update (4x default poll interval)
  if ((time_since_update > 60)); then
    printf 'UNHEALTHY: Status file not updated in %d seconds\n' "$time_since_update" >&2
    exit 1
  fi
else
  # If we can't determine time, check if the process is at least running
  if ! pgrep -f "vpn-port-guard.sh" >/dev/null 2>&1; then
    printf 'UNHEALTHY: vpn-port-guard process not found\n' >&2
    exit 1
  fi
fi

# All checks passed
exit 0

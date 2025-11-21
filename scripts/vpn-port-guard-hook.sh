#!/usr/bin/env bash
# Gluetun port forwarding hook shim. Signals vpn-port-guard when Proton updates the port.
# This script MUST NOT talk to qBittorrent directly.

set -euo pipefail

event="${1:-unknown}"
trigger_path="${CONTROLLER_TRIGGER_FILE:-/gluetun_state/port-guard.trigger}"
events_log="${CONTROLLER_EVENTS_FILE:-/gluetun_state/port-guard-events.log}"

# Ensure directories exist
trigger_dir="$(dirname "${trigger_path}")"
events_dir="$(dirname "${events_log}")"

if [[ ! -d "${trigger_dir}" ]]; then
  mkdir -p "${trigger_dir}" >/dev/null 2>&1 || {
    printf 'Failed to create trigger directory: %s\n' "${trigger_dir}" >&2
    exit 1
  }
fi

if [[ ! -d "${events_dir}" ]]; then
  mkdir -p "${events_dir}" >/dev/null 2>&1 || true
fi

# Create trigger file atomically
if ! touch "${trigger_path}" 2>/dev/null; then
  printf 'Failed to create trigger file: %s\n' "${trigger_path}" >&2
  exit 1
fi

# Log the event (non-fatal)
{
  printf '[%s] vpn-port-guard hook signalled (event=%s)\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || TZ=UTC date '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'UNKNOWN')" \
    "$event"
} >>"${events_log}" 2>/dev/null || true

exit 0

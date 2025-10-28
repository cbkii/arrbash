#!/usr/bin/env bash
# Gluetun port forwarding hook shim. Signals vpn-port-guard when Proton updates the port.
# This script MUST NOT talk to qBittorrent directly.

set -euo pipefail

event="${1:-unknown}"
trigger_path="${CONTROLLER_TRIGGER_FILE:-/gluetun_state/port-guard.trigger}"
events_log="${CONTROLLER_EVENTS_FILE:-/gluetun_state/port-guard-events.log}"

mkdir -p "$(dirname "${trigger_path}")" >/dev/null 2>&1 || true

if touch "${trigger_path}" 2>/dev/null; then
  :
else
  exit 0
fi

{
  printf '[%s] vpn-port-guard hook signalled (%s)\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$event"
} >>"${events_log}" 2>/dev/null || true

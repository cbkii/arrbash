#!/usr/bin/env bash
# Gluetun port forwarding event logger (simplified)
#
# This hook is called by Gluetun when the forwarded port changes.
# It logs events for monitoring and troubleshooting only.
# The vpn-port-guard controller polls Gluetun's API independently.
#
# IMPORTANT: This script does NOT modify qBittorrent or other services.
# Port updates are handled by the vpn-port-guard controller via API polling.
#
# Gluetun calls this with: up, down, or an error message

set -euo pipefail

event="${1:-unknown}"
events_log="${CONTROLLER_EVENTS_FILE:-/gluetun_state/port-guard-events.log}"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "${events_log}")" >/dev/null 2>&1 || true

# Log the event with timestamp (ISO 8601 format)
{
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] Gluetun port forwarding: %s\n' "$timestamp" "$event"
} >>"${events_log}" 2>/dev/null || true

# Note: vpn-port-guard polls /v1/openvpn/portforwarded independently
# This hook provides audit trail only

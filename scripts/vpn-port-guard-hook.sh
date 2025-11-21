#!/usr/bin/env bash
# Gluetun port forwarding event logger
#
# This hook is called by Gluetun when the forwarded port changes.
# It only logs events for monitoring and troubleshooting.
# The vpn-port-guard controller polls independently and does not read these events.
#
# IMPORTANT: This script MUST NOT modify qBittorrent or other services directly.

set -euo pipefail

event="${1:-unknown}"
events_log="${CONTROLLER_EVENTS_FILE:-/gluetun_state/port-guard-events.log}"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "${events_log}")" >/dev/null 2>&1 || true

# Log the event with timestamp (portable format)
{
  # Use ISO 8601 format with fallback for systems without %z support
  timestamp="$(date '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] Gluetun port forwarding event: %s\n' "$timestamp" "$event"
} >>"${events_log}" 2>/dev/null || true

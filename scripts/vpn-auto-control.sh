#!/usr/bin/env bash
# Deprecated legacy helper. Outputs vpn-port-guard status JSON for compatibility.

set -euo pipefail

STATUS_FILE="${VPN_PORT_GUARD_STATUS_FILE:-/gluetun_state/port-guard-status.json}"

if [[ ! -f "${STATUS_FILE}" ]]; then
  echo "vpn-port-guard status file not found at ${STATUS_FILE}" >&2
  exit 1
fi

cat "${STATUS_FILE}"

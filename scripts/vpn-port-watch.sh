#!/usr/bin/env bash
# Deprecated legacy helper retained for compatibility. vpn-port-guard now owns qBittorrent control.

set -euo pipefail

echo "vpn-port-watch.sh is deprecated. vpn-port-guard manages port forwarding and qBittorrent control." >&2
if [[ -n "${ARR_DOCKER_DIR:-}" ]]; then
  host_hint="${ARR_DOCKER_DIR%/}/gluetun/state/port-guard-status.json"
else
  host_hint="\${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json"
fi
echo "See /gluetun_state/port-guard-status.json (host: ${host_hint}) for current status." >&2
exit 0

#!/usr/bin/env bash
# Deprecated legacy helper retained for compatibility. vpn-port-guard now owns qBittorrent control.

set -euo pipefail

echo "vpn-port-watch.sh is deprecated. vpn-port-guard manages port forwarding and qBittorrent control." >&2
echo "See /gluetun_state/port-guard-status.json for current status." >&2
exit 0

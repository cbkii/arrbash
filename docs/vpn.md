# VPN and Port Forwarding Quick Guide

[← Back to README](../README.md)

arrbash ships Gluetun as the VPN front-end for qBittorrent (and SABnzbd when enabled). The defaults favour reliability: Proton port forwarding is off, Gluetun binds its control API to `127.0.0.1` with an API key, and only the Gluetun service publishes ports to your LAN.

## Choose a layout
- **Full tunnel (default, `SPLIT_VPN=0`)** – All services share Gluetun’s namespace. Simple and private, but Arr apps are only reachable through published ports on the Gluetun service.
- **Split tunnel (`SPLIT_VPN=1`)** – Only qBittorrent (and SABnzbd when `SABNZBD_USE_VPN=1`) live inside Gluetun; Arr apps stay on the LAN bridge. Enable `EXPOSE_DIRECT_PORTS=1` so Sonarr/Radarr/Lidarr/Configarr publish LAN ports, then rerun `./arr.sh --yes` and point your Arr download clients at `http://LAN_IP:${QBT_PORT}`.

Switch modes by editing `${ARRCONF_DIR}/userr.conf` and rerunning `./arr.sh --yes`. The installer prints the URLs it publishes; confirm them before exposing ports.

## Proton port forwarding (optional)
1. Use ProtonVPN credentials that support NAT-PMP; keep the stored username **without** `+pmp` (arrbash appends it at runtime for OpenVPN).
2. Opt in via `${ARRCONF_DIR}/userr.conf` and rerun `./arr.sh`:
   ```bash
   VPN_PORT_FORWARDING=on
   VPN_PORT_FORWARDING_PROVIDER=protonvpn
   VPN_PORT_FORWARDING_STATUS_FILE=/tmp/gluetun/forwarded_port
   VPN_PORT_FORWARDING_UP_COMMAND=/scripts/vpn-port-guard-hook.sh up
   VPN_PORT_FORWARDING_DOWN_COMMAND=/scripts/vpn-port-guard-hook.sh down
   ```
3. Bind-mount `${ARR_DOCKER_DIR}/gluetun/state` into Gluetun so helpers can read the leased port and status JSON.

The control API stays on `127.0.0.1:${GLUETUN_CONTROL_PORT}` and enforces `GLUETUN_API_KEY`; avoid publishing it to the LAN.

## Port guard in one minute
`vpn-port-guard` is optional. When enabled, it:
- Polls Gluetun’s control API (or `/tmp/gluetun/forwarded_port` as a fallback) every `${CONTROLLER_POLL_INTERVAL:-10}` seconds.
- Applies the forwarded port to qBittorrent and verifies the change.
- Writes atomic status to `${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`.
- Respects `CONTROLLER_REQUIRE_PF=true` to pause torrents until a port exists; leave it `false` to keep torrents running even without forwarding.

Enable it by setting the forwarding variables above. With forwarding off, the controller and hooks stay idle and qBittorrent chooses its own port on first boot.

### Controller behaviour and safety rails
- Gluetun’s control API stays on `127.0.0.1` with the `GLUETUN_API_KEY` header and exposes a `/healthcheck` endpoint plus public-IP diagnostics for fast sanity checks.
- Polling backs off (2s → 4s → 8s) after API failures to avoid flapping services; the controller resumes normal cadence automatically once the API responds.
- Forwarded ports are validated before use (`1024-65535`) and read back from qBittorrent to ensure the client actually applied the update.
- Hook scripts remain audit-only. The controller polls independently, so port changes still apply even if a hook event is missed.

## Key environment flags
| Variable | Purpose |
| --- | --- |
| `SPLIT_VPN` | `0` for full tunnel, `1` for split tunnel. |
| `EXPOSE_DIRECT_PORTS` | Publish Arr LAN ports when splitting the tunnel. |
| `VPN_PORT_FORWARDING` | Turn Proton port forwarding on/off. |
| `GLUETUN_CONTROL_PORT` / `GLUETUN_API_KEY` | Control server port and API key used by helpers. |
| `CONTROLLER_POLL_INTERVAL` | Seconds between `vpn-port-guard` polls. |
| `CONTROLLER_REQUIRE_PF` | Pause torrents when no forwarded port is available. |

## Quick checks
```bash
# Confirm Gluetun control API is reachable
curl -s -H "X-API-Key: ${GLUETUN_API_KEY}" http://127.0.0.1:${GLUETUN_CONTROL_PORT}/healthcheck

# Read the forwarded port (when enabled)
cat ${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json | jq .forwarded_port

# Rotate the Gluetun API key
./arr.sh --rotate-api-key --yes
```

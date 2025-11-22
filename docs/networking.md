# Networking

[← Back to README](../README.md)

Choose how traffic flows, opt into Proton port forwarding, and place SABnzbd appropriately.

## VPN modes
| Mode | Setting | Behaviour | When to use |
| --- | --- | --- | --- |
| Full tunnel | `SPLIT_VPN=0` (default) | All services share Gluetun’s namespace. | Simplest path when you do not need LAN-reachable APIs. |
| Split tunnel | `SPLIT_VPN=1` | Only qBittorrent (and SABnzbd when `SABNZBD_USE_VPN=1`) live inside Gluetun; Arr apps stay on the LAN bridge. | Recommended for faster metadata and easier troubleshooting. |

Switch modes by editing `${ARRCONF_DIR}/userr.conf`, setting `EXPOSE_DIRECT_PORTS=1` when you want LAN URLs, and rerunning `./arr.sh --yes`. In split mode, point *Arr download clients at `http://LAN_IP:${QBT_PORT}` (qBittorrent listens on port 8082 inside Gluetun by default).

## Proton port forwarding (optional)
1. Use Proton credentials that support NAT-PMP (OpenVPN with `+pmp` is appended at runtime).
2. Opt in via `${ARRCONF_DIR}/userr.conf` and rerun the installer:
   ```bash
   VPN_PORT_FORWARDING=on
   VPN_PORT_FORWARDING_PROVIDER=protonvpn
   VPN_PORT_FORWARDING_STATUS_FILE=/tmp/gluetun/forwarded_port
   VPN_PORT_FORWARDING_UP_COMMAND=/scripts/vpn-port-guard-hook.sh up
   VPN_PORT_FORWARDING_DOWN_COMMAND=/scripts/vpn-port-guard-hook.sh down
   ```
3. The forwarded port is written to `/tmp/gluetun/forwarded_port` and mirrored through `${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json` when forwarding is enabled. Only Gluetun publishes ports; qBittorrent and the Arr apps stay inside the container namespace.

### Port guard
`vpn-port-guard` polls Gluetun’s control API every `${CONTROLLER_POLL_INTERVAL:-10}` seconds, applies the forwarded port to qBittorrent, and writes atomic status to `${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`. Set `CONTROLLER_REQUIRE_PF=true` to pause torrents until a port exists. Helpers and aliases remain idle when forwarding is off.

### Control API safety
- Binds to `127.0.0.1:${GLUETUN_CONTROL_PORT}` and requires `GLUETUN_API_KEY`; keep it off the LAN.
- Rotate the key anytime with `./arr.sh --rotate-api-key --yes` and verify with the health check printed by the installer.

## SABnzbd placements
| Mode | `SABNZBD_USE_VPN` | Network namespace | Host port exposure | Notes |
| --- | --- | --- | --- | --- |
| LAN bridge (default) | `0` | `arr_net` | Controlled by `EXPOSE_DIRECT_PORTS` and `SABNZBD_PORT`. | Keeps SAB reachable by Sonarr/Radarr/Lidarr over the LAN. |
| VPN attached | `1` | Shares Gluetun via `network_mode: "service:gluetun"` | No host port; reach via Gluetun network only. | Use when Usenet traffic must use the VPN exit IP. |

Keep `SABNZBD_INT_PORT=8080` when sharing Gluetun so it does not clash with qBittorrent’s `8082` WebUI. If Gluetun is disabled, SAB automatically falls back to the LAN bridge.

## Useful checks
```bash
arr.vpn.status            # Gluetun control API health
arr.vpn.port.state        # Forwarded port JSON (when enabled)
arr.vpn.port.watch        # Follow port-guard status
arr.vpn.fastest           # Rotate Proton endpoints via control API
```

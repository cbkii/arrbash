[← Back to README](../README.md)

# Networking and VPN

Use these settings to choose how traffic flows, manage Proton VPN forwarding, and enable optional DNS or HTTPS features.

## VPN modes
| Mode | Variable | Behaviour | When to use |
| --- | --- | --- | --- |
| Full tunnel | `SPLIT_VPN=0` (default) | All services share Gluetun’s namespace. | Simplest setup when you do not need LAN-reachable APIs. |
| Split tunnel | `SPLIT_VPN=1` | Only qBittorrent runs inside Gluetun; other services stay on the LAN bridge. | Recommended for faster metadata, fewer rate limits, and easier troubleshooting. |

**Switching modes**
1. Edit `${ARRCONF_DIR}/userr.conf` and set `SPLIT_VPN` as needed.
2. (Optional, Recommended) Set `EXPOSE_DIRECT_PORTS=1` so Sonarr/Radarr/Lidarr/etc. publish LAN ports in split mode.
3. Rerun the installer:
```bash
   ./arr.sh --yes
   ```
4. Update each *Arr download client entry to point at `http://LAN_IP:${QBT_PORT}` when running split tunnel (the
   host defaults to port **8082** unless you preserved a legacy value).

> When `EXPOSE_DIRECT_PORTS=1` is enabled the installer prints the published LAN URLs and asks for confirmation. Use `hostname -I | awk '{print $1}'` to confirm your host address before accepting, or pass `--yes` when you intentionally expose the ports.

Revert by setting `SPLIT_VPN=0` and rerunning the installer.

## SABnzbd network placements

SABnzbd stays off by default. When you enable it, choose where it lives so download speeds and LAN access match your needs.

| Mode | `SABNZBD_USE_VPN` | Network namespace | Host port exposure | Notes |
| --- | --- | --- | --- | --- |
| Direct LAN (default) | `0` | `arr_net` (LAN bridge) | Controlled by `EXPOSE_DIRECT_PORTS` and `SABNZBD_PORT`. | Keeps SAB reachable by Sonarr/Radarr/Lidarr/Prowlarr over the LAN. |
| Split-VPN direct | `0` | `arr_net` while qBittorrent stays in Gluetun | Optional | Works well with the default qBittorrent port (`8082`) so SAB can keep port 8080. |
| VPN attached | `1` | Shares Gluetun (`network_mode: "service:gluetun"`) | No host port; access via Gluetun network only. | Use when Usenet providers must see the VPN exit IP. |

Tips:

- Leave `SABNZBD_INT_PORT=8080` when SAB shares Gluetun so it does not clash with qBittorrent, which listens on 8082 internally.
- When VPN mode is active the stack skips LAN port mappings, so plan to reach SAB through Gluetun (for example using `docker compose exec sabnzbd ...`).
- If Gluetun is disabled, SAB automatically falls back to the LAN bridge so downloads continue.

## Proton port forwarding
- Proton port forwarding is optional—the installer makes a quick attempt after VPN startup and continues even without a lease (you'll see a non-fatal notice in the summary).
- Gluetun acquires the Proton forwarded port after the VPN is healthy. The installer writes hooks in `${ARR_DOCKER_DIR}/gluetun` and spawns an async worker so other services can start without waiting.
- Worker state lives in `${ARR_DOCKER_DIR}/gluetun/pf-state.json`; logs stream to `${ARR_DOCKER_DIR}/gluetun/port-forwarding.log`.
- Helper aliases (available after sourcing `.aliasarr`) expose status:
  ```bash
  arr.vpn.port.state   # JSON snapshot
  arr.vpn.port.watch   # Follow the worker log
  arr.vpn.port.sync    # Force a manual retry
  ```
- Rotate the Gluetun API key anytime with:
  ```bash
  ./arr.sh --rotate-api-key --yes
  ```
- Use `./arr.sh --sync-api-keys` to re-copy Sonarr/Radarr/Prowlarr API keys into Configarr when required.

## Local DNS and HTTPS helpers

Legacy LAN DNS and HTTPS helpers have been retired. Manage hostname overrides and TLS termination with your own tooling when needed. arrbash now exposes services directly on the LAN (when `EXPOSE_DIRECT_PORTS=1`) and relies on Gluetun to publish qBittorrent’s forwarded ports.

## VPN auto-reconnect (optional)
- Enable by setting `VPN_AUTO_RECONNECT_ENABLED=1` and rerunning the installer. The daemon now polls Gluetun’s control server (`/v1/openvpn/status`, `/v1/publicip/ip`, `/v1/openvpn/portforwarded`) instead of curling external IP services.
- The tunnel is marked unhealthy only when OpenVPN is not `running`, the exit IP is missing, or a Proton NAT-PMP port fails to appear after `VPN_PORT_GRACE_SECONDS`. Each failure triggers a control-server stop/start first and only falls back to restarting the Gluetun container via the stack’s compose wrapper when required.
- After a recovery the daemon re-runs the qBittorrent port hook so the client always listens on the forwarded port Gluetun negotiated with ProtonVPN.
- Cooldowns respect `VPN_COOLDOWN_MINUTES`, `VPN_RETRY_DELAY_SECONDS`, and `VPN_MAX_RETRY_MINUTES`; manual overrides continue to work via `.vpn-auto-reconnect-<flag>` files.
- Use helper aliases after sourcing `.aliasarr`:
  ```bash
  arr.vpn.auto.status
  arr.vpn.auto.pause   # create a pause file
  arr.vpn.auto.resume  # remove pause/kill overrides
  arr.vpn.auto.once    # request a single reconnect
  ```
- Runtime status lives in `${ARR_STACK_DIR}/.vpn-auto-reconnect-status.json`; detailed logs sit under `${ARR_DOCKER_DIR}/gluetun/auto-reconnect/daemon.log`.

### Manual VPN rotation
- `arr.vpn.fastest` cycles OpenVPN in-place using Gluetun’s control API so you get a fresh exit IP while keeping qBittorrent inside Gluetun’s `network_mode: "service:gluetun"` boundary.
- `arr.vpn.switch` without arguments behaves the same as `arr.vpn.fastest`. Pass `--next` to walk through `PVPN_ROTATE_COUNTRIES`, or provide an explicit country name to rewrite `SERVER_COUNTRIES` and restart Gluetun safely via `arr.vpn.reconnect --container`.
- Gluetun’s `UPDATER_PERIOD=24h` keeps the Proton server list current, so rotations always consider fresh endpoints without manual maintenance.

## Related topics
- [Configuration](configuration.md) – variables referenced above.
- [Operations](operations.md) – script details and command summaries.
- [Security](security.md) – exposure and certificate handling guidance.
- [Troubleshooting](troubleshooting.md) – DNS, HTTPS, or VPN recovery steps.

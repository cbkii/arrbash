[← Back to README](../README.md)

# Networking and VPN

Use these controls to choose how traffic flows, manage Proton VPN forwarding, and enable optional DNS or HTTPS features.

## VPN modes
| Mode | Variable | Behaviour | When to use |
| --- | --- | --- | --- |
| Full tunnel | `SPLIT_VPN=0` (default) | All services share Gluetun’s namespace. | Simplest setup when you do not need LAN-reachable APIs. |
| Split tunnel | `SPLIT_VPN=1` | Only qBittorrent runs inside Gluetun; other services stay on the LAN bridge. | Recommended for faster metadata, fewer rate limits, and easier troubleshooting. |

**Switching modes**
1. Edit `${ARR_BASE}/userr.conf` and set `SPLIT_VPN` as needed.
2. (Optional, Recommended) Set `EXPOSE_DIRECT_PORTS=1` so Sonarr/Radarr/etc. publish LAN ports in split mode.
3. Rerun the installer:
```bash
   ./arr.sh --yes
   ```
4. Update each *Arr download client entry to point at `http://LAN_IP:${QBT_PORT}` when running split tunnel (the
   host defaults to port **8082** unless you preserved a legacy value).

> When `EXPOSE_DIRECT_PORTS=1` is enabled the installer prints the published LAN URLs and asks for confirmation. Use `hostname -I | awk '{print $1}'` to confirm your host address before accepting, or pass `--yes` when you intentionally expose the ports.

Revert by setting `SPLIT_VPN=0` and rerunning the installer.

## Proton port forwarding
- Proton port forwarding is optional—the installer makes a quick attempt after VPN startup and continues even without a lease (you'll see a non-fatal notice in the summary).
- Gluetun acquires the Proton forwarded port after the VPN is healthy. The installer writes hooks in `docker-data/gluetun` and spawns an async worker so other services can start without waiting.
- Worker state lives in `docker-data/gluetun/pf-state.json`; logs stream to `docker-data/gluetun/port-forwarding.log`.
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

## Local DNS (optional)
1. Set `ENABLE_LOCAL_DNS=1` and choose `LAN_DOMAIN_SUFFIX` (default `home.arpa`).
2. Ensure the host frees port 53 before installing. If `systemd-resolved` or another resolver owns it, run:
   ```bash
   ./scripts/host-dns-setup.sh
   ```
   Revert later with `./scripts/host-dns-rollback.sh`.
3. Rerun the installer. The `local_dns` container serves `*.home.arpa` records and forwards other queries upstream.
4. Point clients at the Pi as their primary DNS server (DHCP Option 6 or per-device settings). Keep a trusted public resolver listed as secondary.

Check status with:
```bash
nslookup qbittorrent.${LAN_DOMAIN_SUFFIX:-home.arpa}
ss -ulpn | grep ':53 '
```

### Runtime state vs request

Setting `ENABLE_LOCAL_DNS=1` requests the resolver container, but the installer also calculates `LOCAL_DNS_STATE` to describe
the actual outcome. Use it (and the companion `LOCAL_DNS_STATE_REASON`) in summaries, the doctor report, or helper scripts to
diagnose why DNS might not be running yet.

| `LOCAL_DNS_STATE` | Meaning | Common next steps |
| --- | --- | --- |
| `inactive` | Local DNS was not requested (`ENABLE_LOCAL_DNS=0`). | Enable it in `userr.conf` and rerun the installer. |
| `blocked` | The request was denied because port 53 was already bound on the host. | Free the port (for example via `scripts/host-dns-setup.sh`) and rerun. |
| `split-disabled` | Split VPN mode disables the dnsmasq container by design. | Switch back to full-tunnel mode if you need the resolver. |
| `active` | The resolver container is included in `docker-compose.yml`. | Point clients at the host’s LAN IP as their DNS server. |

`LOCAL_DNS_STATE_REASON` contains the human-readable explanation that matches the table above, so helpers can echo it directly.

## Local HTTPS via Caddy (optional)
1. Set `ENABLE_CADDY=1` in `userr.conf` (or run `./arr.sh --enable-caddy --yes`).
2. Rerun the installer; it renders `Caddyfile`, validates it with `caddy validate`, and publishes HTTPS on ports 80/443.
3. Fetch the public root certificate once:
   ```bash
   curl -o root.crt http://ca.${LAN_DOMAIN_SUFFIX:-home.arpa}/root.crt
   ```
   Alternatively run `./scripts/export-caddy-ca.sh ~/root.crt` on the host, or `./scripts/install-caddy-ca.sh` for automated trust on Debian/Ubuntu.
4. Import `root.crt` into each device’s trusted root store. Browsers will then accept URLs such as `https://qbittorrent.home.arpa`.

## VPN auto-reconnect (optional)
- Enable by setting `VPN_AUTO_RECONNECT_ENABLED=1` and rerunning the installer. The daemon monitors qBittorrent throughput and rotates Proton servers when sustained speeds fall below `VPN_SPEED_THRESHOLD_KBPS` for `VPN_CONSECUTIVE_CHECKS` intervals.
- Adjust quiet hours and cooldowns with `VPN_ALLOWED_HOURS_START`, `VPN_ALLOWED_HOURS_END`, `VPN_COOLDOWN_MINUTES`, and `VPN_MAX_RETRY_MINUTES`.
- Use helper aliases after sourcing `.aliasarr`:
  ```bash
  arr.vpn.auto.status
  arr.vpn.auto.pause   # create a pause file
  arr.vpn.auto.resume  # remove pause/kill overrides
  arr.vpn.auto.once    # request a single reconnect
  ```
- Runtime status lives in `${ARR_STACK_DIR}/.vpn-auto-reconnect-status.json`; detailed logs sit under `docker-data/gluetun/auto-reconnect/`.

## Related topics
- [Configuration](configuration.md) – variables referenced above.
- [Operations](operations.md) – script details and command summaries.
- [Security](security.md) – exposure and certificate handling guidance.
- [Troubleshooting](troubleshooting.md) – DNS, HTTPS, or VPN recovery steps.

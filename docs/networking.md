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
   ./arrstack.sh --yes
   ```
4. Update each *Arr download client entry to point at `http://LAN_IP:${QBT_PORT}` when running split tunnel (the
   host defaults to port **8082** unless you preserved a legacy value).

> When `EXPOSE_DIRECT_PORTS=1` is enabled the installer prints the published LAN URLs and asks for confirmation (even with `--yes`). Use `hostname -I | awk '{print $1}'` to confirm your host address before accepting.

Revert by setting `SPLIT_VPN=0` and rerunning the installer.

## Startup gating and Proton port forwarding
- `./arrstack.sh` waits up to ~2 minutes for Gluetun to report `running` (and `healthy` when the container provides a healthcheck), confirm a tunnel interface exists (`tun0` or `wg0`), and complete a connectivity probe from inside Gluetun. qBittorrent and the *Arr services never start until this gate passes.
- When Proton port forwarding is enabled, the installer performs a short best-effort wait (~60 seconds) for a lease. If nothing arrives in that window, services still start and the logs/summary remind you that forwarding depends on your VPN provider, plan, and chosen server.
- ProtonVPN’s forwarding feature is limited to paid Plus/Unlimited plans on specific P2P-friendly exit servers, and other VPN providers may not support forwarding at all.
- Successful runs still launch the async worker in `docker-data/gluetun`; state lives in `pf-state.json` and logs in `port-forwarding.log`.
- Helper aliases (available after sourcing `.aliasarr`) expose status:
  ```bash
  arr.vpn.port.state   # JSON snapshot
  arr.vpn.port.watch   # Follow the worker log
  arr.vpn.port.sync    # Force a manual retry
  ```
- Rotate the Gluetun API key anytime with:
  ```bash
  ./arrstack.sh --rotate-api-key --yes
  ```
- Use `./arrstack.sh --sync-api-keys` to re-copy Sonarr/Radarr/Prowlarr API keys into Configarr when required.

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

`LOCAL_DNS_STATE_REASON` contains the human-readable explanation that matches the table above, so helpers can echo it directly. `LOCAL_DNS_SERVICE_ENABLED=0` means the resolver container was intentionally skipped (for example split VPN mode or a retained port conflict), so host daemon merges and restarts are bypassed automatically.

## Local HTTPS via Caddy (optional)
1. Set `ENABLE_CADDY=1` in `userr.conf` (or run `./arrstack.sh --enable-caddy --yes`).
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

## When port checks are skipped
If preflight reports that port validation was skipped (for example Docker was unavailable), manually verify the published ports before exposing the stack:

```bash
ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191|:80|:443|:53'
```

Compare the output to the summary table—only enable router forwards or `EXPOSE_DIRECT_PORTS=1` after confirming no unexpected listeners are present.

[← Back to README](../README.md)

# Troubleshooting

Follow these checks when services fail to start, DNS stops resolving, or VPN helpers misbehave.

## DNS and HTTPS issues
### `ERR_NAME_NOT_RESOLVED`
- Applies only when local DNS is enabled. Ensure clients point at the arrbash host first (DHCP Option 6 or per-device settings). See [Networking](networking.md) for setup guidance.
- Verify:
  ```bash
  nslookup qbittorrent.${LAN_DOMAIN_SUFFIX:-home.arpa}
  ```
  The resolver should report your Pi’s LAN IP.

### Browser warns about HTTPS certificate
- Import the Caddy root certificate from `http://ca.${LAN_DOMAIN_SUFFIX:-home.arpa}/root.crt` or run `./scripts/install-caddy-ca.sh` on Debian/Ubuntu hosts.
- Verify:
  ```bash
  curl -I https://qbittorrent.${LAN_DOMAIN_SUFFIX:-home.arpa}
  ```
  Expect an HTTP 200/301 without TLS warnings.

### Port 53 already in use
- Run the host helper to free the port and start the `local_dns` container:
  ```bash
  ./scripts/host-dns-setup.sh
  ```
- Verify:
  ```bash
  ss -ulpn | grep ':53 '
  ```
  `dnsmasq` should own the socket. Roll back with `./scripts/host-dns-rollback.sh` when finished testing.

## VPN and torrent issues
### qBittorrent unreachable after enabling `SPLIT_VPN=1`
- In split mode only qBittorrent is published automatically. Set `EXPOSE_DIRECT_PORTS=1` or provide your own proxy.
- Verify:
  ```bash
  docker compose ps --format '{{.Service}}\t{{.Publishers}}'
  ```
  The media services should list LAN ports when exposure is enabled.

### *Arr apps cannot reach qBittorrent in split mode
- Update each download client host to `http://LAN_IP:${QBT_PORT}`. Docker service names no longer resolve outside Gluetun.
- Use the in-app **Test** button to confirm connectivity.

### Proton forwarded port stuck at 0
- Check the async worker state:
  ```bash
  arr.vpn.port.state
  arr.vpn.port.watch
  arr.vpn.port.sync
  ```
- Ensure Gluetun accepts API requests (`docker-data/gluetun/auth/config.toml` is created automatically for versions ≥3.40).
- Rotate the API key if authentication fails:
  ```bash
  ./arr.sh --rotate-api-key --yes
  ```

### Gluetun recovery
- When the installer prints “Setup FAILED” for VPN readiness, start with `docker logs gluetun` to identify handshake or authentication errors.
- Remove `${ARR_DOCKER_DIR}/gluetun/auth/config.toml` if your Proton credentials changed and rerun `./arr.sh` to regenerate it.
- Re-run `./arr.sh --yes` after adjusting `userr.conf` (for example choosing a PF-capable server) so the installer retries from a clean state.
- Use `arr.vpn.port.sync` once Gluetun is healthy to confirm a forwarded port is assigned.

### VPN auto-reconnect inactive
- Confirm the feature is enabled:
  ```bash
  grep VPN_AUTO_RECONNECT_ENABLED ${ARRCONF_DIR}/userr.conf
  ```
- Clear pause/kill overrides:
  ```bash
  arr.vpn.auto.resume
  ```
- Inspect logs under `docker-data/gluetun/auto-reconnect/daemon.log` for recent actions.

## WebUI and credentials
### VueTorrent shows HTTP 500 or blank page
- Match `QBT_DOCKER_MODS` to the desired mode. Non-empty keeps the LSIO mod; empty triggers the manual installer and verifies `/config/vuetorrent`.
- Verify the expected path inside the container:
  ```bash
  docker exec qbittorrent test -f /vuetorrent/public/index.html
  docker exec qbittorrent test -f /config/vuetorrent/public/index.html
  ```
  Only one should succeed.
- Manual mode fetches the latest VueTorrent release at runtime, prints the archive SHA256, and skips verification unless you set `VUETORRENT_SHA256`. Provide `VUETORRENT_DOWNLOAD_URL` when you need to install a specific build.

### Need the temporary qBittorrent password
- Check the logs once:
  ```bash
  docker logs qbittorrent | grep 'temporary password'
  ```
- Run `./scripts/qbt-helper.sh show` for a formatted summary or `./scripts/qbt-helper.sh reset` to generate a new login.

### Configarr still complains about API keys
- Run the sync helper after Sonarr/Radarr/Prowlarr generate their `config.xml` files:
  ```bash
  ./arr.sh --sync-api-keys --yes
  ```
- Verify secrets:
  ```bash
  grep _API_KEY docker-data/configarr/secrets.yml
  ```

## Installer and runtime checks
### Installer reports port conflicts
- Stop any conflicting services or containers, then rerun:
  ```bash
  ./arr.sh --yes
  ```
- Set `ARR_PORT_CHECK_MODE=fix` if you want the installer to automatically stop known listeners (Docker proxies,
  stale stack instances) before retrying and then continue in warn mode if conflicts remain.
- Use the printed conflict summary to identify the owning process and adjust `userr.conf` if you must reassign ports.

### Containers stuck in `starting`
- Gluetun must be healthy first. Restart it, wait for the forwarded port, then launch the rest:
  ```bash
  docker compose up -d gluetun
  sleep 30
  docker compose up -d
  ```
- Confirm all services report `running` with `docker compose ps`.

### Unsure which component failed
- Run the bundled diagnostics:
  ```bash
  ./scripts/doctor.sh
  ```
  The script repeats DNS, port, and HTTPS checks using your generated configuration.

## Related topics
- [Networking](networking.md) – VPN, DNS, and HTTPS setup details.
- [Operations](operations.md) – helper command summaries.
- [Security](security.md) – exposure considerations.

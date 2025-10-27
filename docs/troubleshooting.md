# Troubleshooting

[← Back to README](../README.md)

Follow these checks when services fail to start, DNS stops resolving, or VPN helpers misbehave.

## Purge placeholder-polluted sessions

Source the installed `.aliasarr` only (never `scripts/gen-aliasarr.template.sh`). Run Compose from the project directory so `.env` overrides `arrconf/userr.conf`, which overrides `arrconf/userr.conf.defaults.sh`. The last four commands clear optional systemd user and tmux environments.

```bash
env | grep -E '^ARR_' | sed 's/^/ENV: /'
export -n ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
unset ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr" 2>/dev/null || true
docker compose config | grep -n '__ARR_' && echo "❌ placeholder present" || echo "✅ no placeholders"
systemctl --user show-environment | grep -E '^ARR_' || true
systemctl --user unset-environment ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
tmux show-environment | grep -E '^ARR_' 2>/dev/null || true
tmux set-environment -ur ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
```

## DNS and HTTPS issues
arrbash no longer provisions LAN DNS or HTTPS automation. If you require friendly hostnames or TLS termination, deploy and manage your own tooling (Pi-hole/unbound, AdGuard Home, nginx, Traefik, etc.) and point clients at it.

### `ERR_NAME_NOT_RESOLVED`
- When you operate your own resolver, ensure LAN clients use it (DHCP Option 6 or per-device configuration).
- Verify the record resolves as expected:
  ```bash
  nslookup media.example.com
  ```
  Substitute the hostname you publish; the response should report your arrbash host’s LAN IP.

### Browser warns about HTTPS certificate
- Import the trust roots for whatever HTTPS proxy you provide. arrbash no longer installs or manages certificates automatically.
- Verify your proxy terminates TLS cleanly:
  ```bash
  curl -I https://media.example.com
  ```
  Replace the hostname with the value you publish and expect an HTTP 200/301 without TLS warnings.

### Port 53 already in use
- arrbash no longer starts dnsmasq. If a prior deployment left a resolver enabled, stop or remove that service manually before binding another DNS daemon on the host.

## VPN and torrent issues
### qBittorrent unreachable after enabling `SPLIT_VPN=1`
- In split mode only qBittorrent is published automatically. Set `EXPOSE_DIRECT_PORTS=1` or expose the additional services through your own gateway.
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
- Ensure Gluetun accepts API requests (`${ARR_DOCKER_DIR}/gluetun/auth/config.toml` is created automatically for versions ≥3.40).
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
- Check the JSON status the watchdog writes:
  ```bash
  arr.vpn.auto.status
  ```
- Clear pause/kill overrides:
  ```bash
  arr.vpn.auto.resume
  ```
- Use `arr.vpn.status` to ensure Gluetun’s control server responds (the watchdog relies on `/v1/openvpn/status`, `/v1/publicip/ip`, and `/v1/openvpn/portforwarded`).
- Inspect logs under `${ARR_DOCKER_DIR}/gluetun/auto-reconnect/daemon.log` for recent actions.

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
- Run `./scripts/stack-qbt-helper.sh show` for a formatted summary or `./scripts/stack-qbt-helper.sh reset` to generate a new login.

### Configarr still complains about API keys
- Run the sync helper after Sonarr/Radarr/Prowlarr generate their `config.xml` files:
  ```bash
  ./arr.sh --sync-api-keys --yes
  ```
- Verify secrets:
  ```bash
  grep _API_KEY "${ARR_DOCKER_DIR}/configarr/secrets.yml"
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
  ./scripts/fix-doctor.sh
  ```
  The script repeats DNS, port, and HTTPS checks using your generated configuration.

## Related topics
- [Networking](networking.md) – VPN, DNS, and HTTPS setup details.
- [Operations](operations.md) – helper command summaries.
- [Security](security.md) – exposure considerations.

[← Back to README](../README.md)

# Configuration guide

Edit `${ARRCONF_DIR}/userr.conf` to control how the installer renders `.env`, `docker-compose.yml`, and helper files. `ARR_DATA_ROOT` defaults to `~/srv`, so generated files land under `~/srv/arr` unless you override the path. `./arr.sh` copies any exported environment variables, locks them read-only while your config loads, then reapplies them so CLI overrides always win. Before reading the file the installer looks for the first `userr.conf` under `${ARR_DATA_ROOT}` (depth 4) and then above the repo (for example `../userr.conf`). The chosen path appears in the preview table so you can confirm it.

## Configuration layers

1. **CLI flags** – run-scoped toggles (for example `./arr.sh --enable-caddy`) apply after the read-only guard. They override exported variables and `userr.conf`, so use them for temporary changes.
2. **Shell environment** – anything exported before running `./arr.sh` still overrides `userr.conf` and defaults, but CLI flags are applied last. Paths like `ARR_USERCONF_PATH` may be normalised to an absolute path while loading.
3. **`${ARRCONF_DIR}/userr.conf`** – your saved settings (defaults to `${ARR_DATA_ROOT}/${STACK}configs/userr.conf`). Keep it outside version control and rerun the installer after every edit.
4. **`arrconf/userr.conf.defaults.sh`** – repo defaults.

The installer prints a configuration table during preflight. Cancel with `Ctrl+C` if a value looks wrong, adjust `userr.conf`, and rerun.

## Core settings to review

- **Network**
  - `LAN_IP`: set this to your host's private address before exposing ports.
  - `LOCALHOST_IP`: leave on loopback (`127.0.0.1`) so container health checks target the right place.
  - `LAN_DOMAIN_SUFFIX`: optional hostname suffix (default `home.arpa`) needed for local DNS and Caddy URLs.
  - `SPLIT_VPN`: `1` routes only qBittorrent through Gluetun; `0` tunnels everything.
  - `EXPOSE_DIRECT_PORTS`: keep at `1` for simple LAN URLs, or set `0` to hide services behind Docker networking.
  - `DNS_DISTRIBUTION_MODE`: choose `router` to update DHCP Option 6 or `per-device` to set DNS on each client yourself.
  - `ARR_PORT_CHECK_MODE`: `enforce` (default) stops on conflicts, `warn` prints notices, `skip` disables checks, and `fix` tries to stop known blockers before warning.
- **Paths & storage**
  - `ARR_DATA_ROOT`: base directory for everything (defaults to `~/srv`). Override it before the first run if you want a different location.
  - `ARRCONF_DIR`: holds Proton credentials and overrides (defaults to `${ARR_DATA_ROOT}/${STACK}configs`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`, `TV_DIR`, `MOVIES_DIR`, `SUBS_DIR`: point these at your real storage; defaults live under `${ARR_DATA_ROOT}`.
  - `ARR_LOG_DIR`: move logs if you prefer another disk.
- **Credentials & preservation**
  - `QBT_USER` / `QBT_PASS`: keep these in sync with the WebUI. Rerun the installer after changes so `.env` updates automatically.
  - `GLUETUN_API_KEY`, `CADDY_BASIC_AUTH_USER`, `CADDY_BASIC_AUTH_HASH`: leave blank; rotation helpers fill them in.
  - `QBT_AUTH_WHITELIST`: CIDRs allowed to skip the qBittorrent login (loopback and your LAN are added automatically).
  - `QBT_BIND_ADDR`: override the container-side WebUI bind address if you need something other than `0.0.0.0`.
  - WebUI port/address are enforced by default at startup and after drift.
- **VPN automation**
  - `VPN_AUTO_RECONNECT_ENABLED`: runs the reconnect worker that watches qBittorrent speeds.
  - `VPN_SPEED_THRESHOLD_KBPS`, `VPN_CHECK_INTERVAL_MINUTES`, `VPN_CONSECUTIVE_CHECKS`: tune how quickly reconnects fire.
  - `VPN_ALLOWED_HOURS_START` / `VPN_ALLOWED_HOURS_END`: limit reconnects to certain hours; set the same number for 24/7.
- **Permission profiles**
  - `ARR_PERMISSION_PROFILE`: `strict` (default) keeps secrets at `600`, data at `700`, and uses `umask 0077`. `collab` enables group write; set `PGID` to your shared group.
  - Optional overrides: `ARR_UMASK_OVERRIDE`, `ARR_DATA_DIR_MODE_OVERRIDE`, `ARR_NONSECRET_FILE_MODE_OVERRIDE`, `ARR_SECRET_FILE_MODE_OVERRIDE` for advanced tuning.

## Working with overrides / Verify resolved values

1. Edit `${ARRCONF_DIR}/userr.conf` (or the path from `ARR_USERCONF_PATH`).
2. Save the file and rerun:
   ```bash
   ./arr.sh --yes
   # Cancel before container startup if the preview looks wrong.
   ```

3. Review the summary. Never edit generated files (`.env`, `docker-compose.yml`, `Caddyfile`) by hand.
4. Confirm preserved secrets remain in sync:
  ```bash
  grep -E '^QBT_(USER|PASS)=' .env
  ```

## Optional services and containers

Toggle these extras in `${ARRCONF_DIR}/userr.conf` or via the matching `./arr.sh` flags. Rerun the installer after every change so generated files and helper aliases stay in sync.

### Caddy HTTPS proxy
- Set `ENABLE_CADDY=1` or run `./arr.sh --enable-caddy --yes` for a one-off enable.
- Caddy publishes HTTPS on `CADDY_HTTP_PORT`/`CADDY_HTTPS_PORT` (defaults 80/443) and serves hostnames like `https://qbittorrent.${LAN_DOMAIN_SUFFIX}`.
- Fetch the root certificate once and import it on each device. See [Networking](networking.md#local-https-via-caddy-optional) for the certificate flow.

### Local DNS resolver
- Set `ENABLE_LOCAL_DNS=1` to request the dnsmasq container. The installer records the real outcome in `LOCAL_DNS_STATE` and `LOCAL_DNS_STATE_REASON` so you know if another service blocked port 53.
- Free the host resolver port with `./scripts/host-dns-setup.sh` when required, then rerun the installer.
- Client setup guidance lives in [Networking](networking.md#local-dns-optional).

### Configarr automation
- Set `ENABLE_CONFIGARR=1` to let Configarr push opinionated defaults into Sonarr and Radarr.
- Keep `GLUETUN_API_KEY`, Sonarr, Radarr, and Prowlarr API keys current; `./arr.sh --sync-api-keys` recopies them into Configarr.
- Disable for a run with `./arr.sh --no-auto-api-sync` if you need to make manual adjustments temporarily.

### SABnzbd downloader
- Set `SABNZBD_ENABLED=1` (or run `./arr.sh --enable-sab --yes`) to add SABnzbd to the compose file and copy `scripts/sab-helper.sh` into the stack directory.
- Choose where SAB runs with `SABNZBD_USE_VPN` (`0` keeps it on the LAN, `1` shares Gluetun). [Networking](networking.md#sabnzbd-network-placements) shows the available modes and how ports map when qBittorrent sits inside Gluetun.
- Adjust ports with `SABNZBD_PORT` (host) and `SABNZBD_INT_PORT` (container). Leave the internal port at 8080 when SAB shares the VPN namespace so it does not clash with qBittorrent’s WebUI (`8082`).
- `SABNZBD_HOST`, `SABNZBD_TIMEOUT`, and `SABNZBD_CATEGORY` tune helper defaults. Override `SABNZBD_IMAGE` if you need a specific container tag.
- The installer preserves your API key. If `.env` still shows `REPLACE_WITH_SABNZBD_API_KEY`, reruns extract `api_key` from `sabnzbd.ini`, store a dated backup, and write the new value.
- When SAB runs on the LAN and Caddy is enabled, the stack publishes `https://sabnzbd.${LAN_DOMAIN_SUFFIX}` automatically. VPN mode skips LAN mappings, so reach it through Gluetun instead.
- Use the helper commands described in [Operations](operations.md#sabnzbd-helper) to submit jobs or check status.

### VueTorrent WebUI (qBittorrent alternative)
- Leave qBittorrent on the default LinuxServer image to use the built-in VueTorrent mod. The installer reports the active mode in its summary.
- For the standalone VueTorrent build, set `QBT_DOCKER_MODS=` empty and enable manual mode variables such as `VUETORRENT_DOWNLOAD_URL`, `VUETORRENT_SHA256`, and `VUETORRENT_MODE=manual` before rerunning the installer.
- Troubleshooting tips live in [Troubleshooting](troubleshooting.md#vuetorrent-shows-http-500-or-blank-page).

## Related topics
- [Operations](operations.md) – helper scripts and command-line flags.
- [Networking](networking.md) – VPN, DNS, and HTTPS considerations.
- [Security](security.md) – exposure and credential hygiene guidance.

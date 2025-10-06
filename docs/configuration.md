[← Back to README](../README.md)

# Configuration guide

Edit `${ARRCONF_DIR}/userr.conf` to control how the installer renders `.env`, `docker-compose.yml`, and supporting files. `ARR_DATA_ROOT` defaults to `~/srv`, keeping generated assets under the historical data directory unless you override it. `./arr.sh` snapshots exported environment variables, marks them read-only before sourcing your config, and reapplies them afterwards so they continue to win over anything set inside `userr.conf` or the defaults. Before loading the file the installer searches the repo's parent directory for the first path named `userr.conf` (for example `../userr.conf` or `../overrides/site-a/userr.conf`) and uses that file; the same path is surfaced in the configuration preview so you can confirm which override will apply.

## Configuration layers
1. **Shell environment** – anything exported before running `./arr.sh` overrides every other source (use for CI or one-off toggles). Values are made read-only while `userr.conf` loads and reasserted afterwards, except for internal read-only variables and normalized paths such as `ARR_USERCONF_PATH`, which may be canonicalised to an absolute path during startup.
2. **CLI flags** – run-scoped toggles (for example `./arr.sh --enable-caddy`) apply after the read-only guard. Use them to temporarily override `userr.conf` without editing the file. Environment exports still win if both are present.
3. **`${ARRCONF_DIR}/userr.conf`** – your persistent copy (defaults to `${ARR_DATA_ROOT}/${STACK}configs/userr.conf`). Keep it out of version control and rerun the installer after every edit.
4. **`arrconf/userr.conf.defaults.sh`** – project defaults committed in the repo.

The installer prints a configuration table during preflight. Cancel with `Ctrl+C` if a value looks wrong, adjust `userr.conf`, and rerun.

## Core settings to review
- **Network**
  - `LAN_IP`: private address for the host; required before ports are exposed.
  - `LOCALHOST_IP` must be loopback.
    Healthchecks run inside containers. Set `LOCALHOST_IP` to a loopback address (`127.0.0.1`). If you point it at a LAN IP, some healthchecks will probe the wrong interface and flap. Example:

    `LOCALHOST_IP=127.0.0.1`
  - `LAN_DOMAIN_SUFFIX`: optional suffix for hostnames (default `home.arpa`). Needed for local DNS or Caddy.
  - `SPLIT_VPN`: set `1` to run only qBittorrent inside Gluetun, or `0` to tunnel everything.
  - `EXPOSE_DIRECT_PORTS`: leave at `1` for LAN-friendly URLs, or set `0` to keep services internal to Docker networking.
  - `DNS_DISTRIBUTION_MODE`: choose `router` (default) to update DHCP Option 6, or `per-device` when pointing clients at the resolver manually.
  - `ARR_PORT_CHECK_MODE`: `enforce` (default) fails fast on conflicts, `warn` prints notices, `skip` disables port validation (use sparingly), and `fix` attempts to stop conflicting listeners automatically before falling back to warn mode.
- **Paths & storage**
  - `ARR_DATA_ROOT`: top-level data directory (defaults to `~/srv`). Override it before running the installer if you want a different layout.
  - `ARRCONF_DIR`: configuration directory for Proton credentials and overrides (defaults to `${ARR_DATA_ROOT}/${STACK}configs`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`, `TV_DIR`, `MOVIES_DIR`, `SUBS_DIR`: defaults live under `${ARR_DATA_ROOT}` (for example `${ARR_DATA_ROOT}/media` and `${ARR_DATA_ROOT}/media/Shows`), so update them in `userr.conf` to target your actual media drive.
  - `ARR_LOG_DIR`: location for installer and helper logs if you prefer another disk.
- **Credentials & preservation**
  - `QBT_USER` / `QBT_PASS`: update after changing the WebUI login; rerun the installer to persist them.
  - `GLUETUN_API_KEY`, `CADDY_BASIC_AUTH_USER`, `CADDY_BASIC_AUTH_HASH`: left blank by default so rotation helpers manage them.
  - `QBT_AUTH_WHITELIST`: CIDRs that bypass the qBittorrent login (auto-populated with loopback and your LAN subnet).
- **Optional services**
  - `ENABLE_CADDY`: `1` enables the HTTPS proxy on `CADDY_HTTP_PORT`/`CADDY_HTTPS_PORT` (defaults 80/443). Adjust those port variables if another web server is present.
  - `ENABLE_LOCAL_DNS`: `1` runs the dnsmasq container for LAN hostnames; combine with `DNS_DISTRIBUTION_MODE` to control how clients learn the resolver. The installer records the runtime result in `LOCAL_DNS_STATE`/`LOCAL_DNS_STATE_REASON` so you can tell whether DNS actually started.
  - `ENABLE_CONFIGARR`: `1` keeps Configarr managing Sonarr/Radarr settings.
  - `SPLIT_VPN` and optional toggles such as `ENABLE_CADDY` can also be set per run with `./arr.sh` flags.
- **VPN automation**
  - `VPN_AUTO_RECONNECT_ENABLED`: monitor qBittorrent throughput and rotate Proton servers automatically.
  - `VPN_SPEED_THRESHOLD_KBPS`, `VPN_CHECK_INTERVAL_MINUTES`, `VPN_CONSECUTIVE_CHECKS`: tune when reconnects trigger.
  - `VPN_ALLOWED_HOURS_START` / `VPN_ALLOWED_HOURS_END`: restrict reconnect windows; set equal to permit 24/7 operation.
- **Permission profiles**
  - `ARR_PERMISSION_PROFILE`: `strict` (default) keeps secrets at `600` and data at `700`. Switch to `collab` when multiple accounts need write access; set `PGID` to the shared group.
  - Optional overrides: `ARR_UMASK_OVERRIDE`, `ARR_DATA_DIR_MODE_OVERRIDE`, `ARR_NONSECRET_FILE_MODE_OVERRIDE`, `ARR_SECRET_FILE_MODE_OVERRIDE` for advanced tuning.

## Working with overrides
1. Edit `${ARRCONF_DIR}/userr.conf` (or the path set in `ARR_USERCONF_PATH`).
2. Save the file and rerun:
   ```bash
   ./arr.sh --yes
   ```
3. Review the printed summary. Generated files (`.env`, `docker-compose.yml`, `Caddyfile`) should never be edited directly.

## Verify
- Show resolved values without applying changes:
  ```bash
  ./arr.sh --yes
  ```
  Cancel before container startup if the preview looks wrong.
- Confirm preserved secrets remain in sync:
  ```bash
  grep -E '^QBT_(USER|PASS)=' .env
  ```

## Related topics
- [Operations](operations.md) – helper scripts and command-line flags.
- [Networking](networking.md) – VPN, DNS, and HTTPS considerations.
- [Security](security.md) – exposure and credential hygiene guidance.

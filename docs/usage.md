# Usage

[← Back to README](../README.md)

How to install, configure, and operate the stack.

## Install and run
1. Ensure Docker, the Compose plugin, Git, `curl`, `jq`, `openssl`, `envsubst`, and `python3` are present on the host.
2. Clone the repo into your working directory (defaults assume `~/srv/arrbash`).
3. Copy `arrconf/proton.auth.example` and `arrconf/userr.conf.example` outside the repo (for example `../arrconfigs/`), set ownership to your user, and chmod the files to `600`.
4. Populate Proton credentials plus your LAN IP and storage paths in `userr.conf`.
5. Run the installer anytime you change configuration:
   ```bash
   ./arr.sh --yes
   ```
   The script regenerates `.env` from `scripts/.env.template` via `scripts/gen-env.sh`, rewrites `docker-compose.yml`, refreshes helper files, and starts containers. Never edit generated files directly.

## Configuration layers
- Defaults: `arrconf/userr.conf.defaults.sh`
- Overrides: `${ARRCONF_DIR}/userr.conf` (defaults to `${ARR_DATA_ROOT}/${STACK}configs/userr.conf`)
- Environment overrides: exported variables before invoking `./arr.sh`
- CLI flags: highest precedence per run

Effective order: `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`. The installer prints the resolved values before starting containers.

`scripts/.env.template` uses `# @if VAR` guards for optional blocks. `scripts/gen-env.sh` filters those sections, substitutes surviving placeholders with `envsubst`, and writes `KEY=value` lines (no quotes) to `${ARR_STACK_DIR}/.env` with mode `0600`.

## Key settings
- **LAN and paths**: set `LAN_IP`, `ARR_DATA_ROOT` (base working directory), `ARRCONF_DIR` (config folder), `ARR_STACK_DIR` (stack output), and download/library paths such as `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`, `TV_DIR`, `MOVIES_DIR`, and `MUSIC_DIR`.
- **Networking**: `SPLIT_VPN=1` keeps qBittorrent (and optionally SABnzbd) inside Gluetun; `EXPOSE_DIRECT_PORTS=1` publishes LAN ports for *Arr apps.
- **Ports**: internal ports like `QBT_INT_PORT`, `SONARR_INT_PORT`, etc., backfill host ports (`QBT_PORT`, `SONARR_PORT`, …) when `EXPOSE_DIRECT_PORTS=1`.
- **API resilience**: adjust `QBT_API_TIMEOUT`, `QBT_API_RETRY_COUNT`, `QBT_API_RETRY_DELAY`, `GLUETUN_API_TIMEOUT`, `GLUETUN_API_RETRY_COUNT`, `GLUETUN_API_RETRY_DELAY`, and `GLUETUN_API_MAX_RETRY_DELAY` if control endpoints are unstable.
- **Images**: override `*_IMAGE` values in `userr.conf` to pin or float tags; the installer validates availability when rendering.
- **Permissions**: `ARR_PERMISSION_PROFILE=strict` keeps secrets at `600` and directories at `700`; set to `collab` with a matching `PGID` when collaborative writes are required.

## Optional services
- **Configarr**: enable with `ENABLE_CONFIGARR=1` to sync Sonarr/Radarr defaults. Re-run `./arr.sh --sync-api-keys --yes` if you change API keys in the apps.
- **SABnzbd**: enable with `SABNZBD_ENABLED=1`. Choose placement via `SABNZBD_USE_VPN` (`0` for LAN bridge, `1` to share Gluetun). Adjust `SABNZBD_PORT`/`SABNZBD_INT_PORT` as needed; the installer preserves `SABNZBD_API_KEY` between runs.
- **VueTorrent**: keep the LinuxServer mod by leaving `QBT_DOCKER_MODS` set. Clear it and set `VUETORRENT_MODE=manual` (plus optional `VUETORRENT_DOWNLOAD_URL`/`VUETORRENT_SHA256`) to supply your own build.

## Everyday operations
- Common flags:
  ```bash
  ./arr.sh --yes               # non-interactive
  ./arr.sh --trace             # bash tracing for debugging
  ./arr.sh --rotate-api-key    # refresh Gluetun control API key
  ./arr.sh --enable-sab        # temporary SABNZBD_ENABLED=1
  ./arr.sh --sync-api-keys     # recopy Sonarr/Radarr/Prowlarr keys into Configarr
  ./arr.sh --uninstall         # stop containers and remove generated assets
  ```
- Load aliases after the first run:
  ```bash
  source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr"
  arr.vpn.status
  arr.vpn.port
  arr.logs
  arr.open
  arr.config.sync
  ```
- Helper scripts live under `scripts/` and `${ARR_STACK_DIR}/scripts/` after installation. Notable examples: `scripts/stack-qbt-helper.sh` (qBittorrent credentials/whitelist), `scripts/fix-doctor.sh` (sanity checks), and `scripts/stack-sab-helper.sh` (SABnzbd tasks when enabled).

## Diagnostics and health
- Run targeted checks before upgrades or when debugging: `./scripts/stack-diagnostics.sh` (dependency and API validation) and `./scripts/stack-healthcheck.sh --format json` (API and service status output for monitoring).

## Security basics
- Keep `proton.auth`, `userr.conf`, and generated `.env` files out of version control; permissions default to `600` for secrets.
- **qBittorrent password**: On first install, if you set a custom `QBT_PASS` in `userr.conf` (not the default `adminadmin`), the installer will apply it to qBittorrent via API. After that, if you change the password in qBittorrent's WebUI, update `QBT_PASS` in your `userr.conf` to match.
- **LAN whitelist**: When `LAN_IP` is set, the installer automatically adds `LAN_IP/24` to `QBT_AUTH_WHITELIST` for passwordless access from your local network.
- Rotate the Gluetun API key periodically with `./arr.sh --rotate-api-key --yes`; validate with the control API health check printed in the installer summary.
- Verify exposed ports explicitly when `EXPOSE_DIRECT_PORTS=1`:
  ```bash
  sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191'
  ```
  Expect only the ports you enabled on the LAN bridge.

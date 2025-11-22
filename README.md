# arrbash

Set up the *arr media stack with Proton VPN support on a Debian-based host.

## What you get
- qBittorrent routed through Gluetun with optional Proton VPN port forwarding.
- Sonarr, Radarr, Lidarr, Prowlarr, Bazarr, and FlareSolverr on the LAN bridge.
- Optional extras: Configarr sync, SABnzbd downloader, and the VueTorrent WebUI.

## Prerequisites
- 64-bit Debian 12 (Bookworm) or equivalent with a static LAN IP, 4 CPU cores, and 4 GB RAM.
- Docker, Docker Compose plugin, Git, `curl`, `jq`, `openssl`, and `envsubst` available on the host.
- Proton VPN Plus or Unlimited subscription for port forwarding support.

## Quickstart
1. Install dependencies:
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose-plugin git curl jq openssl gettext-base
   ```

2. Clone the repo and enter it:
   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrbash.git
   cd arrbash
   ```

3. Prepare credentials and overrides (keep them outside the repo):
   ```bash
   mkdir -p ../arrconfigs
   cp arrconf/proton.auth.example ../arrconfigs/proton.auth
   cp arrconf/userr.conf.example ../arrconfigs/userr.conf
   chmod 600 ../arrconfigs/proton.auth ../arrconfigs/userr.conf
   ```
   Edit `../arrconfigs/proton.auth` for `PROTON_USER`/`PROTON_PASS` and `../arrconfigs/userr.conf` for `LAN_IP`, download paths, and any toggles you want.

4. Run the installer:
   ```bash
   ./arr.sh --yes        # omit --yes for interactive confirmation
   ```
   The script renders `.env` from `scripts/.env.template` via `scripts/gen-env.sh`, writes `docker-compose.yml`, and starts the stack. Rerun it after updating `userr.conf`; never edit generated files directly.

5. Access services using the summary printed by the installer (for example `http://192.168.1.50:8082` for qBittorrent).

## Configuration basics
- Defaults live in `arrconf/userr.conf.defaults.sh`; your overrides live in `${ARRCONF_DIR}/userr.conf` (defaults to `${ARR_DATA_ROOT}/${STACK}configs/userr.conf`).
- Effective precedence is `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`.
- Key values to set first:
  - `LAN_IP` – host LAN address.
  - `ARR_DATA_ROOT` – base path for generated assets (defaults to `~/srv`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`, `MUSIC_DIR` – storage locations.
  - `SPLIT_VPN` – `1` to keep only qBittorrent inside Gluetun.
  - `ENABLE_CONFIGARR`, `SABNZBD_ENABLED` – toggle optional services.
- Rotate Gluetun credentials anytime with:
  ```bash
  ./arr.sh --rotate-api-key --yes
  ```

## Everyday commands
- Show flags and options: `./arr.sh --help`
- Refresh generated files after edits: `./arr.sh --yes`
- Uninstall and clean generated assets: `./arr.sh --uninstall`
- Load helper aliases after the first run:
  ```bash
  source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr"
  arr.vpn.status
  arr.logs
  arr.open
  ```

## Documentation
- [Usage](./docs/usage.md) – installation details, configuration layers, options, and helper commands.
- [Architecture](./docs/architecture.md) – how templates render into compose and env files.
- [Networking](./docs/networking.md) – VPN modes, Proton port forwarding, and SABnzbd placements.
- [Troubleshooting](./docs/troubleshooting.md) – quick checks for connectivity and VPN issues.

## License
[MIT](./LICENSE)

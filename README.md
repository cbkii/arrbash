# arrbash

Self-host the *arr stack with Proton VPN port forwarding on a Debian-based host.

## What you get
- qBittorrent running through Gluetun with automatic Proton port forwarding.
- Sonarr, Radarr, Prowlarr, Bazarr, and FlareSolverr on the LAN bridge.
- Optional extras: Caddy HTTPS proxy, local DNS resolver, Configarr sync, VueTorrent WebUI.

## Prerequisites
- 64-bit Debian 12 (Bookworm) or equivalent with a static LAN IP, 4 CPU cores, and 4 GB RAM.
- Proton VPN Plus or Unlimited subscription for port forwarding support.

## Quick start
1. **Install dependencies.**
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose-plugin git curl jq openssl
   ```
   > The installer expects these dependencies to be present already; it does not install Docker, Compose, or CLI tools on your behalf.
2. **Clone arrbash and enter the directory.**
    ```bash
    mkdir -p ~/srv && cd ~/srv
    git clone https://github.com/cbkii/arrbash.git
    cd arrbash
    ```
3. **Add Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth    # set PROTON_USER and PROTON_PASS (the script appends +pmp)
   chmod 600 arrconf/proton.auth
   ```
4. **Create your overrides.**
   ```bash
   cp arrconf/userr.conf.example ../userr.conf
   nano ../userr.conf          # set LAN_IP, DOWNLOADS_DIR, COMPLETED_DIR, MEDIA_DIR
   ```
5. **Run the installer.**
   ```bash
   ./arr.sh --yes         # omit --yes for interactive mode
   ```
  The script installs prerequisites, renders `.env` and `docker-compose.yml`, and starts the stack. Rerun it anytime after editing `userr.conf`. The installer automatically searches the repo's parent directory and uses the first `userr.conf` it finds there (for example `../userr.conf` or `../arrconfigs/userr.conf`), so keep only the copy you want applied.
6. **Access services.** Use the summary printed by the installer or browse to `http://LAN_IP:PORT` (for example `http://192.168.1.50:8082` for qBittorrent).

## Minimal configuration
- `ARR_DATA_ROOT`: top-level data directory for the stack (defaults to `~/srv`). Override it via the environment or `userr.conf` before running `./arr.sh`.
- `userr.conf` defaults to `${ARR_BASE:-$ARR_DATA_ROOT}/userr.conf`; keep it outside version control. If multiple overrides live alongside the repo, the installer loads the first file named `userr.conf` it finds above the repo.
- Review these core values:
  - `LAN_IP`: private address of the host; required before ports are exposed.
- `STACK`: project label used for generated paths and logs (defaults to `arr` via `STACK="${STACK:-arr}"`).
- `ARR_BASE`: base directory for generated files (defaults to `ARR_DATA_ROOT`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`: map to your storage paths.
  - `SPLIT_VPN`: set to `1` to tunnel only qBittorrent; leave `0` for full VPN mode.
  - `ENABLE_CADDY`, `ENABLE_LOCAL_DNS`, `ENABLE_CONFIGARR`: toggle optional HTTPS/DNS/Configarr services.
- Secrets such as `QBT_USER`, `QBT_PASS`, and `GLUETUN_API_KEY` persist across runs. Rotate them with `./arr.sh --rotate-api-key` or `./arr.sh --rotate-caddy-auth`.
- Show available flags at any time:
  ```bash
  ./arr.sh --help
  ```

### Minimum tested container versions (2024-08-25)
- `qmcgaw/gluetun:v3.40.0`
- `lscr.io/linuxserver/qbittorrent:5.1.2-r2-ls415`
- `lscr.io/linuxserver/sonarr:4.0.15.2941-ls291`
- `lscr.io/linuxserver/radarr:5.27.5.10198-ls283`
- `ghcr.io/flaresolverr/flaresolverr:v3.3.21`
- `caddy:2.8.4`
- `4km3/dnsmasq:2.90-r3`

> LinuxServer.io apps that default to `:latest` (Prowlarr, Bazarr, SABnzbd, Configarr) remain unpinned; override them in `userr.conf` if you need to lock a tag.
## Next steps
- Read [Configuration](./docs/configuration.md) for variable precedence and permission profiles.
- Follow [Networking](./docs/networking.md) before enabling split VPN, local DNS, or HTTPS.
- Keep [Operations](./docs/operations.md) nearby for helper scripts, rotation commands, and rerun guidance.
- Review [Security](./docs/security.md) prior to exposing services beyond your LAN.
- Bookmark [Troubleshooting](./docs/troubleshooting.md) for recovery steps.

## First-run checklist
- Confirm `LAN_IP` points at your host (run `hostname -I | awk '{print $1}'` if unsure).
- Rotate qBittorrent credentials and update `QBT_USER`/`QBT_PASS` in `userr.conf`.
- Verify Proton port forwarding is active (summary should show a forwarded port or follow the Gluetun recovery steps if it fails).
- Decide whether local DNS or direct LAN exposure is appropriate for your environment.
- Spot-check published ports with `ss -tulpn` to ensure only expected services listen on the LAN.

### SABnzbd (Usenet Downloader)

SABnzbd integration is optional.

Enable in your user config (for example `${ARR_BASE}/userr.conf`):

```bash
SABNZBD_ENABLED=1
# Optional overrides (see docs/sabnzbd.md for the full matrix)
SABNZBD_PORT=8080          # Host port for the WebUI (qBittorrent now defaults to 8082)
SABNZBD_HOST="${LOCALHOST_IP}"  # Host sab-helper uses (defaults to LOCALHOST_IP)
SABNZBD_CATEGORY="${STACK}" # Category assigned to helper-submitted jobs
SABNZBD_TIMEOUT=15         # Helper/API timeout in seconds
# Set SABNZBD_IMAGE=lscr.io/linuxserver/sabnzbd:latest to pin an alternate container tag
```

After your first SABnzbd login, paste the API key into the WebUI once; reruns will hydrate
`SABNZBD_API_KEY` from `sabnzbd.ini` automatically.

To enable SABnzbd for a single installer run without editing `userr.conf`, pass `--enable-sab`:

```bash
./arr.sh --enable-sab --yes
```

Refer to [docs/sabnzbd.md](docs/sabnzbd.md) for networking scenarios, API key preservation,
and helper usage tips.

Run:

```bash
./arr.sh --yes
```

Helper:

```bash
scripts/sab-helper.sh status
scripts/sab-helper.sh add-file /path/to/file.nzb
```

VPN note:
By default SAB runs outside the VPN (TLS to Usenet servers). Enable `SABNZBD_USE_VPN=1` for full tunnelling through Gluetun.
If Gluetun is disabled, the stack logs a warning and runs SAB directly so downloads continue.

## Documentation index
- [Architecture](./docs/architecture.md) – container map, generated files, and installer flow.
- [Configuration](./docs/configuration.md) – precedence, core variables, and permission modes.
- [Networking](./docs/networking.md) – VPN modes, port forwarding, DNS, and HTTPS guidance.
- [Operations](./docs/operations.md) – script reference, aliases, and recurring tasks.
- [Security](./docs/security.md) – credential handling, exposure guidance, and verification checks.
- [Troubleshooting](./docs/troubleshooting.md) – diagnostic steps and targeted fixes.
- [Version management](./docs/version-management.md) – process for adjusting image tags safely.
- [FAQ](./docs/faq.md) and [Glossary](./docs/glossary.md) – quick answers and terminology.

## Support & contributions
Open an issue or PR for bugs or documentation gaps. Review `./arr.sh --help` and the docs before filing reports to confirm behaviour.

## License
[MIT](./LICENSE)

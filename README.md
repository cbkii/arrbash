# arrbash

Set up the *arr media stack with Proton VPN port forwarding on a Debian-based host.

## What you get
- qBittorrent routed through Gluetun with Proton VPN port forwarding.
- Sonarr, Radarr, Prowlarr, Bazarr, and FlareSolverr on the LAN bridge.
- Optional extras: Caddy HTTPS proxy, local DNS resolver, Configarr sync, SABnzbd downloader, and the VueTorrent WebUI.

## Prerequisites
- 64-bit Debian 12 (Bookworm) or equivalent with a static LAN IP, 4 CPU cores, and 4 GB RAM.
- Proton VPN Plus or Unlimited subscription for port forwarding support.

## Quick start
1. **Install dependencies.**
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose-plugin git curl jq openssl
   ```
   > The installer expects these tools to be present already. It does not install Docker, Compose, or the helper CLIs for you.
2. **Clone arrbash and enter the directory.**
    ```bash
    mkdir -p ~/srv && cd ~/srv
    git clone https://github.com/cbkii/arrbash.git
    cd arrbash
    ```
3. **Add Proton credentials.**
   ```bash
   mkdir -p ../arrconfigs
   cp arrconf/proton.auth.example ../arrconfigs/proton.auth
   nano ../arrconfigs/proton.auth    # set PROTON_USER and PROTON_PASS (the script appends +pmp)
   chmod 600 ../arrconfigs/proton.auth
   ```
4. **Create your overrides.**
   ```bash
   cp arrconf/userr.conf.example ../arrconfigs/userr.conf
   nano ../arrconfigs/userr.conf     # set LAN_IP and point DOWNLOADS_DIR/COMPLETED_DIR/MEDIA_DIR to your storage
   ```
5. **Run the installer.**
   ```bash
   ./arr.sh --yes         # omit --yes for interactive mode
   ```
   > The script checks Docker, Compose, and helper tools, then regenerates `.env` from `.env.template` via `scripts/gen-env.sh` alongside `docker-compose.yml` and support files before starting the stack. Do not edit those generated files by hand—change `userr.conf` instead and rerun the installer. The installer looks under `${ARR_DATA_ROOT}` (depth 4) and then the repo's parent directory for the first `userr.conf` it finds, so keep only the copy you want applied.
  
6. **Access services.** Follow the summary printed by the installer or visit `http://LAN_IP:PORT` (for example `http://192.168.1.50:8082` for qBittorrent). See **First-Run Checklist** below.

## Minimal configuration
- `ARR_DATA_ROOT`: top-level data directory for the stack (defaults to `~/srv`). Override it via the environment or `userr.conf` before running `./arr.sh`.
- `ARRCONF_DIR`: configuration folder for Proton credentials and overrides (defaults to `${ARR_DATA_ROOT}/${STACK}configs`).
- `userr.conf` and `proton.auth` both live in `${ARRCONF_DIR}`. Keep them out of version control. If multiple overrides exist, the installer scans `${ARR_DATA_ROOT}` (depth 4) and then above the repo for the first `userr.conf` it finds.
- Configuration precedence is `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`. The later layers only apply when earlier ones do not set a value.
- Check these values first:
  - `LAN_IP`: private address of the host. Set this before exposing ports.
  - `STACK`: project label used for generated paths and logs (defaults to `arr`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`: defaults sit under `${ARR_DATA_ROOT}`, but point each one at your actual storage.
  - `SPLIT_VPN`: set to `1` to tunnel only qBittorrent. Leave `0` for full VPN mode.
  - `ENABLE_CADDY`, `ENABLE_LOCAL_DNS`, `ENABLE_CONFIGARR`, `SABNZBD_ENABLED`: toggle optional services. See [Optional services and containers](./docs/configuration.md#optional-services-and-containers) for tips.
- Secrets such as `QBT_USER`, `QBT_PASS`, and `GLUETUN_API_KEY` persist across runs. Rotate them with `./arr.sh --rotate-api-key` or `./arr.sh --rotate-caddy-auth`.
- Show available flags at any time:
  ```bash
  ./arr.sh --help
  ```

To remove the stack and clean up generated assets later, run:

```bash
./arr.sh --uninstall
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
- Review [Security](./docs/security.md) before exposing services beyond your LAN.
- Bookmark [Troubleshooting](./docs/troubleshooting.md) for recovery steps.

## First-run checklist
- Confirm `LAN_IP` points at your host (run `hostname -I | awk '{print $1}'` if unsure).
- Rotate qBittorrent credentials and update `QBT_USER`/`QBT_PASS` in `userr.conf`.
- Verify Proton port forwarding is active. The summary should show a forwarded port; follow the Gluetun recovery steps if it fails.
- Confirm optional services and containers match your plan (see [Optional services and containers](./docs/configuration.md#optional-services-and-containers)).
- Decide whether local DNS or direct LAN exposure fits your environment.
- Spot-check published ports with `ss -tulpn` to ensure only expected services listen on the LAN.
- Review [credential hygiene tips](./docs/security.md#credential-hygiene) so core logins and API keys stay rotated.

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

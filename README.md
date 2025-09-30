# arrstack-mini

Self-host the *arr stack with Proton VPN port forwarding on a Debian or Raspberry Pi 5 host in minutes.

## What you get
- Proton-enabled qBittorrent behind Gluetun with automatic port forwarding.
- Sonarr, Radarr, Prowlarr, Bazarr, and FlareSolverr on the LAN bridge.
- Optional extras: Caddy HTTPS proxy, local DNS, Configarr sync, VueTorrent WebUI.

## Prerequisites
- 64-bit Debian Bookworm host (Pi 5 recommended) with static LAN IP, 4 CPU cores, and 4 GB RAM.
- Proton VPN Plus or Unlimited account (required for port forwarding).
- Docker Engine + Compose plugin and basic CLI tools (`git`, `curl`, `jq`, `openssl`). Install them once:
  ```bash
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git curl jq openssl docker.io docker-compose-plugin
  ```

## Quick start
1. **Clone the repo.**
   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrstackmini.git
   cd arrstackmini
   ```
2. **Create Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth    # set PROTON_USER and PROTON_PASS (the script appends +pmp)
   chmod 600 arrconf/proton.auth
   ```
3. **Create your overrides.**
   ```bash
   cp arrconf/userr.conf.example ../userr.conf
   nano ../userr.conf          # at minimum set LAN_IP, DOWNLOADS_DIR, COMPLETED_DIR, MEDIA_DIR
   ```
4. **Run the installer.**
   ```bash
   ./arrstack.sh --yes         # omit --yes for interactive mode
   ```
   The script installs prerequisites, renders `.env`, `docker-compose.yml`, and starts the stack. Rerun it anytime after editing `userr.conf`.
5. **Load helper aliases (optional).**
   ```bash
   source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr"
   ```
   Helpers like `arr.vpn.status`, `arr.logs`, and `arr.vpn.port` become available in the current shell.
6. **Access the services.** Browse to `http://LAN_IP:PORT` (for example `http://192.168.1.50:8080` for qBittorrent). The installer prints a summary with exact URLs.

## Minimal configuration
- `userr.conf` lives at `${ARR_BASE:-$HOME/srv}/userr.conf`; keep it outside version control.
- Key values to review:
  - `LAN_IP`: private address of the host (stack refuses to expose ports until set).
  - `ARR_BASE`: base directory for data (defaults to `~/srv`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`: map to your storage paths.
  - `SPLIT_VPN`: set to `1` to tunnel only qBittorrent; leave `0` for full VPN mode.
  - `ENABLE_CADDY`, `ENABLE_LOCAL_DNS`: toggle optional HTTPS/DNS profiles (see [Networking](./docs/networking.md)).
- The installer preserves secrets such as `QBT_USER`, `QBT_PASS`, and `GLUETUN_API_KEY` between runs. Rotate them with `./arrstack.sh --rotate-api-key` or `./arrstack.sh --rotate-caddy-auth` when needed.
- View available flags at any time with:
  ```bash
  ./arrstack.sh --help
  ```

## Next steps
- Review [Configuration](./docs/configuration.md) for all supported variables and permission profiles.
- Read [Networking](./docs/networking.md) before enabling split VPN, local DNS, or HTTPS.
- Keep [Operations](./docs/operations.md) handy for helper scripts, rotation commands, and rerun guidance.
- Check [Security](./docs/security.md) prior to exposing services beyond your LAN.
- Use [Troubleshooting](./docs/troubleshooting.md) for common recovery steps.

## Documentation index
- [Architecture](./docs/architecture.md) – container map, generated files, and installer flow.
- [Configuration](./docs/configuration.md) – precedence, core variables, and permission modes.
- [Networking](./docs/networking.md) – VPN modes, port forwarding, DNS, and HTTPS guidance.
- [Operations](./docs/operations.md) – script reference, aliases, and recurring tasks.
- [Security](./docs/security.md) – credential handling, exposure guidance, and verification checks.
- [Troubleshooting](./docs/troubleshooting.md) – diagnosis steps and targeted fixes.
- [Version management](./docs/version-management.md) – safe process for adjusting image tags.
- [FAQ](./docs/faq.md) and [Glossary](./docs/glossary.md) – quick answers and terminology.

## Support & contributions
Open an issue or PR if you find bugs or documentation gaps. Run `./arrstack.sh --help` and the docs before filing reports to confirm behaviour. Follow repository coding standards when submitting changes.

## License
[MIT](./LICENSE)

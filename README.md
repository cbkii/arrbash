# arrbash

Self-host the *arr stack with Proton VPN port forwarding on a Debian-based host.

## What you get
- qBittorrent running through Gluetun with automatic Proton port forwarding.
- Sonarr, Radarr, Prowlarr, Bazarr, and FlareSolverr on the LAN bridge.
- Optional extras: Caddy HTTPS proxy, local DNS resolver, Configarr sync, VueTorrent WebUI.

## Prerequisites
- 64-bit Debian 12 (Bookworm) or equivalent with a static LAN IP, 4 CPU cores, and 4 GB RAM.
- Proton VPN Plus or Unlimited subscription for port forwarding support.
- Docker Engine with the Compose plugin, plus `git`, `curl`, `jq`, and `openssl` installed.

## Quick start
1. **Clone arrbash and enter the directory.**
   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrbash.git
   cd arrbash
   ```
2. **Add Proton credentials.**
   ```bash
   cp arrconf/proton.auth.example arrconf/proton.auth
   nano arrconf/proton.auth    # set PROTON_USER and PROTON_PASS (the script appends +pmp)
   chmod 600 arrconf/proton.auth
   ```
3. **Create your overrides.**
   ```bash
   cp arrconf/userr.conf.example ../userr.conf
   nano ../userr.conf          # set LAN_IP, DOWNLOADS_DIR, COMPLETED_DIR, MEDIA_DIR
   ```
4. **Run the installer.**
   ```bash
   ./arrstack.sh --yes         # omit --yes for interactive mode
   ```
   The script installs prerequisites, renders `.env` and `docker-compose.yml`, and starts the stack. Rerun it anytime after editing `userr.conf`.
5. **Access services.** Use the summary printed by the installer or browse to `http://LAN_IP:PORT` (for example `http://192.168.1.50:8080` for qBittorrent).

## Minimal configuration
- `userr.conf` lives at `${ARR_BASE:-$HOME/srv}/userr.conf`; keep it outside version control.
- Review these core values:
  - `LAN_IP`: private address of the host; required before ports are exposed.
  - `ARR_BASE`: base directory for generated files (defaults to `~/srv`).
  - `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MEDIA_DIR`: map to your storage paths.
  - `SPLIT_VPN`: set to `1` to tunnel only qBittorrent; leave `0` for full VPN mode.
  - `ENABLE_CADDY`, `ENABLE_LOCAL_DNS`, `ENABLE_CONFIGARR`: toggle optional HTTPS/DNS/Configarr services.
- Secrets such as `QBT_USER`, `QBT_PASS`, and `GLUETUN_API_KEY` persist across runs. Rotate them with `./arrstack.sh --rotate-api-key` or `./arrstack.sh --rotate-caddy-auth`.
- Show available flags at any time:
  ```bash
  ./arrstack.sh --help
  ```

## Next steps
- Read [Configuration](./docs/configuration.md) for variable precedence and permission profiles.
- Follow [Networking](./docs/networking.md) before enabling split VPN, local DNS, or HTTPS.
- Keep [Operations](./docs/operations.md) nearby for helper scripts, rotation commands, and rerun guidance.
- Review [Security](./docs/security.md) prior to exposing services beyond your LAN.
- Bookmark [Troubleshooting](./docs/troubleshooting.md) for recovery steps.

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
Open an issue or PR for bugs or documentation gaps. Review `./arrstack.sh --help` and the docs before filing reports to confirm behaviour.

## License
[MIT](./LICENSE)

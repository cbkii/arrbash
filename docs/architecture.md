# Architecture

[← Back to README](../README.md)

The installer renders configuration from Bash templates, writes stack files, and launches Docker containers for media automation and VPN routing.

## Core containers
| Service | Purpose | Default access |
| --- | --- | --- |
| Gluetun | Proton VPN tunnel and optional port forwarding worker. | Control API on `http://127.0.0.1:${GLUETUN_CONTROL_PORT}` (API key required). |
| qBittorrent | Torrent client routed through Gluetun. | `http://LAN_IP:${QBT_PORT}` (VueTorrent optional). |
| Sonarr / Radarr / Lidarr / Prowlarr / Bazarr | Media automation apps on the LAN bridge. | `http://LAN_IP:${SONARR_PORT}`, `:${RADARR_PORT}`, `:${LIDARR_PORT}`, etc. |
| FlareSolverr | Captcha solver used by indexers. | `http://LAN_IP:${FLARR_PORT}`. |
| Configarr (optional) | Keeps Sonarr/Radarr configuration in sync. | Headless; uses stored API keys. |
| SABnzbd (optional) | Usenet downloader. | Placement controlled by `SABNZBD_USE_VPN`; ports governed by `EXPOSE_DIRECT_PORTS`. |

arrbash no longer ships LAN DNS or HTTPS helpers. Services publish directly on LAN ports or through Gluetun when applicable.

## Generated files
`./arr.sh` writes artifacts into `${ARR_STACK_DIR}` and `${ARR_DOCKER_DIR}`:
- `.env` – rendered by `scripts/gen-env.sh` using `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`, then persisted for reuse.
- `docker-compose.yml` – service definitions, networks, health checks, and optional features keyed off `.env`.
- `.aliasarr` – helper alias definitions sourced in your shell.
- `${ARR_DOCKER_DIR}` – persistent application data, credentials, and Gluetun hooks.

Do not edit generated files directly; adjust `userr.conf` and rerun the installer instead.

### Template rendering rules
- `scripts/.env.template` is filtered through `# @if VAR` / `# @endif` guards so optional blocks (for example VPN helpers or SABnzbd) only emit when their controlling variables are truthy. `scripts/gen-env.sh` substitutes placeholders that survive filtering, writing `KEY=value` lines without wrapping quotes.
- `docker-compose.yml` is assembled from Bash templates that double-quote scalar values. Helper functions escape backslashes, quotes, and newlines so YAML stays valid even when credentials contain special characters. Optional services are feature-gated—when Configarr, SABnzbd, or VPN helpers are disabled, their sections and dependent environment variables are omitted.

## Installer flow
1. **Preflight** – checks dependencies, confirms Docker availability, validates Proton credentials, and ensures required ports are free before writing files.
2. **Defaults and overrides** – layers configuration as `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh` before rendering.
3. **File rendering** – creates directories with safe permissions, hydrates preserved secrets from existing `.env`, and writes compose/env files in atomic steps.
4. **Service start** – launches Gluetun first, waits for it to become healthy, then starts the optional Proton port-forwarding worker and brings up the remaining containers and extras.
5. **Summary** – prints URLs, credentials, and reminders such as updating *Arr download client hosts when split tunnel is active.

## Related topics
- [Usage](usage.md) – adjust installer inputs and flags.
- [Networking](networking.md) – VPN modes and port forwarding details.
- [Troubleshooting](troubleshooting.md) – diagnose startup issues.

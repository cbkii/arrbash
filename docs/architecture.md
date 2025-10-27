# Architecture

[← Back to README](../README.md)

The installer renders configuration from a few scripts, then launches Docker containers for media automation and VPN routing.

## Core containers
| Service | Purpose | Default access |
| --- | --- | --- |
| Gluetun | Proton VPN tunnel and port forwarding worker. | Control API on `http://127.0.0.1:${GLUETUN_CONTROL_PORT:-8000}` (API key required). |
| qBittorrent | Torrent client routed through Gluetun. | `http://LAN_IP:${QBT_PORT}` (VueTorrent optional). |
| Sonarr / Radarr / Lidarr / Prowlarr / Bazarr | Media automation apps on the LAN bridge. | `http://LAN_IP:${SONARR_PORT}`, `:${RADARR_PORT}`, `:${LIDARR_PORT}`, etc. |
| FlareSolverr | Captcha solver service used by indexers. | `http://LAN_IP:${FLARR_PORT}`. |
| Configarr (optional) | Keeps Sonarr/Radarr configuration in sync. | Runs headless; configure via Configarr secrets. |
| Configarr (optional) | Keeps Sonarr/Radarr configuration in sync. | Runs headless; configure via Configarr secrets. |

> **Note:** arrbash no longer ships built-in LAN DNS or HTTPS helpers. Services publish directly on LAN ports or through Gluetun's forwarded ports.

## Generated files

## Generated files
`./arr.sh` writes artifacts into `${ARR_STACK_DIR}` and `${ARR_DOCKER_DIR}`:
- `.env` – rendered by `scripts/gen-env.sh` using `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`, then persisted for reuse across runs.
- `docker-compose.yml` – defines service profiles, networks, and health checks using the resolved values from `.env`.
- `.aliasarr` – helper alias definitions sourced in your shell.
- `${ARR_DOCKER_DIR}` – persistent application data, credentials, and Gluetun hooks.

Do not edit generated files directly. Adjust `userr.conf` and rerun the installer instead.

### Template rendering rules
- `.env.template` is filtered through `# @if VAR` / `# @endif` guards so optional blocks (for example VPN helpers or SABnzbd) only emit when their controlling variables resolve to a truthy value. `scripts/gen-env.sh` then substitutes only the placeholders that survived filtering, writing `KEY=value` lines without wrapping quotes. Any value that contains spaces, hashes, or shell-sensitive characters is emitted as-is because Compose reads the `.env` file literally.
- `docker-compose.yml` is assembled from Bash templates that always double-quote scalar values. Helper functions escape backslashes, double quotes, and newlines so the resulting YAML remains valid even when credentials or API keys contain special characters. Optional services are feature-gated—if Configarr, SABnzbd, or Gluetun extras are disabled, their sections and dependent environment variables are omitted entirely.

## Installer flow
1. **Preflight** – checks dependencies, confirms Docker availability, validates Proton credentials, and ensures required ports are free before writing files.
2. **Defaults and overrides** – layers configuration as `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh` before any files are rendered.
3. **File rendering** – creates directories with safe permissions, hydrates preserved secrets from existing `.env`, and writes compose/env files in atomic steps.
4. **Service start** – launches Gluetun first, waits for it to become healthy, then starts the asynchronous Proton port-forwarding worker (when enabled) and brings up the remaining containers and optional extras.
5. **Summary** – prints URLs, credentials, and reminders such as updating *Arr download client hosts when split tunnel is active.

Understanding this flow helps when troubleshooting. Rerunning the installer replays the pipeline and reconciles drift automatically.

## Related topics
- [Configuration](configuration.md) – adjust installer inputs.
- [Networking](networking.md) – understand VPN, DNS, and HTTPS behaviour.
- [Operations](operations.md) – command references.
- [Troubleshooting](troubleshooting.md) – diagnose startup issues.

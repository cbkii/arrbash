[← Back to README](../README.md)

# Architecture

This stack renders configuration from a small set of scripts, then launches Docker containers for media automation and VPN routing.

## Core containers
| Service | Purpose | Default access |
| --- | --- | --- |
| Gluetun | Proton VPN tunnel and port forwarding worker. | Control API on `http://127.0.0.1:${GLUETUN_CONTROL_PORT:-8000}` (API key required). |
| qBittorrent | Torrent client routed through Gluetun. | `http://LAN_IP:${QBT_PORT}` (VueTorrent optional). |
| Sonarr / Radarr / Prowlarr / Bazarr | Media automation apps on the LAN bridge. | `http://LAN_IP:${SONARR_PORT}`, `:${RADARR_PORT}`, etc. |
| FlareSolverr | Captcha solver service used by indexers. | `http://LAN_IP:${FLARR_PORT}`. |
| Configarr (optional) | Keeps Sonarr/Radarr configuration in sync. | Runs headless; configure via Configarr secrets. |
| Caddy (optional) | HTTPS reverse proxy with internal CA. | `https://<service>.<LAN_DOMAIN_SUFFIX>` with basic auth for remote access. |
| local_dns (optional) | dnsmasq-based resolver that answers `*.home.arpa`. | List the Pi as primary DNS on clients. |

The installer publishes LAN ports when `EXPOSE_DIRECT_PORTS=1`. When disabled, access services via Docker networks or the optional proxy.

## Generated files
`./arr.sh` writes artefacts into `${ARR_STACK_DIR}` and `${ARR_DOCKER_DIR}`:
- `.env` – rendered from defaults plus `${ARRCONF_DIR}/userr.conf`; reused across runs.
- `docker-compose.yml` – defines service profiles, networks, and health checks.
- `Caddyfile` – created when Caddy is enabled and validated with `caddy validate` before use.
- `.aliasarr` – helper alias definitions sourced in your shell.
- `docker-data/` – persistent application data, credentials, and Gluetun hooks.

Generated files should not be edited manually; adjust `userr.conf` and rerun the installer instead.

## Installer flow
1. **Preflight** – checks dependencies, confirms Docker availability, validates Proton credentials, and ensures required ports are free before writing files.
2. **Defaults and overrides** – sources `arrconf/userr.conf.defaults.sh`, applies environment variables, then your `${ARRCONF_DIR}/userr.conf` values.
3. **File rendering** – creates directories with safe permissions, hydrates preserved secrets from existing `.env`, and writes compose/env/proxy files in atomic steps.
4. **Service start** – launches Gluetun first, waits for port forwarding, then starts the remaining containers and optional extras.
5. **Summary** – prints URLs, credentials, and reminders such as updating *Arr download client hosts when split tunnel is active.

Understanding this flow helps when troubleshooting: re-running the installer replays the entire pipeline and reconciles drift automatically.

## Related topics
- [Configuration](configuration.md) – adjust installer inputs.
- [Networking](networking.md) – understand VPN, DNS, and HTTPS behaviour.
- [Operations](operations.md) – command references.
- [Troubleshooting](troubleshooting.md) – diagnose startup issues.

# Architecture

[← Back to README](../README.md)

This document explains how arrbash works internally: how the installer processes configuration, generates files, and launches the Docker stack.

______________________________________________________________________

## Overview

The `arr.sh` script is the main entry point. When you run it:

1. Loads configuration from defaults, user overrides, environment, and CLI flags
1. Validates dependencies and prerequisites
1. Generates `.env` and `docker-compose.yml` files
1. Creates directories with proper permissions
1. Starts Docker containers in the correct order

______________________________________________________________________

## Container services

The stack consists of these containers:

| Service | Image | Purpose | Network |
|---------|-------|---------|---------|
| **gluetun** | `qmcgaw/gluetun` | VPN tunnel using ProtonVPN. Provides network namespace for qBittorrent. | Host network for control API |
| **vpn-port-guard** | Uses gluetun's namespace | Monitors Gluetun's forwarded port and updates qBittorrent's listening port. | Shares gluetun |
| **qbittorrent** | `linuxserver/qbittorrent` | Torrent client. All traffic routed through Gluetun. | Shares gluetun |
| **sonarr** | `linuxserver/sonarr` | TV show automation. | `arr_net` bridge |
| **radarr** | `linuxserver/radarr` | Movie automation. | `arr_net` bridge |
| **lidarr** | `linuxserver/lidarr` | Music automation. | `arr_net` bridge |
| **prowlarr** | `linuxserver/prowlarr` | Indexer management for all \*arr apps. | `arr_net` bridge |
| **bazarr** | `linuxserver/bazarr` | Subtitle automation. | `arr_net` bridge |
| **flaresolverr** | `flaresolverr/flaresolverr` | Cloudflare captcha solver for indexers. | `arr_net` bridge |
| **sabnzbd** (optional) | `linuxserver/sabnzbd` | Usenet downloader. Placement controlled by `SABNZBD_USE_VPN`. | `arr_net` or shares gluetun |
| **configarr** (optional) | `raydak-labs/configarr` | Syncs TRaSH-Guides profiles to Sonarr/Radarr. | `arr_net` bridge |

### Service access

When `EXPOSE_DIRECT_PORTS=1` (default), services publish their WebUI ports on the host:

| Service | Default URL |
|---------|-------------|
| Gluetun Control API | `http://127.0.0.1:8000` (localhost only, requires API key) |
| qBittorrent | `http://LAN_IP:8080` |
| Sonarr | `http://LAN_IP:8989` |
| Radarr | `http://LAN_IP:7878` |
| Lidarr | `http://LAN_IP:8686` |
| Prowlarr | `http://LAN_IP:9696` |
| Bazarr | `http://LAN_IP:6767` |
| FlareSolverr | `http://LAN_IP:8191` |
| SABnzbd | `http://LAN_IP:8080` (when enabled) |

**Note**: arrbash does not provide DNS or HTTPS. Configure those separately with a reverse proxy if needed.

______________________________________________________________________

## Generated files

Running `./arr.sh` creates these files in `${ARR_STACK_DIR}` (default: `~/srv/arr`):

| File | Purpose | Editable? |
|------|---------|-----------|
| `.env` | Environment variables for Docker Compose | **No** – regenerated on each run |
| `docker-compose.yml` | Service definitions, networks, volumes | **No** – regenerated on each run |
| `.aliasarr` | Shell alias definitions | **No** – regenerated on each run |

Additionally, in `${ARR_DOCKER_DIR}` (default: `~/srv/arr/dockarr`):

| Directory | Contents |
|-----------|----------|
| `gluetun/` | VPN config, state files, port-guard status |
| `qbittorrent/` | qBittorrent config and data |
| `sonarr/`, `radarr/`, etc. | Application configs and databases |
| `configarr/` | Configarr secrets and generated profiles |

**Important**: Never edit generated files directly. Change `userr.conf` and re-run the installer.

______________________________________________________________________

## How the installer works

### Step 1: Configuration loading

The `main()` function in `arr.sh` processes configuration in this order:

1. **Defaults** (`arrconf/userr.conf.defaults.sh`) – Loaded first, provides all default values
1. **User config** (`${ARRCONF_DIR}/userr.conf`) – Overrides defaults
1. **Environment variables** – Exported vars override user config
1. **CLI flags** – Highest precedence (e.g., `--enable-sab` sets `SABNZBD_ENABLED=1`)

The precedence ensures you can always override any setting at runtime.

### Step 2: Preflight checks

Before generating files, the installer validates:

- Required commands are available (`docker`, `curl`, `jq`, `openssl`, `yq`, `python3`)
- Docker daemon is running
- Proton VPN credentials are present (in `proton.auth`)
- Required ports are available (or handles conflicts based on `ARR_PORT_CHECK_MODE`)
- Write permissions for target directories

### Step 3: File generation

#### `.env` generation

The `scripts/gen-env.sh` script:

1. Sources the configuration (defaults + user overrides)
1. Applies derived logic (port fallbacks, boolean normalization)
1. Reads `scripts/.env.template`
1. Processes conditional blocks (`# @if VAR` ... `# @endif`)
1. Runs `envsubst` to replace `${VAR}` placeholders
1. Writes the result to `${ARR_ENV_FILE}` with mode `0600`

**Template guards**: The template uses `# @if VAR` blocks to conditionally include sections:

```bash
# @if SABNZBD_ENABLED
SABNZBD_HOST=${SABNZBD_HOST}
SABNZBD_PORT=${SABNZBD_PORT}
# @endif
```

When `SABNZBD_ENABLED` is false/empty, these lines are omitted entirely.

#### `docker-compose.yml` generation

The compose file is assembled from Bash templates in `scripts/stack-compose.sh`:

- Service definitions are built dynamically based on enabled features
- YAML values are properly escaped (quotes, backslashes, newlines)
- Optional services (SABnzbd, Configarr) are gated by their enable flags
- Health checks and dependencies ensure correct startup order

### Step 4: Directory creation

The `mkdirs` function creates:

- `${ARR_STACK_DIR}` – Where compose files live
- `${ARR_DOCKER_DIR}` – Persistent container data
- `${ARR_LOG_DIR}` – Runtime logs
- Service-specific directories with appropriate permissions

Permissions follow `ARR_PERMISSION_PROFILE`:

- `strict` (default): secrets `600`, directories `700`
- `collab`: shared files `660`, directories `770`

### Step 5: Service startup

The `start_stack` function:

1. Starts **gluetun** first and waits for it to become healthy
1. Starts **vpn-port-guard** (monitors forwarded port)
1. Starts **qbittorrent** (waits for port-guard health)
1. Starts remaining services in parallel
1. Runs optional post-start tasks (API key sync, etc.)

Health checks ensure services don't start before their dependencies are ready.

______________________________________________________________________

## Key helper scripts

| Script | Purpose |
|--------|---------|
| `scripts/gen-env.sh` | Generates `.env` from template |
| `scripts/stack-compose.sh` | Generates `docker-compose.yml` |
| `scripts/vpn-port-guard.sh` | Polls Gluetun, syncs port to qBittorrent |
| `scripts/gluetun-api.sh` | Gluetun control API wrapper |
| `scripts/qbt-api.sh` | qBittorrent WebUI API wrapper |
| `scripts/stack-preflight.sh` | Pre-installation validation |
| `scripts/stack-apikeys.sh` | API key sync for Configarr |
| `scripts/gen-aliasarr.sh` | Generates shell aliases |

______________________________________________________________________

## Network architecture

### Default mode (`SPLIT_VPN=0`)

All services share Gluetun's network namespace. Traffic flows:

```
Internet ← VPN tunnel ← Gluetun ← all services
```

### Split tunnel mode (`SPLIT_VPN=1`)

Only qBittorrent (and optionally SABnzbd) use the VPN:

```
Internet ← VPN tunnel ← Gluetun ← qbittorrent
                                ↖ sabnzbd (if SABNZBD_USE_VPN=1)

Internet ← arr_net bridge ← sonarr, radarr, prowlarr, etc.
                          ↖ sabnzbd (if SABNZBD_USE_VPN=0)
```

Split mode is recommended because:

- \*arr apps can access metadata servers directly (faster)
- Troubleshooting is easier
- Only torrent/usenet traffic is VPN-protected

______________________________________________________________________

## Related documentation

- [Usage](usage.md) – Configuration options and CLI flags
- [Networking](networking.md) – VPN modes and port forwarding details
- [Troubleshooting](troubleshooting.md) – Common issues and fixes

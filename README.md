# arrbash

**arrbash** is a Bash-based installer that sets up a complete media automation stack on a Debian-based Linux host. It configures **qBittorrent** with VPN routing using either **wg-quick** (host-based WireGuard, default) or **Gluetun** (Docker-based) alongside the \*arr apps (Sonarr, Radarr, Lidarr, Prowlarr, Bazarr) for automated media management.

## What you get

- **qBittorrent** routed through a VPN tunnel with automatic ProtonVPN port forwarding for better torrent connectivity.
- Two VPN backend options:
  - **wg-quick** (default): Host-based WireGuard with automatic server rotation (8-48 hours)
  - **Gluetun**: Docker-based VPN container for those who prefer containerized VPN
- **Sonarr** (TV shows), **Radarr** (movies), **Lidarr** (music), **Prowlarr** (indexer management), **Bazarr** (subtitles), and **FlareSolverr** (captcha solving) accessible on your local network.
- **vpn-port-guard** – a helper service that keeps qBittorrent's listening port synchronized with ProtonVPN's forwarded port.
- Optional extras: **Configarr** (auto-syncs TRaSH-Guides quality profiles), **SABnzbd** (Usenet downloader), and **VueTorrent** (modern WebUI for qBittorrent).

## Prerequisites

- **Operating System**: 64-bit Debian 12 (Bookworm), Ubuntu 22.04+, or equivalent. A static/reserved LAN IP is strongly recommended.
- **Hardware**: Minimum 4 CPU cores and 4 GB RAM.
- **Software**: Docker, Docker Compose v2 plugin, Git, `curl`, `jq`, `openssl`, `yq`, `envsubst` (from `gettext-base`), and `python3`.
- **VPN**: ProtonVPN Plus or Unlimited subscription (required for port forwarding support).
- **For wg-quick backend** (default): `wireguard-tools`, `natpmpc` (or `libnatpmp-utils`), and root/sudo access.

## Quick start

Follow these steps to get the stack running. Each command should be copy-pasted into your terminal.

### Step 1: Install dependencies

#### For wg-quick backend (default, recommended)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git curl jq openssl gettext-base python3 wireguard-tools
```

Install natpmpc for ProtonVPN port forwarding:

```bash
# Debian/Ubuntu
sudo apt install -y libnatpmp-utils
```

#### For Gluetun backend (Docker-based)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git curl jq openssl gettext-base python3
```

If you need `yq`, install it separately (it's not in the default Debian repos):

```bash
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/local/bin/yq
```

### Step 2: Clone the repository

Create a working directory and clone arrbash:

```bash
mkdir -p ~/srv && cd ~/srv
git clone https://github.com/cbkii/arrbash.git
cd arrbash
```

### Step 3: Set up ProtonVPN WireGuard configs (wg-quick backend only)

If using the wg-quick backend (default), download ProtonVPN WireGuard configurations:

1. Log into your ProtonVPN account at https://account.protonvpn.com/
2. Go to Downloads → WireGuard configuration
3. Select servers and download configs with **NAT-PMP enabled** (required for port forwarding)
4. Place configs in `/etc/wireguard/proton/`:

```bash
sudo mkdir -p /etc/wireguard/proton
sudo mv ~/Downloads/*.conf /etc/wireguard/proton/
sudo chmod 600 /etc/wireguard/proton/*.conf
```

### Step 4: Set up configuration

Copy the example files to a separate config directory (this keeps your secrets outside the Git repo):

```bash
mkdir -p ~/srv/arrconfigs
cp arrconf/userr.conf.example ~/srv/arrconfigs/userr.conf
chmod 600 ~/srv/arrconfigs/userr.conf
```

Edit your configuration:

```bash
nano ~/srv/arrconfigs/userr.conf
```

At minimum, set:

- **`LAN_IP`**: Your machine's local IP address (e.g., `192.168.1.50`). Find it with `ip addr` or `hostname -I`.
- **`DOWNLOADS_DIR`** and **`MEDIA_DIR`**: Paths to your download and media storage.
- **`VPN_BACKEND`**: Set to `wg-quick` (default) or `gluetun`

**For Gluetun backend users**, also set up ProtonVPN credentials:

```bash
cp arrconf/proton.auth.example ~/srv/arrconfigs/proton.auth
chmod 600 ~/srv/arrconfigs/proton.auth
nano ~/srv/arrconfigs/proton.auth
```

Replace `your_protonvpn_username` and `your_protonvpn_password` with your actual ProtonVPN OpenVPN credentials.

### Step 5: Run the installer

```bash
sudo ./arr.sh --yes
```

**Note**: `sudo` is required for wg-quick backend to manage WireGuard interfaces. For Gluetun backend, `sudo` may still be needed for Docker operations depending on your setup.

This single command:

1. Reads your configuration from `~/srv/arrconfigs/userr.conf`.
1. Generates a `.env` file with all necessary settings.
1. Creates a `docker-compose.yml` file.
1. Starts the VPN connection (wg-quick) or VPN container (Gluetun).
1. Starts all application containers (Docker will download images on first run).

**Note**: Omit `--yes` if you want interactive confirmation prompts.

### Step 6: Access your services

Once the installer completes, it prints a summary with URLs for each service. Typical defaults:

| Service | URL |
|---------|-----|
| qBittorrent | `http://LAN_IP:8080` |
| Sonarr | `http://LAN_IP:8989` |
| Radarr | `http://LAN_IP:7878` |
| Lidarr | `http://LAN_IP:8686` |
| Prowlarr | `http://LAN_IP:9696` |
| Bazarr | `http://LAN_IP:6767` |
| FlareSolverr | `http://LAN_IP:8191` |

Replace `LAN_IP` with the IP you configured.

## Configuration

Configuration follows this precedence (highest to lowest):

1. **CLI flags** (e.g., `--enable-sab`)
1. **Exported environment variables** (e.g., `export SPLIT_VPN=1`)
1. **User config file** (`~/srv/arrconfigs/userr.conf` by default)
1. **Defaults** (`arrconf/userr.conf.defaults.sh`)

### Key settings to review

| Variable | Default | Description |
|----------|---------|-------------|
| `VPN_BACKEND` | `wg-quick` | VPN backend: `wg-quick` (host WireGuard) or `gluetun` (Docker container). |
| `LAN_IP` | (empty) | Your machine's LAN IP address. Required for service access. |
| `ARR_DATA_ROOT` | `~/srv` | Base path for all generated files and data. |
| `DOWNLOADS_DIR` | `~/Downloads` | Where qBittorrent saves active downloads. |
| `MEDIA_DIR` | `~/srv/media` | Root directory for your media library. |
| `SPLIT_VPN` | `0` | Set to `1` to route only qBittorrent through VPN (recommended). |
| `VPN_ROTATE_MIN_HOURS` | `8` | Minimum hours between automatic server rotations (wg-quick only). |
| `VPN_ROTATE_MAX_HOURS` | `48` | Maximum hours between automatic server rotations (wg-quick only). |
| `ENABLE_CONFIGARR` | `1` | Set to `0` to disable Configarr TRaSH sync. |
| `SABNZBD_ENABLED` | `0` | Set to `1` to enable the SABnzbd Usenet downloader. |

See `arrconf/userr.conf.example` for the full list of options.

## Switching VPN Backends

arrbash supports two VPN backends that can be switched between by updating your configuration.

### wg-quick (Host-based WireGuard, default)

**Advantages:**
- Faster and more lightweight (no Docker overhead)
- Automatic server rotation every 8-48 hours
- No dependency on Gluetun container lifecycle
- Direct ProtonVPN port forwarding via NAT-PMP

**Requirements:**
- `wireguard-tools` and `natpmpc` packages
- ProtonVPN WireGuard configs in `/etc/wireguard/proton/`
- Root/sudo access
- Configs must have NAT-PMP enabled for port forwarding

**Setup:**
1. Download WireGuard configs from ProtonVPN (with NAT-PMP)
2. Place in `/etc/wireguard/proton/*.conf`
3. Set `VPN_BACKEND="wg-quick"` in `userr.conf`
4. Run `sudo ./arr.sh --yes`

### Gluetun (Docker-based)

**Advantages:**
- No host-level network changes
- All VPN logic contained in Docker
- Well-suited for users uncomfortable with host network changes

**Requirements:**
- Docker and docker-compose
- ProtonVPN OpenVPN credentials in `proton.auth`

**Setup:**
1. Create `~/srv/arrconfigs/proton.auth` with OpenVPN credentials
2. Set `VPN_BACKEND="gluetun"` in `userr.conf`
3. Configure `SERVER_COUNTRIES` and optionally `SERVER_NAMES`
4. Run `./arr.sh --yes`

### Migrating between backends

To switch from one backend to another:

1. Stop the stack: `./arr.sh --uninstall` (or manually stop containers/VPN)
2. Update `VPN_BACKEND` in `~/srv/arrconfigs/userr.conf`
3. For wg-quick: Set up WireGuard configs (see above)
4. For Gluetun: Set up `proton.auth` credentials (see above)
5. Re-run the installer: `sudo ./arr.sh --yes`

**Note:** Your qBittorrent settings, *arr configurations, and media libraries are preserved during backend switches.

## CLI options

```
./arr.sh [options]

Options:
  --trace              Enable detailed tracing and write a log for debugging
  --yes                 Run non-interactively and assume yes to prompts
  --enable-sab          Enable SABnzbd for this run (sets SABNZBD_ENABLED=1)
  --rotate-api-key      Force regeneration of the Gluetun API key (Gluetun backend only)
  --sync-api-keys       Force Sonarr/Radarr/Prowlarr API key sync into Configarr secrets
  --no-auto-api-sync    Disable automatic Configarr API key sync for this run
  --refresh-aliases     Regenerate helper aliases and reload your shell
  --force-unlock        Remove an existing installer lock before continuing
  --uninstall           Remove the ARR stack and revert host changes
  --help                Show this help message
```

## Everyday commands

After the first run, load the helper aliases in your shell:

```bash
source ~/srv/arr/.aliasarr
```

Common aliases:

- `arr.vpn.status` – Check VPN connection status
- `arr.vpn.port` – Show the current forwarded port
- `arr.logs` – Tail container logs
- `arr.open` – Open service URLs in your browser

To apply configuration changes, re-run the installer:

```bash
./arr.sh --yes
```

To completely remove the stack and generated files:

```bash
./arr.sh --uninstall
```

## Documentation

- [Usage](./docs/usage.md) – Detailed installation, configuration, and operation guide.
- [Architecture](./docs/architecture.md) – How the installer works, generated files, and container structure.
- [Networking](./docs/networking.md) – VPN modes, port forwarding, and SABnzbd placement options.
- [Troubleshooting](./docs/troubleshooting.md) – Common issues and how to diagnose them.

## License

[MIT](./LICENSE)

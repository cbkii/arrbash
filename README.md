# arrbash

**arrbash** is a Bash-based installer that sets up a complete media automation stack on a Debian-based Linux host. It configures **qBittorrent** behind a **Gluetun** VPN container (using ProtonVPN) alongside the *arr apps (Sonarr, Radarr, Lidarr, Prowlarr, Bazarr) for automated media management.

## What you get

- **qBittorrent** routed through a VPN tunnel (Gluetun with ProtonVPN), with optional port forwarding for better torrent connectivity.
- **Sonarr** (TV shows), **Radarr** (movies), **Lidarr** (music), **Prowlarr** (indexer management), **Bazarr** (subtitles), and **FlareSolverr** (captcha solving) accessible on your local network.
- **vpn-port-guard** – a helper service that keeps qBittorrent's listening port synchronized with ProtonVPN's forwarded port.
- Optional extras: **Configarr** (auto-syncs TRaSH-Guides quality profiles), **SABnzbd** (Usenet downloader), and **VueTorrent** (modern WebUI for qBittorrent).

## Prerequisites

- **Operating System**: 64-bit Debian 12 (Bookworm), Ubuntu 22.04+, or equivalent. A static/reserved LAN IP is strongly recommended.
- **Hardware**: Minimum 4 CPU cores and 4 GB RAM.
- **Software**: Docker, Docker Compose v2 plugin, Git, `curl`, `jq`, `openssl`, `yq`, `envsubst` (from `gettext-base`), and `python3`.
- **VPN**: ProtonVPN Plus or Unlimited subscription (required for port forwarding support).

## Quick start

Follow these steps to get the stack running. Each command should be copy-pasted into your terminal.

### Step 1: Install dependencies

This command installs Docker and the other tools arrbash needs:

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

### Step 3: Set up your credentials and configuration

Copy the example files to a separate config directory (this keeps your secrets outside the Git repo):

```bash
mkdir -p ~/srv/arrconfigs
cp arrconf/proton.auth.example ~/srv/arrconfigs/proton.auth
cp arrconf/userr.conf.example ~/srv/arrconfigs/userr.conf
chmod 600 ~/srv/arrconfigs/proton.auth ~/srv/arrconfigs/userr.conf
```

Now edit your credentials:

```bash
nano ~/srv/arrconfigs/proton.auth
```

Replace `your_protonvpn_username` and `your_protonvpn_password` with your actual ProtonVPN OpenVPN credentials (found in your ProtonVPN account under "OpenVPN / IKEv2 username").

Then edit your configuration:

```bash
nano ~/srv/arrconfigs/userr.conf
```

At minimum, set:
- **`LAN_IP`**: Your machine's local IP address (e.g., `192.168.1.50`). Find it with `ip addr` or `hostname -I`.
- **`DOWNLOADS_DIR`** and **`MEDIA_DIR`**: Paths to your download and media storage.

### Step 4: Run the installer

```bash
./arr.sh --yes
```

This single command:
1. Reads your configuration from `~/srv/arrconfigs/userr.conf`.
2. Generates a `.env` file with all necessary settings.
3. Creates a `docker-compose.yml` file.
4. Starts all containers (Docker will download the images on first run).

**Note**: Omit `--yes` if you want interactive confirmation prompts.

### Step 5: Access your services

Once the installer completes, it prints a summary with URLs for each service. Typical defaults:

| Service | URL |
|---------|-----|
| qBittorrent | `http://LAN_IP:8082` |
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
2. **Exported environment variables** (e.g., `export SPLIT_VPN=1`)
3. **User config file** (`~/srv/arrconfigs/userr.conf` by default)
4. **Defaults** (`arrconf/userr.conf.defaults.sh`)

### Key settings to review

| Variable | Default | Description |
|----------|---------|-------------|
| `LAN_IP` | (empty) | Your machine's LAN IP address. Required for service access. |
| `ARR_DATA_ROOT` | `~/srv` | Base path for all generated files and data. |
| `DOWNLOADS_DIR` | `~/Downloads` | Where qBittorrent saves active downloads. |
| `MEDIA_DIR` | `~/srv/media` | Root directory for your media library. |
| `SPLIT_VPN` | `0` | Set to `1` to route only qBittorrent through VPN (recommended). |
| `ENABLE_CONFIGARR` | `1` | Set to `0` to disable Configarr TRaSH sync. |
| `SABNZBD_ENABLED` | `0` | Set to `1` to enable the SABnzbd Usenet downloader. |

See `arrconf/userr.conf.example` for the full list of options.

## CLI options

```
./arr.sh [options]

Options:
  --trace              Enable detailed tracing and write a log for debugging
  --yes                 Run non-interactively and assume yes to prompts
  --enable-sab          Enable SABnzbd for this run (sets SABNZBD_ENABLED=1)
  --rotate-api-key      Force regeneration of the Gluetun API key
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

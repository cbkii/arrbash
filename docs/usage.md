# Usage

[← Back to README](../README.md)

This guide covers installation, configuration, and daily operation of the arrbash media stack.

---

## Installation

### Prerequisites

Before installing, ensure your system has:

1. **Docker** and **Docker Compose v2** (the `docker compose` subcommand, not the legacy `docker-compose`)
2. **Git**, **curl**, **jq**, **openssl**, **yq**, **envsubst** (from `gettext-base`), and **python3**

Install on Debian/Ubuntu:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git curl jq openssl gettext-base python3
```

For `yq` (not in default repos):

```bash
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/local/bin/yq
```

### Step-by-step installation

1. **Clone the repository** into your working directory (the defaults assume `~/srv/arrbash`):

   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrbash.git
   cd arrbash
   ```

2. **Create your configuration directory** outside the repo to keep secrets separate:

   ```bash
   mkdir -p ~/srv/arrconfigs
   ```

3. **Copy the example files** and set secure permissions:

   ```bash
   cp arrconf/proton.auth.example ~/srv/arrconfigs/proton.auth
   cp arrconf/userr.conf.example ~/srv/arrconfigs/userr.conf
   chmod 600 ~/srv/arrconfigs/proton.auth ~/srv/arrconfigs/userr.conf
   ```

4. **Edit your VPN credentials** in `~/srv/arrconfigs/proton.auth`:

   ```bash
   nano ~/srv/arrconfigs/proton.auth
   ```

   Replace the placeholder values with your ProtonVPN OpenVPN username and password (found in your ProtonVPN account settings).

5. **Edit your configuration** in `~/srv/arrconfigs/userr.conf`:

   ```bash
   nano ~/srv/arrconfigs/userr.conf
   ```

   At minimum, set:
   - `LAN_IP` – Your machine's LAN IP address (find with `ip addr` or `hostname -I`)
   - `DOWNLOADS_DIR` – Where qBittorrent saves active downloads
   - `MEDIA_DIR` – Root of your media library

6. **Run the installer**:

   ```bash
   ./arr.sh --yes
   ```

   This command:
   - Validates your configuration and dependencies
   - Generates `.env` and `docker-compose.yml` files
   - Creates necessary directories with proper permissions
   - Starts all containers (first run downloads the Docker images)

   Omit `--yes` to see confirmation prompts before each major step.

---

## Configuration

### Configuration precedence

arrbash reads configuration from multiple sources. When the same variable is set in multiple places, the highest-precedence source wins:

1. **CLI flags** (highest) – e.g., `--enable-sab` sets `SABNZBD_ENABLED=1` for that run
2. **Exported environment variables** – e.g., `export SPLIT_VPN=1 && ./arr.sh`
3. **User config file** – `${ARRCONF_DIR}/userr.conf` (defaults to `~/srv/arrconfigs/userr.conf`)
4. **Defaults file** (lowest) – `arrconf/userr.conf.defaults.sh` in the repo

### Default paths

| Variable | Default value | Description |
|----------|---------------|-------------|
| `ARR_DATA_ROOT` | `~/srv` | Base directory for all arrbash data |
| `ARR_STACK_DIR` | `${ARR_DATA_ROOT}/arr` | Contains `docker-compose.yml`, `.env`, aliases |
| `ARRCONF_DIR` | `${ARR_STACK_DIR}configs` | User config and secrets directory |
| `ARR_DOCKER_DIR` | `${ARR_STACK_DIR}/dockarr` | Persistent container data volumes |
| `ARR_ENV_FILE` | `${ARR_STACK_DIR}/.env` | Generated environment file for Docker Compose |

### Essential settings

Edit these in your `userr.conf`:

| Variable | Default | Description |
|----------|---------|-------------|
| `LAN_IP` | (empty) | Your machine's local IP address. **Required** for web access. |
| `DOWNLOADS_DIR` | `~/Downloads` | qBittorrent active download location |
| `COMPLETED_DIR` | `${DOWNLOADS_DIR}/completed` | Completed downloads destination |
| `MEDIA_DIR` | `${ARR_DATA_ROOT}/media` | Root media library directory |
| `TV_DIR` | `${MEDIA_DIR}/Shows` | Sonarr TV library path |
| `MOVIES_DIR` | `${MEDIA_DIR}/Movies` | Radarr movie library path |
| `MUSIC_DIR` | `${MEDIA_DIR}/Music` | Lidarr music library path |
| `TIMEZONE` | `Australia/Sydney` | Container timezone (IANA format) |
| `PUID` | `$(id -u)` | User ID for container processes |
| `PGID` | `$(id -g)` | Group ID for container processes |

### Network settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLIT_VPN` | `0` | `0` = all services through VPN; `1` = only qBittorrent through VPN (recommended) |
| `EXPOSE_DIRECT_PORTS` | `1` | `1` = publish service ports on the host; `0` = internal only |
| `SERVER_COUNTRIES` | `Netherlands,Singapore` | ProtonVPN exit country preference list |
| `GLUETUN_CONTROL_PORT` | `8000` | Port for Gluetun's HTTP control API |
| `GLUETUN_CONTROL_BIND` | `all` | `all` = bind to 0.0.0.0; `loopback` = 127.0.0.1 only |

### Service ports

| Variable | Default | Description |
|----------|---------|-------------|
| `QBT_PORT` | `8080` | qBittorrent WebUI port |
| `SONARR_PORT` | `8989` | Sonarr WebUI port |
| `RADARR_PORT` | `7878` | Radarr WebUI port |
| `LIDARR_PORT` | `8686` | Lidarr WebUI port |
| `PROWLARR_PORT` | `9696` | Prowlarr WebUI port |
| `BAZARR_PORT` | `6767` | Bazarr WebUI port |
| `FLARR_PORT` | `8191` | FlareSolverr port |
| `SABNZBD_PORT` | `8081` | SABnzbd WebUI port (when enabled) |

### VPN port guard settings

The vpn-port-guard service keeps qBittorrent's listening port synchronized with ProtonVPN's forwarded port:

| Variable | Default | Description |
|----------|---------|-------------|
| `VPN_PORT_GUARD_POLL_SECONDS` | `15` | How often to check for port changes (seconds) |
| `VPN_PORT_GUARD_STATUS_TIMEOUT` | `90` | Max wait for status file at startup (seconds) |
| `CONTROLLER_REQUIRE_PF` | `false` | `true` = pause torrents if no forwarded port; `false` = continue anyway |

### Permissions

| Variable | Default | Description |
|----------|---------|-------------|
| `ARR_PERMISSION_PROFILE` | `strict` | `strict` = secrets 600, dirs 700; `collab` = 660/770 for shared access |

### API timeouts

Adjust these if you experience connectivity issues:

| Variable | Default | Description |
|----------|---------|-------------|
| `GLUETUN_API_TIMEOUT` | `10` | Gluetun control API timeout (seconds) |
| `GLUETUN_API_RETRY_COUNT` | `3` | Number of retry attempts |
| `GLUETUN_API_RETRY_DELAY` | `2` | Delay between retries (seconds) |
| `QBT_API_TIMEOUT` | `10` | qBittorrent API timeout (seconds) |
| `QBT_API_RETRY_COUNT` | `3` | Number of retry attempts |

---

## CLI flags

All available command-line options:

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
  --alias               Generate standalone .aliasarr file without stack updates
  --force-unlock        Remove an existing installer lock before continuing
  --preserve-config     Preserve existing service configs during re-run (safe update mode)
  --uninstall           Remove the ARR stack and revert host changes
  --help                Show this help message
```

### Examples

```bash
# Standard run (interactive)
./arr.sh

# Non-interactive run (for scripts/automation)
./arr.sh --yes

# Debug mode with full tracing
./arr.sh --trace --yes

# Force new Gluetun API key
./arr.sh --rotate-api-key --yes

# Temporarily enable SABnzbd
./arr.sh --enable-sab --yes

# Safe update mode - preserve existing configs
./arr.sh --preserve-config --yes

# Sync API keys to Configarr after changing them in the apps
./arr.sh --sync-api-keys --yes

# Remove the stack completely
./arr.sh --uninstall
```

---

## Optional services

### Configarr

Configarr syncs TRaSH-Guides quality profiles to Sonarr and Radarr automatically.

- Enabled by default (`ENABLE_CONFIGARR=1`)
- Set `ENABLE_CONFIGARR=0` in `userr.conf` to disable
- If you change API keys in Sonarr/Radarr/Prowlarr, run:
  ```bash
  ./arr.sh --sync-api-keys --yes
  ```

### SABnzbd (Usenet)

- Enable with `SABNZBD_ENABLED=1` in `userr.conf`
- Or temporarily with `./arr.sh --enable-sab`
- Control VPN routing:
  - `SABNZBD_USE_VPN=0` – SABnzbd on LAN bridge (reachable by *arr apps)
  - `SABNZBD_USE_VPN=1` – SABnzbd shares Gluetun's VPN tunnel

### VueTorrent WebUI

The modern VueTorrent interface for qBittorrent is included by default via the LinuxServer Docker mod:

- `QBT_DOCKER_MODS="ghcr.io/vuetorrent/vuetorrent-lsio-mod:latest"` – default, auto-installs VueTorrent
- Clear `QBT_DOCKER_MODS=""` to disable the mod

Access VueTorrent at `http://LAN_IP:8080/vuetorrent/` (note the trailing slash).

---

## Daily operations

### Loading helper aliases

After the first install, load the aliases in your shell:

```bash
source ~/srv/arr/.aliasarr
```

Add this line to your `~/.bashrc` or `~/.zshrc` to load automatically.

#### Standalone alias installation

You can generate the `.aliasarr` file without running the full stack installer:

```bash
./arr.sh --alias
```

This creates a runtime-config-aware alias file that:
- Automatically discovers configuration from your stack directory
- Reads `.env` and service config files on each sourcing
- Extracts API keys from `config.xml` files
- Honors `UrlBase` settings from service configs
- Provides clear error messages when config is missing

The generated file is standalone and has no template placeholders—it can be sourced independently even after moving it to a different location (though it will use that location as the stack directory).

### Useful aliases

**Service-specific helpers** (run `arr.<service>.help` for full list):

| Alias | Description |
|-------|-------------|
| `arr.rad.help` | Radarr API helpers and commands |
| `arr.son.help` | Sonarr API helpers and commands |
| `arr.lid.help` | Lidarr API helpers and commands |
| `arr.prow.help` | Prowlarr API helpers and commands |
| `arr.baz.help` | Bazarr API helpers and commands |
| `arr.qbt.help` | qBittorrent Web API helpers |
| `arr.sab.help` | SABnzbd API helpers (if enabled) |
| `arr.vpn.help` | Gluetun VPN control API helpers |
| `arr.pf.help` | Port forwarding helpers |
| `arr.flarr.help` | FlareSolverr helpers |

**Quick access examples:**

| Alias | Description |
|-------|-------------|
| `arr.rad.status` | Radarr system status (GET /api/v3/system/status) |
| `arr.son.status` | Sonarr system status (GET /api/v3/system/status) |
| `arr.qbt.version` | qBittorrent version |
| `arr.qbt.port.get` | Current qBittorrent listen port |
| `arr.vpn.status` | Check Gluetun VPN connection status |
| `arr.vpn.ip` | Show current exit IP address |
| `arr.pf.port` | Show current forwarded port number |
| `arr.pf.sync` | Sync Gluetun forwarded port to qBittorrent |
| `arr.logs <service>` | Tail logs from a specific container |
| `arr.restart <service>` | Restart a specific container |
| `arr.shell <service>` | Open interactive shell in container |

**Configuration and diagnostics:**

| Alias | Description |
|-------|-------------|
| `arr.config.sync` | Sync API keys to Configarr (if enabled) |
| `arr.help` | Show all available helpers |

### Re-running the installer

After editing `userr.conf`, re-run the installer to apply changes:

```bash
./arr.sh --yes
```

This regenerates configuration files and restarts affected services.

### Safe update mode (--preserve-config)

When re-running the installer on an existing installation, use `--preserve-config` to avoid overwriting your service configurations:

```bash
./arr.sh --preserve-config
```

**What gets preserved:**
- ✅ **Docker service configs** (`qBittorrent.conf`, arr settings xml) - completely untouched if it exists
- ✅ **Environment variables** (`.env`) - existing values are kept, new keys added
- ✅ **Timestamped backup** - critical files backed up to `${ARR_STACK_DIR}/.backups/YYYYMMDD-HHMMSS/`

**What still gets updated:**
- ✅ **Helper scripts** - bug fixes and improvements in `${ARR_STACK_DIR}/scripts/`
- ✅ **docker-compose.yml** - new service definitions and features
- ✅ **Aliases** (`.aliasarr`) - updated with new helpers

**When to use this flag:**
- You've made manual changes via qBittorrent WebUI (port, username, whitelist, etc.)
- You want to update scripts without risking config overwrites
- You're running on a production system and want minimal disruption
- Default values have changed between versions but you want to keep your settings

**Example workflow:**
```bash
# Initial installation
./arr.sh --yes

# Make changes via qBittorrent WebUI...
# (change port from 8080 to 8082, modify auth whitelist, etc.)

# Update scripts/features without overwriting configs
./arr.sh --preserve-config --yes
# Output: 📦 Backup created at: /home/user/srv/arr/.backups/20251211-143022/
```

### Rotating the Gluetun API key

For security, periodically rotate the API key:

```bash
./arr.sh --rotate-api-key --yes
```

---

## Diagnostics

### Health check scripts

Run these to verify your installation:

```bash
# Check dependencies and API connectivity
./scripts/stack-diagnostics.sh

# Get JSON-formatted health status
./scripts/stack-healthcheck.sh --format json
```

### Verify exposed ports

Check which ports are listening on your host:

```bash
sudo ss -tulpn | grep -E ':8080|:8989|:7878|:9696|:6767|:8191'
```

---

## Security best practices

1. **Keep secrets outside the repo**: Store `proton.auth` and `userr.conf` in `~/srv/arrconfigs/` (not in the cloned repo).

2. **File permissions**: The installer sets `.env` and credential files to mode `600` (owner read/write only).

3. **qBittorrent password**:
   - Default is `adminadmin` – change it immediately in the WebUI.
   - After changing in WebUI, update `QBT_PASS` in `userr.conf` to match, then re-run the installer.

4. **LAN whitelist**: When `LAN_IP` is set, the installer adds `LAN_IP/24` to `QBT_AUTH_WHITELIST`, allowing password-less access from your local network.

5. **Rotate API keys**: Periodically run `./arr.sh --rotate-api-key --yes` to generate new Gluetun credentials.

6. **Never commit secrets**: Ensure `.env`, `proton.auth`, and `userr.conf` are in your `.gitignore`.

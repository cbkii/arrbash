# AGENTS.md

## Purpose / Role of Agent

You are an AI coding agent for the `cbkii/arrbash` project. Your responsibilities include:

- Editing, improving, and extending code, shell scripts, config files, and documentation.
- Ensuring consistency between docs, examples, and code behaviour.
- Providing diffs or patches when making changes.
- Suggesting PR messages, structural improvements, and diagnostics.
- But **not** running live services (Docker compose up, host-level modifications) inside this environment. Those tasks are for a host machine.

______________________________________________________________________

## Repository Overview

### Entry script

- `arr.sh` — Main orchestrator that handles installation, configuration, and stack management.
- Flags: `--trace`, `--yes`, `--enable-sab`, `--rotate-api-key`, `--sync-api-keys`, `--no-auto-api-sync`, `--refresh-aliases`, `--force-unlock`, `--uninstall`, `--help`

### Config directory: `arrconf/`

This is the canonical source of configuration variables:

| File | Purpose |
|------|---------|
| `userr.conf.defaults.sh` | Default values for all configuration variables |
| `userr.conf.example` | Example user configuration file |
| `proton.auth.example` | Example ProtonVPN credentials file |

### Scripts directory: `scripts/`

Key helper scripts:

| Script | Purpose |
|--------|---------|
| `gen-env.sh` | Generates `.env` from template (authoritative env emission) |
| `.env.template` | Template with `${VAR}` placeholders and `# @if` guards |
| `stack-compose.sh` | Generates `docker-compose.yml` |
| `stack-common.sh` | Shared utility functions (`msg`, `warn`, `die`, etc.) |
| `stack-defaults.sh` | Runtime defaults and permission handling |
| `stack-preflight.sh` | Pre-installation validation |
| `vpn-port-guard.sh` | Port forwarding monitor controller |
| `vpn-gluetun.sh` | Gluetun API helpers |
| `gluetun-api.sh` | Low-level Gluetun control API wrapper |
| `qbt-api.sh` | qBittorrent WebUI API wrapper |
| `stack-apikeys.sh` | API key sync for Configarr |
| `gen-aliasarr.sh` | Shell alias generator |
| `stack-uninstall.sh` | Uninstallation handler |

### Documentation: `docs/`

| File | Content |
|------|---------|
| `usage.md` | Installation, configuration, and operation guide |
| `architecture.md` | System design and file generation |
| `networking.md` | VPN modes and port forwarding |
| `troubleshooting.md` | Problem diagnosis and fixes |
| `AGENTS.md` | This file - agent guidance |

______________________________________________________________________

## Configuration Precedence

Configuration is layered (highest to lowest precedence):

1. **CLI flags** — e.g., `--enable-sab` sets `SABNZBD_ENABLED=1`
1. **Exported environment variables** — e.g., `export SPLIT_VPN=1`
1. **User config file** — `${ARRCONF_DIR}/userr.conf` (default: `~/srv/arrconfigs/userr.conf`)
1. **Defaults file** — `arrconf/userr.conf.defaults.sh`

### Default paths

| Variable | Default |
|----------|---------|
| `ARR_DATA_ROOT` | `~/srv` |
| `ARR_STACK_DIR` | `${ARR_DATA_ROOT}/${STACK}` (default: `~/srv/arr`) |
| `ARRCONF_DIR` | `${ARR_STACK_DIR}configs` (default: `~/srv/arrconfigs`) |
| `ARR_DOCKER_DIR` | `${ARR_STACK_DIR}/dockarr` |
| `ARR_ENV_FILE` | `${ARR_STACK_DIR}/.env` |

______________________________________________________________________

## Env Generation Workflow

### Process

1. **Inputs**:

   - `arrconf/userr.conf.defaults.sh` (defaults)
   - `${ARRCONF_DIR}/userr.conf` (user overrides)
   - `scripts/.env.template` (placeholders + guards)
   - CLI flags and exported environment variables

1. **Generator** (`scripts/gen-env.sh`):

   - Sources defaults then user overrides
   - Applies derived logic (port fallbacks, boolean normalization)
   - Processes conditional blocks (`# @if VAR` ... `# @endif`)
   - Runs `envsubst` on surviving placeholders
   - Writes to `${ARR_ENV_FILE}` with mode `0600`

1. **Output format**:

   - `KEY=value` (no `export`, no wrapping quotes)
   - Compose reads values literally

### Template guards

Optional blocks use `# @if VAR` syntax:

```bash
# @if SABNZBD_ENABLED
SABNZBD_HOST=${SABNZBD_HOST}
SABNZBD_PORT=${SABNZBD_PORT}
# @endif
```

When `SABNZBD_ENABLED` is falsey, these lines are omitted entirely.

______________________________________________________________________

## Core Services

| Service | Image | Purpose |
|---------|-------|---------|
| gluetun | `qmcgaw/gluetun` | VPN tunnel (ProtonVPN) |
| vpn-port-guard | Uses gluetun namespace | Port forwarding monitor |
| qbittorrent | `linuxserver/qbittorrent` | Torrent client |
| sonarr | `linuxserver/sonarr` | TV automation |
| radarr | `linuxserver/radarr` | Movie automation |
| lidarr | `linuxserver/lidarr` | Music automation |
| prowlarr | `linuxserver/prowlarr` | Indexer management |
| bazarr | `linuxserver/bazarr` | Subtitle automation |
| flaresolverr | `flaresolverr/flaresolverr` | Captcha solver |
| sabnzbd (optional) | `linuxserver/sabnzbd` | Usenet downloader |
| configarr (optional) | `raydak-labs/configarr` | TRaSH profile sync |

______________________________________________________________________

## Naming Conventions

- **User config (canonical)**: `arrconf/userr.conf.defaults.sh` → `${ARRCONF_DIR}/userr.conf` (double 'r')
- **Scripts/helpers**: kebab-case filenames; shared helpers prefixed `arr_`
- **Variables**: uppercase `SNAKE_CASE` with service prefixes (`ARR_`, `GLUETUN_`, `QBT_`, `PROWLARR_`, etc.)
- **Compose/env artifacts**:
  - `scripts/.env.template` (tracked, hand-edited)
  - `.env` (generated, do not hand-edit)
- **Examples**: `*.example` suffix only (never commit real secrets)

______________________________________________________________________

## Coding Style & Conventions

- Use Bash with strict safety: `#!/usr/bin/env bash`, `set -Eeuo pipefail`
- Scripts should remain zsh-compatible where possible
- Check dependencies at runtime and fail with clear messages
- Permissions: secrets default to `600`; never commit real credentials
- Standalone helpers bootstrap with:
  ```bash
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
  ```
- Reuse shared helpers from `scripts/stack-common.sh` — don't reimplement `msg`, `warn`, `die`
- Quote variables in paths: `"${VAR}"` not `$VAR`
- Example/template files reflect defaults or placeholders only

______________________________________________________________________

## Key Variable Groups

### Paths and identity

`STACK`, `ARR_STACK_DIR`, `ARRCONF_DIR`, `ARR_DATA_ROOT`, `ARR_DOCKER_DIR`, `ARR_ENV_FILE`, `PUID`, `PGID`, `TIMEZONE`

### Media and downloads

`MEDIA_DIR`, `TV_DIR`, `MOVIES_DIR`, `MUSIC_DIR`, `SUBS_DIR`, `DOWNLOADS_DIR`, `COMPLETED_DIR`

### Network and VPN

`LAN_IP`, `LOCALHOST_IP`, `SPLIT_VPN`, `EXPOSE_DIRECT_PORTS`, `SERVER_COUNTRIES`, `PVPN_ROTATE_COUNTRIES`, `GLUETUN_API_KEY`, `GLUETUN_CONTROL_PORT`, `GLUETUN_CONTROL_BIND`

### VPN port guard

`VPN_PORT_GUARD_POLL_SECONDS`, `VPN_PORT_GUARD_STATUS_TIMEOUT`, `CONTROLLER_REQUIRE_PF`

### Service ports

Internal: `QBT_INT_PORT`, `SONARR_INT_PORT`, `RADARR_INT_PORT`, etc.
External: `QBT_PORT`, `SONARR_PORT`, `RADARR_PORT`, etc. (when `EXPOSE_DIRECT_PORTS=1`)

### qBittorrent

`QBT_USER`, `QBT_PASS`, `QBT_BIND_ADDR`, `QBT_ENFORCE_WEBUI`, `QBT_AUTH_WHITELIST`, `QBT_DOCKER_MODS`

### SABnzbd (when enabled)

`SABNZBD_ENABLED`, `SABNZBD_USE_VPN`, `SABNZBD_HOST`, `SABNZBD_INT_PORT`, `SABNZBD_PORT`, `SABNZBD_API_KEY`

### Configarr

`ENABLE_CONFIGARR`, `ARR_VIDEO_MIN_RES`, `ARR_VIDEO_MAX_RES`, `ARR_EP_MIN_MB`, `ARR_EP_MAX_GB`, etc.

______________________________________________________________________

## Testing & Validation

### Static checks

- `shellcheck` for all changed shell scripts
- `bash -n script.sh` for syntax validation

### Generator parity

```bash
# Remove .env and regenerate
rm -f ~/srv/arr/.env
./scripts/gen-env.sh scripts/.env.template ~/srv/arr/.env

# Verify file exists with correct permissions
ls -l ~/srv/arr/.env  # Should show -rw------- (600)
```

### Compose validation

```bash
docker compose config >/dev/null  # No unresolved placeholders
```

### CLI help

```bash
./arr.sh --help  # Should reflect current flags
```

______________________________________________________________________

## Agent Responsibilities

### May do

- Modify code, scripts, config, and docs
- Generate patches and suggestions
- Update example/template permissions
- Validate static correctness
- Consolidate duplicates into authoritative functions

### May not do

- Launch the full stack via Docker Compose
- Make host OS changes (DNS, services)
- Use real secrets/credentials
- Assume unrestricted network or host privileges
- Add parallel/duplicate logic to existing helpers

______________________________________________________________________

## Pull Request Guidelines

### Commit format

`<type>(<area>): short description`

Examples:

- `feat(env): add ENABLE_FOO guard to template`
- `fix(vpn): correct port-guard polling interval`
- `docs(usage): update CLI flag documentation`

### PR body

1. Summary of change
1. Impact / user-visible differences
1. Host actions required (e.g., "re-run `./arr.sh --yes`")
1. Static check results

______________________________________________________________________

## Security & Secrets

- Never commit real credentials
- Use placeholders (`*.example`) only
- Files containing secrets default to mode `600`
- API keys should stay out of repo; use loopback bindings by default

______________________________________________________________________

## Agent Priorities

1. **Correctness** — behavior matches docs and remains stable
1. **Clarity** — errors/help/docs are clear and concise
1. **Safety** — no secret leaks; cautious file modes
1. **Maintainability** — remove duplication; keep code small and cohesive
1. **Minimal assumptions** — operate within environment constraints

# SABnzbd Integration

This document expands on the optional SABnzbd support shipped with arrbash. It covers
networking behaviour, environment overrides, helper tooling, and the preservation
logic that keeps your API key and configuration safe across reruns.

## Network Modes

| Mode | `SABNZBD_USE_VPN` | Network namespace | Host port exposure | Notes |
| ---- | ----------------- | ----------------- | ------------------ | ----- |
| Direct (default) | `0` | `arr_net` (split VPN) or default bridge | Controlled by `EXPOSE_DIRECT_PORTS` / `SABNZBD_PORT` | Keeps SAB reachable by the *Arr containers. |
| Split-VPN direct | `0` | `arr_net` | Optional host mapping | Matches downloader connectivity expected by Sonarr/Radarr while qBittorrent remains tunneled. |
| VPN (opt-in) | `1` | Gluetun (`network_mode: "service:gluetun"`) | No host ports (shares Gluetun stack) | Use only when SAB must egress via the VPN. |

qBittorrent now defaults to WebUI port **8082** which frees 8080 for SABnzbd when
both containers share Gluetun. If you intentionally keep SAB in VPN mode, keep
its listen port at 8080 (the new qBittorrent default avoids the historical
collision).

## API Key Preservation

The preservation layer parses `${ARR_DOCKER_DIR}/sab/config/sabnzbd.ini` on reruns.
When `api_key = ...` is present and `.env` still contains the
`REPLACE_WITH_SABNZBD_API_KEY` placeholder, arrbash:

1. Takes a timestamped backup of `sabnzbd.ini` (`sabnzbd.ini.bak-YYYYmmdd-HHMMSS`).
2. Hydrates `SABNZBD_API_KEY` in-memory and records a preservation note for the
   summary output.
3. Writes the hydrated value back to `.env`, matching the qBittorrent credential
   behaviour.

When Configarr is enabled, the installer also ensures the `configarr/secrets.yml`
file contains a `SABNZBD_API_KEY` entry. Hydrated keys replace the
`REPLACE_WITH_SABNZBD_API_KEY` placeholder automatically; existing non-placeholder
values are left untouched.

If you manually rotate the API key, rerun `./arrstack.sh --yes` after SAB has
written the change; the installer will detect and capture the new value.

## Healthcheck Improvements

The compose generator now emits a simple JSON version probe that does **not**
require an API key:

```
http://127.0.0.1:<internal_port>/api?mode=version&output=json
```

A `start_period` of at least 60 seconds (or your configured `SABNZBD_TIMEOUT` if
higher) gives SAB time to bootstrap before health retries begin. The healthcheck
message inside `scripts/services.sh` has been updated accordingly.

## Configuration Overrides

Relevant environment variables:

- `SABNZBD_ENABLED` — enable/disable the service.
- `SABNZBD_USE_VPN` — route SABnzbd through Gluetun (`0` keeps it on arr_net).
- `SABNZBD_PORT` — host port when SAB runs directly on the LAN (default `8780`).
- `SABNZBD_URL` — helper target URL (default `http://localhost:8780`).
- `SABNZBD_TIMEOUT` — helper timeout *and* minimum healthcheck start period.
- `SABNZBD_CATEGORY` — optional category applied by `sab-helper.sh add-*` commands.
- `SABNZBD_IMAGE` — override the container image tag.

Example snippet for a VPN opt-in lab environment:

```bash
SABNZBD_ENABLED=1
SABNZBD_USE_VPN=1
EXPOSE_DIRECT_PORTS=0
SABNZBD_URL="http://sabnzbd:8080"   # qBittorrent now listens on 8082 inside Gluetun
```

> **Tip:** When forcing SAB through Gluetun, keep its listen port at 8080 or pick
> another value that does not clash with your qBittorrent container port.

> **Caddy note:** When SAB runs directly on the LAN (`SABNZBD_USE_VPN=0`) and
> you enable the Caddy reverse proxy, arrbash publishes
> `https://sabnzbd.${LAN_DOMAIN_SUFFIX}` automatically. VPN mode skips LAN port
> exposure, so you must access SAB through Gluetun in that configuration.

## Helper Script

`scripts/sab-helper.sh` ships with the stack and is automatically copied to
`${ARR_STACK_DIR}/scripts/sab-helper.sh` when SAB is enabled. Core commands:

```bash
./scripts/sab-helper.sh version   # Prints SAB version via the public API endpoint
./scripts/sab-helper.sh status    # Summarises queue state and download speed
./scripts/sab-helper.sh queue     # Raw queue JSON (requires API key)
./scripts/sab-helper.sh add-file <path/to/file.nzb>
./scripts/sab-helper.sh add-url <https://example/nzb>
```

After `./arrstack.sh --refresh-aliases`, the shell also exposes `sab-logs`,
`sab-shell`, and `open-sab` convenience aliases.

If SAB is disabled the helper prints a warning and exits gracefully. Ensure
`SABNZBD_URL` and `SABNZBD_API_KEY` are correct before using upload commands.
The helper will still report the SAB version even when the API key is not yet
configured, aligning with the new compose healthcheck.

## Deferred Features

`SABNZBD_CATEGORY` is passed through to helper uploads today but the stack does
not yet manage SAB categories automatically. Future hardening work will also look
at container resource limits (CPU, memory) and read-only filesystems; the compose
output includes a commented NOTE as a reminder.

For troubleshooting tips or examples, visit the main [Operations guide](operations.md).

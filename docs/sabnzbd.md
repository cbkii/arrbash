# SABnzbd Integration

This document expands on the optional SABnzbd support shipped with arrbash. It covers
networking behaviour, environment overrides, helper tooling, and the preservation
logic that keeps your API key and configuration safe across reruns.

## Network Modes

| Mode | `SABNZBD_USE_VPN` | `FORCE_SAB_VPN` | Network namespace | Host port exposure | Notes |
| ---- | ----------------- | --------------- | ----------------- | ------------------ | ----- |
| Direct (default) | `0` | `0` | `arr_net` (split VPN) or default bridge | Controlled by `EXPOSE_DIRECT_PORTS` / `SABNZBD_PORT` | Avoids qBittorrent port collisions and keeps SAB reachable by the *Arr containers. |
| Split-VPN direct | `0` | `0` | `arr_net` | Optional host mapping | Matches downloader connectivity expected by Sonarr/Radarr while qBittorrent remains tunneled. |
| VPN (opt-in) | `1` | `1` | Gluetun (`network_mode: "service:gluetun"`) | No host ports (shares Gluetun stack) | Only use when SAB must egress via the VPN. You **must** confirm SAB listens on a different internal port than qBittorrent. |

The installer now forces `SABNZBD_USE_VPN=0` unless `FORCE_SAB_VPN=1` is explicitly
set. This default prevents the long-standing internal port collision with
qBittorrent (both bind to 8080) when containers share Gluetun’s namespace. If you
opt back into the VPN path, review your SAB configuration and adjust its listen
port to avoid conflicts.

## API Key Preservation

The preservation layer parses `${ARR_DOCKER_DIR}/sab/config/sabnzbd.ini` on reruns.
When `api_key = ...` is present and `.env` still contains the
`REPLACE_WITH_SABNZBD_API_KEY` placeholder, arrbash:

1. Takes a timestamped backup of `sabnzbd.ini` (`sabnzbd.ini.bak-YYYYmmdd-HHMMSS`).
2. Hydrates `SABNZBD_API_KEY` in-memory and records a preservation note for the
   summary output.
3. Writes the hydrated value back to `.env`, matching the qBittorrent credential
   behaviour.

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
- `SABNZBD_USE_VPN` — request Gluetun networking (ignored unless
  `FORCE_SAB_VPN=1`).
- `FORCE_SAB_VPN` — advanced opt-in to keep SAB behind Gluetun; defaults to `0`.
- `SABNZBD_PORT` — host port when SAB runs directly on the LAN.
- `SABNZBD_URL` — helper target URL (default `http://localhost:8780`).
- `SABNZBD_TIMEOUT` — helper timeout *and* minimum healthcheck start period.
- `SABNZBD_CATEGORY` — optional category applied by `sab-helper.sh add-*` commands.
- `SABNZBD_IMAGE` — override the container image tag.

Example snippet for a VPN opt-in lab environment:

```bash
SABNZBD_ENABLED=1
SABNZBD_USE_VPN=1
FORCE_SAB_VPN=1
EXPOSE_DIRECT_PORTS=0
SABNZBD_URL="http://sabnzbd:8081"   # ensure SAB listens on a unique internal port
```

> **Tip:** When forcing SAB through Gluetun, change SAB’s listen port inside the
> WebUI (e.g., to 8081) before rerunning arrbash so qBittorrent and SAB do not
> clash inside the shared namespace.

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

If SAB is disabled the helper prints a warning and exits gracefully. Ensure
`SABNZBD_URL` and `SABNZBD_API_KEY` are correct before using upload commands.

## Deferred Features

`SABNZBD_CATEGORY` is passed through to helper uploads today but the stack does
not yet manage SAB categories automatically. Future hardening work will also look
at container resource limits (CPU, memory) and read-only filesystems; the compose
output includes a commented NOTE as a reminder.

For troubleshooting tips or examples, visit the main [Operations guide](operations.md).

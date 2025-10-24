[← Back to README](../README.md)

# Version management

Track container tags safely so `$STACK` installs stay reproducible (defaults to `arr`).

## Why
The stack pins each image to a tested tag. Registries occasionally remove old manifests; the helper scripts swap to `:latest` automatically for LinuxServer images when necessary.

## Current image guidance
| Service | Image | Recommended tag | Notes |
| --- | --- | --- | --- |
| Gluetun | `qmcgaw/gluetun` | `v3.40.0` | Keep pinned; controls VPN routing. |
| qBittorrent | `lscr.io/linuxserver/qbittorrent` | `5.1.2-r2-ls415` | Falls back to `:latest` if the pin disappears. |
| Sonarr | `lscr.io/linuxserver/sonarr` | `4.0.15.2941-ls291` | Installer switches to `:latest` when a tag vanishes. |
| Radarr | `lscr.io/linuxserver/radarr` | `5.27.5.10198-ls283` | Same fallback as Sonarr. |
| Lidarr | `lscr.io/linuxserver/lidarr` | `latest` | Floating tag to avoid churn. |
| Prowlarr | `lscr.io/linuxserver/prowlarr` | `latest` | Floating tag to avoid churn. |
| Bazarr | `lscr.io/linuxserver/bazarr` | `latest` | Floating tag to avoid churn. |
| FlareSolverr | `ghcr.io/flaresolverr/flaresolverr` | `v3.3.21` | Keep pinned to a stable release. |
| Caddy | `caddy` | `2.8.4` | Use upstream stable. |

## Update workflow
1. Back up your data:
   ```bash
   cd "${ARR_DATA_ROOT}"
   STACK="${STACK:-arr}"
   tar -czf "${STACK}-backup-$(date +%Y%m%d).tar.gz" \
     -C "$(dirname "${ARR_STACK_DIR:-${ARR_DATA_ROOT}/${STACK}}")" "$(basename "${ARR_STACK_DIR:-${STACK}}")" \
     -C "$(dirname "${ARR_DOCKER_DIR}")" "$(basename "${ARR_DOCKER_DIR}")"
   ```
2. Edit `${ARRCONF_DIR}/userr.conf` to change any `*_IMAGE` values.
3. Apply changes:
   ```bash
   ./arr.sh --yes
   ```
   The installer validates images and swaps LinuxServer pins to `:latest` if a tag is missing.
4. Confirm runtime:
   ```bash
   docker compose ps
   ```

## Recover from `manifest unknown`
1. Repair the generated `.env`:
   ```bash
   "${ARR_STACK_DIR}/scripts/fix-versions.sh"
   ```
2. Rerun the installer:
   ```bash
   ./arr.sh --yes
   ```
3. Pin to a new tag later if you need a specific release.

## Check tags manually
```bash
IMAGE="linuxserver/prowlarr"
curl -s "https://hub.docker.com/v2/repositories/${IMAGE}/tags/?page_size=10" |
  jq -r '.results[].name'
```

## Verify
List the images in use and confirm the expected tags appear:
```bash
docker compose images
```

## Related topics
- [Configuration](configuration.md) – edit `*_IMAGE` overrides.
- [Operations](operations.md) – rerun commands and helpers.
- [Security](security.md) – checks before exposing updated services.
- [Troubleshooting](troubleshooting.md) – container recovery steps.

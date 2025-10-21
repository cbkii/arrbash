[← Back to README](../README.md)

# Operations

Use these commands to run the installer safely, rotate credentials, and call helper scripts.

## Installer basics
- `./arr.sh` is idempotent. Rerun it after editing `${ARRCONF_DIR}/userr.conf`; the script regenerates `.env` from `.env.template` via `scripts/gen-env.sh` plus `docker-compose.yml`, the Caddyfile, and helper assets before starting containers. Do not edit those generated files manually—change `userr.conf` or use CLI flags instead. It only checks prerequisites, so install Docker and helper tools yourself first.
- Key flags (combine as needed):

  ```bash
  ./arr.sh --yes                 # non-interactive mode
  ./arr.sh --enable-caddy        # temporary toggle for ENABLE_CADDY=1
  ./arr.sh --enable-sab          # temporary toggle for SABNZBD_ENABLED=1
  ./arr.sh --rotate-api-key      # issue a new Gluetun API key
  ./arr.sh --rotate-caddy-auth   # generate new Caddy basic auth credentials
  ./arr.sh --sync-api-keys       # resync Sonarr/Radarr/Prowlarr keys into Configarr
  ./arr.sh --no-auto-api-sync    # skip automatic Configarr sync for one run
  ./arr.sh --force-unlock        # clear a stale installer lock (override concurrency guard)
  ./arr.sh --setup-host-dns      # run the host DNS takeover helper during install
  ./arr.sh --refresh-aliases     # rebuild .aliasarr
  ./arr.sh --uninstall           # stop services, remove assets, and restore host defaults
  ```

- The installer validates dependencies, checks port availability, and prints a summary before starting services. Cancel with `Ctrl+C` if something looks wrong and adjust `userr.conf` or your host configuration.
- `--uninstall` delegates to `scripts/uninstall.sh`, which tears down containers, removes generated stack files, re-enables `systemd-resolved`, and deletes installed Caddy trust material. Run it with `--yes` to skip the confirmation prompt.

## Helper aliases
After running `./arr.sh` at least once, load the generated aliases in new shells:
```bash
source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr"
```
Common helpers include:
- `arr.vpn.status` – display Gluetun health.
- `arr.vpn.port`, `arr.vpn.port.state`, `arr.vpn.port.watch` – inspect Proton port forwarding.
- `arr.logs` – follow stack logs.
- `arr.config.sync` – trigger Configarr after manual API key updates.
- `arr.vpn.auto.*` – manage the VPN auto-reconnect daemon.

Reload aliases whenever you rerun the installer.

## Targeted scripts
Run these from the repository root:

| Script | Purpose |
| --- | --- |
| `scripts/host-dns-setup.sh` | Disable `systemd-resolved`, install a static `/etc/resolv.conf`, and start the local DNS container when the host still owns port 53. |
| `scripts/host-dns-rollback.sh` | Restore the original resolver configuration. |
| `scripts/setup-lan-dns.sh` | Update `/etc/hosts`, Docker DNS settings, and LAN hostnames without full DNS takeover. |
| `scripts/install-caddy-ca.sh` | Install the Caddy root certificate into the host trust store (requires sudo). |
| `scripts/export-caddy-ca.sh` | Copy the public `root.crt` to a safe location for manual import. |
| `scripts/qbt-helper.sh` | Show or reset qBittorrent WebUI credentials and whitelist entries. |
| `scripts/doctor.sh` | Run the same port, DNS, HTTPS, and connectivity checks the installer performs. |
| `scripts/fix-versions.sh` | Swap pinned LinuxServer tags to `latest` when a registry removes a manifest. |
| `scripts/sab-helper.sh` | Submit downloads, check SAB status, or open a shell when SABnzbd is enabled. |

## Routine maintenance
1. Edit `${ARRCONF_DIR}/userr.conf` with new paths, credentials, or toggles.
2. Rerun `./arr.sh --yes` and review the summary for updated URLs and credentials.
3. Load `.aliasarr` and verify services:
   ```bash
   docker compose ps
   arr.vpn.status
   ```
4. Rotate secrets periodically using the dedicated flags or helpers (`--rotate-api-key`, `--rotate-caddy-auth`, `scripts/qbt-helper.sh reset`).

## SABnzbd helper

When `SABNZBD_ENABLED=1`, the installer copies `scripts/sab-helper.sh` into `${ARR_STACK_DIR}/scripts/` and refreshes handy aliases such as `sab-logs`, `sab-shell`, and `open-sab` (run `./arr.sh --refresh-aliases` if you need them immediately).

- View commands with `scripts/sab-helper.sh --help` or `sab-helper --help` from inside the stack directory.
- Common tasks: `status` (checks connectivity), `add-file` (upload an NZB), and `add-url` (submit a direct download link).
- The helper prints a gentle warning and exits if SABnzbd is disabled, so you always know why a request failed.
- Set `SABNZBD_HOST`, `SABNZBD_PORT`, and `SABNZBD_API_KEY` in `userr.conf` if you customised the WebUI or run SAB behind Gluetun.
- The helper reports SAB’s version even before the API key is stored, matching the container healthcheck described in the installer summary.
- For network placement advice, revisit [SABnzbd network placements](networking.md#sabnzbd-network-placements).

## Related topics
- [Configuration](configuration.md) – variable reference.
- [Networking](networking.md) – VPN, DNS, and HTTPS guidance.
- [Security](security.md) – exposure checks before publishing services.
- [Troubleshooting](troubleshooting.md) – follow-up when checks fail.

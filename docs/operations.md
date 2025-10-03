[← Back to README](../README.md)

# Operations

Use these commands to run the installer safely, rotate credentials, and call helper scripts.

## Installer basics
- `./arrstack.sh` is idempotent. Rerun it after editing `${ARR_BASE:-$HOME/srv}/userr.conf`; the script regenerates `.env`, `docker-compose.yml`, the Caddyfile, and helper assets before starting containers.
- Key flags (combine as needed):
  ```bash
  ./arrstack.sh --yes                 # non-interactive mode
  ./arrstack.sh --enable-caddy        # temporary toggle for ENABLE_CADDY=1
  ./arrstack.sh --enable-sab          # temporary toggle for SABNZBD_ENABLED=1
  ./arrstack.sh --rotate-api-key      # issue a new Gluetun API key
  ./arrstack.sh --rotate-caddy-auth   # generate new Caddy basic auth credentials
  ./arrstack.sh --sync-api-keys       # resync Sonarr/Radarr/Prowlarr keys into Configarr
  ./arrstack.sh --no-auto-api-sync    # skip automatic Configarr sync for one run
  ./arrstack.sh --setup-host-dns      # run the host DNS takeover helper during install
  ./arrstack.sh --refresh-aliases     # rebuild .aliasarr
  ```
- The installer validates dependencies, checks port availability, and prints a summary before starting services. Cancel with `Ctrl+C` if something looks wrong and adjust `userr.conf` or your host configuration.

## Helper aliases
After running `./arrstack.sh` at least once, load the generated aliases in new shells:
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

## Routine maintenance
1. Edit `${ARR_BASE}/userr.conf` with new paths, credentials, or toggles.
2. Rerun `./arrstack.sh --yes` and review the summary for updated URLs and credentials.
3. Load `.aliasarr` and verify services:
   ```bash
   docker compose ps
   arr.vpn.status
   ```
4. Rotate secrets periodically using the dedicated flags or helpers (`--rotate-api-key`, `--rotate-caddy-auth`, `scripts/qbt-helper.sh reset`).

## Related topics
- [Configuration](configuration.md) – variable reference.
- [Networking](networking.md) – VPN, DNS, and HTTPS guidance.
- [Security](security.md) – exposure checks before publishing services.
- [Troubleshooting](troubleshooting.md) – follow-up when checks fail.

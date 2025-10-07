[← Back to README](../README.md)

# Security

Keep the deployment private to your LAN and rotate credentials regularly.

## Secrets and permissions
- Leave `ARR_PERMISSION_PROFILE=strict` unless you need collaborative write access. Secrets stay at mode `600`, data directories at `700`, and the installer enforces `umask 0077`.
- When you switch to the `collab` profile, set `PGID` to the shared storage group so write access stays limited to expected members.
- Never commit `arrconf/proton.auth`, `.env`, or other generated files to version control. The installer keeps permissions tight automatically.

## Credential hygiene
- Change qBittorrent credentials after first login and copy the values into `${ARRCONF_DIR}/userr.conf` (`QBT_USER`, `QBT_PASS`). Rerun the installer so `.env` updates without manual edits.
- After your first SABnzbd login, copy the API key from SABnzbd's WebUI into your configuration (e.g., `.env`). The installer hydrates `SABNZBD_API_KEY` automatically on reruns when the placeholder remains in `.env`.
- Rotate the Gluetun API key periodically with `./arr.sh --rotate-api-key --yes` and restart the stack.
- Refresh Caddy basic auth with `./arr.sh --rotate-caddy-auth --yes` before sharing remote access.
- Keep the exported Caddy certificate bundle limited to the public `root.crt`. Never expose `docker-data/caddy` or private keys.

## Network exposure
- Bind the stack to a private `LAN_IP` and avoid forwarding raw service ports through your router. Use Caddy with strong credentials if you require remote access.
- When local DNS is enabled, ensure only trusted clients point at the arrbash host. Keep a fallback public resolver in DHCP to avoid outages if the host is offline.
- Enabling local DNS backs up `/etc/docker/daemon.json`, merges in `{ "userland-proxy": false }`, and requires a Docker restart before the change applies (use `scripts/host-dns-rollback.sh` to undo it).
- Verify open ports regularly:
  ```bash
  sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191|:80|:443|:53'
  ```
  Expect 80/443 only when Caddy is enabled and 53 only when local DNS is active.

## Updates and audits
- Review generated summaries from `./arr.sh` for unexpected URLs or credentials.
- Use `scripts/doctor.sh` to spot misconfigurations before exposing services outside the LAN.
- Before pushing changes, search the repo for accidental personal data or unofficial links:
  ```bash
  git grep -nE '(yourname|@|home\\.local)'
  ```

## Related topics
- [Configuration](configuration.md) – permission profile details.
- [Networking](networking.md) – Caddy, DNS, and VPN context.
- [Operations](operations.md) – rotation commands.
- [Troubleshooting](troubleshooting.md) – recovery steps.

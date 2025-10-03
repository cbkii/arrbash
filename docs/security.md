[← Back to README](../README.md)

# Security

Keep the deployment private to your LAN and rotate credentials regularly.

## Secrets and permissions
- Leave `ARR_PERMISSION_PROFILE=strict` unless you require collaborative write access. Secrets stay at mode `600`, data directories at `700`, and the installer enforces `umask 0077`.
- When using the `collab` profile, set `PGID` to the shared storage group so write access is limited to expected members.
- Never commit `arrconf/proton.auth`, `.env`, or other generated files to version control. The installer keeps permissions tight automatically.

## Credential hygiene
- Change qBittorrent credentials after first login and copy the values into `${ARR_BASE}/userr.conf` (`QBT_USER`, `QBT_PASS`). Rerun the installer so `.env` updates without manual edits.
- Rotate the Gluetun API key periodically with `./arrstack.sh --rotate-api-key --yes` and restart the stack.
- Refresh Caddy basic auth with `./arrstack.sh --rotate-caddy-auth --yes` before sharing remote access.
- Keep the exported Caddy certificate bundle limited to the public `root.crt`. Never expose `docker-data/caddy` or private keys.

## Network exposure
- Bind the stack to a private `LAN_IP` and avoid forwarding raw service ports through your router. Use Caddy with strong credentials if you require remote access.
- When local DNS is enabled, ensure only trusted clients point at the Pi. Keep a fallback public resolver in DHCP to avoid outages if the Pi is offline.
- Verify open ports regularly:
  ```bash
  sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191|:80|:443|:53'
  ```
  Expect 80/443 only when Caddy is enabled and 53 only when local DNS is active.

## Updates and audits
- Review generated summaries from `./arrstack.sh` for unexpected URLs or credentials.
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

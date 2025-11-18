# Security

[← Back to README](../README.md)

Keep the deployment private to your LAN and rotate credentials regularly.

## Secrets and permissions
- Leave `ARR_PERMISSION_PROFILE=strict` unless you need collaborative write access. Secrets stay at mode `600`, data directories at `700`, and the installer enforces `umask 0077`.
- When you switch to the `collab` profile, set `PGID` to the shared storage group so write access stays limited to expected members.
- Never commit `arrconf/proton.auth`, `.env`, or other generated files to version control. The installer keeps permissions tight automatically.

## Credential hygiene
- Change qBittorrent credentials after first login and copy the values into `${ARRCONF_DIR}/userr.conf` (`QBT_USER`, `QBT_PASS`). Rerun the installer so `.env` updates without manual edits.
- After your first SABnzbd login, copy the API key from SABnzbd's WebUI into your configuration (e.g., `.env`). The installer hydrates `SABNZBD_API_KEY` automatically on reruns when the placeholder remains in `.env`.
- Rotate the Gluetun API key periodically with `./arr.sh --rotate-api-key --yes`. The installer now persists a fresh key into `.env`, recreates Gluetun so the control server consumes it, and refreshes helper aliases. Verify the result with:
  ```bash
  grep '^GLUETUN_API_KEY=' .env
  curl -fsS -H "X-API-Key: $GLUETUN_API_KEY" "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/healthz"
  ```

## Network exposure
- Bind the stack to a private `LAN_IP` and avoid forwarding raw service ports through your router. Terminate HTTPS through your own VPN, SSH tunnel, or dedicated gateway if you need off-LAN access.
- Verify open ports regularly:
  ```bash
  sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191'
  ```
  Expect only the ports you explicitly expose on the LAN bridge.

## Updates and audits
- Review generated summaries from `./arr.sh` for unexpected URLs or credentials.
- Use `scripts/fix-doctor.sh` to spot misconfigurations before exposing services outside the LAN.
- Before pushing changes, search the repo for accidental personal data or unofficial links:
  ```bash
  git grep -nE '(yourname|@|home\\.local)'
  ```

## Related topics
- [Configuration](configuration.md) – permission profile details.
- [Networking](networking.md) – split tunnel and port forwarding context.
- [Operations](operations.md) – rotation commands.
- [Troubleshooting](troubleshooting.md) – recovery steps.

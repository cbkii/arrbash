[← Back to README](../README.md)

# port-manager sidecar

The optional `port-manager` container keeps qBittorrent’s listening port aligned with the ProtonVPN lease that Gluetun negotiates. It reads the forwarded-port file Gluetun maintains, falls back to the control API when necessary, and updates qBittorrent via its Web API.

## Quickstart
1. Set the toggle in your overrides:
   ```bash
   echo "PORT_MANAGER_ENABLE=1" >> ${ARRCONF_DIR}/userr.conf
   ```
2. Ensure the qBittorrent WebUI credentials and port in `.env`/`userr.conf` are correct (`QBT_USER`, `QBT_PASS`, `QBT_WEB_PORT`).
3. Rerun the installer:
   ```bash
   ./arr.sh --yes
   ```
4. Bring the stack back up. The generator creates a lightweight Alpine container that shares Gluetun’s network namespace, mounts `/tmp/gluetun` read-only, and runs `scripts/port-manager/pm-watch.sh`.

## Helper aliases
Source `.aliasarr` to gain quick access to the new helpers:

```bash
arr.pf.help      # overview of port-manager commands
arr.pf.port      # print the forwarded port (file first, control API fallback)
arr.pf.sync      # run a one-shot sync using pm-watch.sh logic
arr.pf.tail      # tail -f the forwarded port status file with timestamps
arr.pf.logs      # follow docker logs for the port-manager container
arr.pf.test 4444 # dry-run a qBittorrent update to a specific port
```

## Security notes
- `port-manager` runs inside Gluetun’s namespace (`network_mode: "service:gluetun"`), so it never exposes ports on the LAN by itself.
- The container mounts the forwarded-port volume read-only and talks to qBittorrent over `127.0.0.1` within Gluetun.
- Gluetun’s control server stays bound to `127.0.0.1` and requires `GLUETUN_API_KEY`. Do not remap it to your LAN.

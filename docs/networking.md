# Networking

[← Back to README](../README.md)

This document explains the VPN tunnel modes, ProtonVPN port forwarding, and SABnzbd placement options.

---

## VPN modes

arrbash supports two network configurations controlled by `SPLIT_VPN`:

| Mode | Setting | What happens | Best for |
|------|---------|--------------|----------|
| **Full tunnel** | `SPLIT_VPN=0` | All services share Gluetun's VPN network. Everything goes through the VPN tunnel. | Maximum privacy; all traffic protected. |
| **Split tunnel** | `SPLIT_VPN=1` | Only qBittorrent (and optionally SABnzbd) use the VPN. The *arr apps connect directly to the internet. | **Recommended**. Faster metadata lookups, easier troubleshooting. |

### Changing modes

1. Edit `userr.conf` and set `SPLIT_VPN=1` (or `0`)
2. Optionally set `EXPOSE_DIRECT_PORTS=1` to publish WebUI ports on your LAN
3. Re-run the installer:
   ```bash
   ./arr.sh --yes
   ```

### Split tunnel considerations

When using split tunnel mode (`SPLIT_VPN=1`):

- **Download client configuration**: In Sonarr, Radarr, and Lidarr, configure the download client host as `http://LAN_IP:8082` (your machine's LAN IP, not `localhost`). qBittorrent is only reachable via the LAN address when split.

- **Port exposure**: Set `EXPOSE_DIRECT_PORTS=1` to publish service ports on the host. Without this, services only listen on their internal Docker network.

---

## ProtonVPN port forwarding

ProtonVPN supports NAT-PMP port forwarding on certain servers. This allows incoming connections to your torrents, improving download speeds and connectivity.

### How it works

1. **Gluetun** connects to ProtonVPN using your credentials.
2. ProtonVPN assigns a **forwarded port** (this port can change between sessions).
3. **vpn-port-guard** detects the forwarded port by polling Gluetun's control API.
4. The guard updates qBittorrent's listening port to match.
5. Status is written to `${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`.

### Requirements

- ProtonVPN **Plus** or **Unlimited** subscription (free accounts don't support port forwarding)
- OpenVPN credentials with the `+pmp` suffix (arrbash adds this automatically)
- Server selection that includes P2P-capable servers

### Configuration

Port forwarding is enabled automatically when using ProtonVPN. The relevant settings in `userr.conf`:

| Variable | Default | Description |
|----------|---------|-------------|
| `VPN_PORT_GUARD_POLL_SECONDS` | `15` | How often vpn-port-guard checks for port changes |
| `VPN_PORT_GUARD_STATUS_TIMEOUT` | `90` | Max seconds to wait for status file at startup |
| `CONTROLLER_REQUIRE_PF` | `false` | If `true`, pause torrents when no port is forwarded |

### The vpn-port-guard service

This sidecar container:

1. Polls Gluetun's control API every `VPN_PORT_GUARD_POLL_SECONDS` seconds
2. Reads the current forwarded port from `/tmp/gluetun/forwarded_port`
3. If the port changed, updates qBittorrent via its WebUI API
4. Writes atomic status to `port-guard-status.json`

The service has its own health check that verifies:
- The status file exists and was updated recently
- Gluetun's control API is responding
- qBittorrent's API is accessible

qBittorrent waits for vpn-port-guard to become healthy before starting.

### Strict port forwarding mode

Set `CONTROLLER_REQUIRE_PF=true` to pause all torrents when no forwarded port is available:

```bash
CONTROLLER_REQUIRE_PF=true
```

This prevents traffic from flowing without a forwarded port, useful if you require the port for privacy or performance reasons.

### Checking port status

After installation, use these aliases:

```bash
arr.vpn.status         # Check VPN connection status
arr.vpn.port           # Show current forwarded port number
arr.vpn.port.state     # Show full port-guard status as JSON
arr.vpn.port.watch     # Follow status changes in real-time
```

### Gluetun control API

Gluetun exposes a control API for status checks and server management:

| Setting | Default | Description |
|---------|---------|-------------|
| `GLUETUN_CONTROL_PORT` | `8000` | Port for the control API |
| `GLUETUN_CONTROL_BIND` | `all` | `all` = bind to 0.0.0.0; `loopback` = 127.0.0.1 only |

The API requires `GLUETUN_API_KEY` for authentication. Rotate it periodically:

```bash
./arr.sh --rotate-api-key --yes
```

---

## SABnzbd placement

When SABnzbd is enabled (`SABNZBD_ENABLED=1`), you can choose where it runs:

| Setting | `SABNZBD_USE_VPN` | Network | Reachable from | Notes |
|---------|-------------------|---------|----------------|-------|
| **LAN bridge** | `0` (default) | `arr_net` | `http://LAN_IP:8080` | Recommended. Sonarr/Radarr can reach it directly. |
| **VPN attached** | `1` | Shares Gluetun | Internal only | Use when Usenet traffic must exit via VPN. |

### LAN bridge mode (default)

```bash
SABNZBD_ENABLED=1
SABNZBD_USE_VPN=0
```

- SABnzbd runs on the `arr_net` bridge like the *arr apps
- Accessible at `http://LAN_IP:8080` when `EXPOSE_DIRECT_PORTS=1`
- Sonarr/Radarr/Lidarr can connect using `localhost:8080` or the LAN IP

### VPN mode

```bash
SABNZBD_ENABLED=1
SABNZBD_USE_VPN=1
```

- SABnzbd shares Gluetun's network namespace (like qBittorrent)
- All Usenet traffic goes through the VPN tunnel
- Not directly accessible on a host port; *arr apps connect through Docker networking
- Uses port `8080` inside Gluetun (doesn't conflict with qBittorrent's `8082`)

### Port configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SABNZBD_INT_PORT` | `8080` | SABnzbd's internal listening port |
| `SABNZBD_PORT` | `8080` | Host port when `EXPOSE_DIRECT_PORTS=1` |

If SABnzbd shares Gluetun (`SABNZBD_USE_VPN=1`), keep `SABNZBD_INT_PORT=8080` to avoid conflicts with qBittorrent (`8082`).

---

## Useful diagnostic commands

Check VPN connectivity:

```bash
# Verify Gluetun status
arr.vpn.status

# Test DNS resolution through VPN
docker exec gluetun nslookup github.com

# Check your VPN exit IP
docker exec gluetun wget -qO- https://ipinfo.io/ip

# View forwarded port state
arr.vpn.port.state
```

Check port-guard health:

```bash
# Container health status
docker inspect vpn-port-guard --format '{{.State.Health.Status}}'

# View logs
docker logs vpn-port-guard --tail 50
```

---

## Related documentation

- [Usage](usage.md) – Configuration options and CLI reference
- [Architecture](architecture.md) – How the installer works
- [Troubleshooting](troubleshooting.md) – Common issues and fixes

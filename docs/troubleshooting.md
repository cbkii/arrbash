# Troubleshooting

[← Back to README](../README.md)

This guide helps diagnose and fix common issues with the arrbash media stack.

---

## Quick fixes

### Reset your environment

If things seem broken, start with a clean shell environment:

```bash
# Unset any conflicting environment variables
unset ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null

# Navigate to your stack directory
cd ~/srv/arr

# Reload aliases
source .aliasarr

# Verify compose configuration is valid
docker compose config >/dev/null && echo "Compose config OK"
```

### Re-run the installer

Many issues can be fixed by regenerating configuration:

```bash
./arr.sh --yes
```

This rebuilds `.env`, `docker-compose.yml`, and restarts services.

---

## VPN and connectivity issues

### qBittorrent unreachable in split mode

**Symptom**: Can't access qBittorrent WebUI when using `SPLIT_VPN=1`.

**Solutions**:
1. Ensure `EXPOSE_DIRECT_PORTS=1` is set in `userr.conf`
2. Access qBittorrent using your LAN IP: `http://LAN_IP:8082`
3. In Sonarr/Radarr download client settings, use `http://LAN_IP:8082` (not `localhost`)

### qBittorrent can't download anything

**Symptom**: Torrents add but don't download; trackers show errors.

**Check VPN connectivity**:
```bash
# Test DNS resolution through the VPN
docker exec gluetun nslookup github.com

# Check internet connectivity
docker exec gluetun wget -qO- https://ipinfo.io/ip

# View qBittorrent logs for tracker/peer errors
docker logs qbittorrent 2>&1 | grep -i "tracker\|peer\|connection"
```

**If DNS fails**: Gluetun might not have connected. Check its logs:
```bash
docker logs gluetun --tail 100
```

### Services start too early

**Symptom**: qBittorrent or other services start before dependencies are ready.

**Check health status**:
```bash
# View container status with health
docker ps --format "table {{.Names}}\t{{.Status}}"

# Check specific container health
docker inspect gluetun --format '{{.State.Health.Status}}'
docker inspect vpn-port-guard --format '{{.State.Health.Status}}'
```

Health checks should show `healthy` before dependent services start.

### Forwarded port missing or not updating

**Symptom**: `arr.vpn.port` shows no port or an old port.

**Diagnose**:
```bash
# Check port-guard status
arr.vpn.port.state

# Watch for changes
arr.vpn.port.watch

# View port-guard logs
docker logs vpn-port-guard --tail 50
```

**Fix**: Rotate the Gluetun API key and restart:
```bash
./arr.sh --rotate-api-key --yes
```

### Gluetun authentication failures

**Symptom**: Gluetun logs show auth errors; VPN won't connect.

**Check credentials**:
```bash
# View Gluetun logs
docker logs gluetun | tail -50

# Verify proton.auth exists and has correct format
cat ~/srv/arrconfigs/proton.auth
```

**Regenerate auth config**:
```bash
rm -f ~/srv/arr/dockarr/gluetun/auth/config.toml
./arr.sh --yes
```

### VPN auto-reconnect not working

**Symptom**: VPN stays disconnected; auto-reconnect seems inactive.

**Check if enabled**:
```bash
grep VPN_AUTO_RECONNECT_ENABLED ~/srv/arrconfigs/userr.conf
```

**Check status**:
```bash
arr.vpn.auto.status
```

**Resume if paused**:
```bash
arr.vpn.auto.resume
```

---

## WebUI and credential issues

### VueTorrent shows blank page or HTTP 500

**Check mod configuration**:
```bash
grep QBT_DOCKER_MODS ~/srv/arr/.env
```

**If using LSIO mod** (default):
- VueTorrent should be at `http://LAN_IP:8082/vuetorrent/`
- The mod auto-installs VueTorrent on container start

**If blank after fresh install**: Wait for container to fully start, then refresh:
```bash
docker logs qbittorrent 2>&1 | grep -i vuetorrent
```

### Forgot qBittorrent password

**View current credentials**:
```bash
# From helper script
./scripts/stack-qbt-helper.sh show

# Or check .env directly
grep QBT_PASS ~/srv/arr/.env
```

**Reset to default**:
```bash
./scripts/stack-qbt-helper.sh reset
./arr.sh --yes
```

### qBittorrent API authentication failing

**Symptom**: Helper scripts fail with auth errors.

**Verify password matches**:
```bash
# Check what's in .env
grep QBT_PASS ~/srv/arr/.env

# If you changed password in WebUI, update userr.conf:
nano ~/srv/arrconfigs/userr.conf
# Set QBT_PASS to match the WebUI password

# Then re-run installer
./arr.sh --yes
```

### LAN IP not in qBittorrent whitelist

**Symptom**: Always prompted for password from LAN machines.

**Check whitelist configuration**:
```bash
# View qBittorrent config
grep AuthSubnetWhitelist ~/srv/arr/dockarr/qbittorrent/qBittorrent/qBittorrent.conf
```

**Fix**: Ensure `LAN_IP` is set in `userr.conf`. The installer auto-adds `LAN_IP/24` to the whitelist:
```bash
grep LAN_IP ~/srv/arrconfigs/userr.conf
./arr.sh --yes
```

### Docker networking masks client IP (whitelist bypass fails)

**Symptom**: LAN whitelist is configured, but login is still required.

**Explanation**: When qBittorrent runs behind Gluetun (`network_mode: service:gluetun`), connections to its WebUI arrive from Docker's bridge network (by default `172.17.0.0/16`, or another subnet within `172.16.0.0/12`), not from your actual LAN IP. This means the client's true IP is masked.

**Solution**: The default `QBT_AUTH_WHITELIST` now includes `172.17.0.0/16,::ffff:172.28.0.1/128` to cover Docker's default bridge network internal traffic. Additionally, `LocalHostAuth` is set to `false` so the whitelist bypass works correctly. If you use custom Docker networks, add their subnets explicitly.

If you're running an older configuration:
1. Update `userr.conf` to include Docker's default bridge subnet in the whitelist:
   ```bash
   QBT_AUTH_WHITELIST="127.0.0.1/32,::1/128,172.17.0.0/16,::ffff:172.28.0.1/128"
   ```
2. Re-run the installer to apply changes:
   ```bash
   ./arr.sh --yes
   ```

### Configarr API key errors

**Symptom**: Configarr fails with "invalid API key" errors.

**Sync API keys**:
```bash
./arr.sh --sync-api-keys --yes
```

Run this after:
- First installation
- Any Sonarr/Radarr/Prowlarr reinstall
- Changing API keys in the apps

---

## Container and Docker issues

### Container keeps restarting

**View restart reason**:
```bash
docker inspect <container> --format '{{.State.ExitCode}} {{.State.Error}}'
docker logs <container> --tail 100
```

### Out of disk space

**Check Docker disk usage**:
```bash
docker system df
docker system prune -a  # WARNING: removes unused images/containers
```

### Permission denied errors

**Check ownership**:
```bash
ls -la ~/srv/arr/
ls -la ~/srv/arr/dockarr/
```

Files should be owned by your user (matching `PUID`/`PGID` in config).

**Fix permissions**:
```bash
./scripts/fix-permissions.sh
./arr.sh --yes
```

---

## Network and port issues

### Port already in use

**Symptom**: Installer fails with "port in use" error.

**Find what's using the port**:
```bash
sudo ss -tulpn | grep :8082
sudo lsof -i :8082
```

**Options**:
1. Stop the conflicting service
2. Change the port in `userr.conf` (e.g., `QBT_PORT=8083`)
3. Set `ARR_PORT_CHECK_MODE=warn` to continue anyway

### Verify exposed ports

After installation, check what's actually listening:

```bash
sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191|:8080'
```

You should see only the services you've enabled.

### Firewall blocking access

**Check UFW status**:
```bash
sudo ufw status
```

**Allow a port**:
```bash
sudo ufw allow 8082/tcp comment "qBittorrent"
```

---

## Diagnostic scripts

### Run full diagnostics

```bash
./scripts/stack-diagnostics.sh
```

This checks:
- Required dependencies
- Docker daemon status
- API connectivity
- File permissions

### Health check JSON output

For monitoring systems:

```bash
./scripts/stack-healthcheck.sh --format json
```

---

## Getting more help

### Enable debug tracing

For detailed logs during installation:

```bash
./arr.sh --trace --yes
```

This creates a timestamped log file with full bash tracing.

### View container logs

```bash
# All containers
docker compose logs --tail 100

# Specific container
docker logs gluetun --tail 100

# Follow logs in real-time
docker logs -f qbittorrent
```

### Check compose configuration

```bash
docker compose config
```

If this shows errors, there's a problem with the generated `docker-compose.yml`.

---

## Related documentation

- [Usage](usage.md) – Configuration and CLI options
- [Architecture](architecture.md) – How the installer works
- [Networking](networking.md) – VPN and port forwarding details

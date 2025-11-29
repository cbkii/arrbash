# Troubleshooting

[← Back to README](../README.md)

Quick checks when services fail to start, VPN helpers misbehave, or credentials drift.

## Reset your environment
Run commands from the stack directory so `.env` is applied, then reload aliases:
```bash
export -n ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
unset ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR 2>/dev/null || true
source "${ARR_STACK_DIR:-$(pwd)}/.aliasarr" 2>/dev/null || true
docker compose config >/dev/null    # ensure no unresolved placeholders
```

## VPN and connectivity
- **qBittorrent unreachable in split mode**: set `EXPOSE_DIRECT_PORTS=1` and point *Arr download clients at `http://LAN_IP:${QBT_PORT}`.
- **qBittorrent starts but can't download**: Verify VPN DNS and connectivity:
  ```bash
  docker exec gluetun nslookup github.com        # Test DNS resolution
  docker exec gluetun wget -O- https://ipinfo.io # Test connectivity
  docker logs qbittorrent | grep -i "tracker\|peer"
  ```
- **Services starting too early**: Check healthcheck status to ensure proper ordering:
  ```bash
  docker ps --format "table {{.Names}}\t{{.Status}}"
  docker inspect gluetun --format '{{.State.Health.Status}}'
  docker inspect vpn-port-guard --format '{{.State.Health.Status}}'
  ```
- **Forwarded port missing**: check controller status and rotate the control API key if authentication fails:
  ```bash
  arr.vpn.port.state
  arr.vpn.port.watch
  ./arr.sh --rotate-api-key --yes
  ```
- **Gluetun issues**: inspect logs and regenerate auth config when credentials change:
  ```bash
  docker logs gluetun | tail
  rm -f "${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
  ./arr.sh --yes
  ```
- **VPN auto-reconnect inactive**: confirm the feature flag and review status files:
  ```bash
  grep VPN_AUTO_RECONNECT_ENABLED "${ARRCONF_DIR}/userr.conf"
  arr.vpn.auto.status
  arr.vpn.auto.resume
  ```

## WebUI and credentials
- **VueTorrent blank or HTTP 500**: ensure `QBT_DOCKER_MODS` matches the desired mode; in manual mode confirm `/config/vuetorrent` exists inside the container.
- **Need qBittorrent credentials**: run `scripts/stack-qbt-helper.sh show` or `... reset` to generate new ones.
- **Configarr complaining about API keys**: rerun `./arr.sh --sync-api-keys --yes` after Sonarr/Radarr/Prowlarr create their configs.
- **qBittorrent API authentication failing**: ensure `QBT_PASS` in `.env` matches the actual qBittorrent WebUI password:
  ```bash
  grep QBT_PASS "${ARR_STACK_DIR}/.env"
  # If changed in WebUI, update userr.conf and rerun installer
  ```
- **LAN IP not in qBittorrent whitelist**: `QBT_AUTH_WHITELIST` is automatically populated with `LAN_IP/24` when `LAN_IP` is set. Check the generated config:
  ```bash
  grep AuthSubnetWhitelist "${ARR_DOCKER_DIR}/qbittorrent/qBittorrent/qBittorrent.conf"
  ```

## Network exposure sanity checks
- arrbash does not provision DNS or HTTPS. Manage those layers externally.
- Verify published ports before opening firewall rules:
  ```bash
  sudo ss -tulpn | grep -E ':8082|:8989|:7878|:9696|:6767|:8191'
  ```

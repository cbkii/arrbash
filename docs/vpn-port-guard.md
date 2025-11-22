# vpn-port-guard controller

`vpn-port-guard` keeps qBittorrent aligned with Gluetun’s forwarded port **when
you opt in to Proton port forwarding**. The default stack leaves forwarding and
hooks disabled so qBittorrent comes up reliably on day one with no controllers
in the way. Enable forwarding only if you need inbound peers and are happy to
accept the extra moving parts.


## Architecture

The vpn-port-guard system consists of two simple components:

1. **Controller (`vpn-port-guard.sh`)**: A polling loop that checks Gluetun for 
   the forwarded port and updates qBittorrent when it changes.
2. **Event Logger (`vpn-port-guard-hook.sh`)**: Called by Gluetun when port 
   changes occur, logs events for monitoring but does not trigger the controller.

## What it does when enabled

- Polls Gluetun every `${CONTROLLER_POLL_INTERVAL:-10}` seconds using
  `http://${GLUETUN_API_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded`.
- Falls back to the Proton NAT-PMP file `${FORWARDED_PORT_FILE:-/tmp/gluetun/forwarded_port}`
  only when the control API is unreachable.
- Idempotently sets `listen_port` via qBittorrent’s Web API whenever the port
  changes.
- Optionally pauses/resumes torrents when `CONTROLLER_REQUIRE_PF=true` and no
  forwarded port is available. The default (`false`) leaves torrents running
  even when Proton has not assigned a port.
- Writes one atomic JSON to `${STATUS_FILE:-${ARR_DOCKER_DIR:-/var/lib/arr}/gluetun/state/port-guard-status.json}`
  on every poll.

The design is simple: **poll → check → apply → record** on a fixed interval.
The controller polls independently of Gluetun's hook events.

## Enabling Proton port forwarding (optional)

- ProtonVPN plan that supports port forwarding.
- Use ProtonVPN **OpenVPN** credentials; arrbash still appends `+pmp` just
  before launch. Keep the stored username without the suffix.
- Opt in via `${ARRCONF_DIR}/userr.conf` and rerun `./arr.sh`:

  ```bash
  VPN_PORT_FORWARDING=on
  PORT_FORWARD_ONLY=off
  VPN_PORT_FORWARDING_PROVIDER=protonvpn
  VPN_PORT_FORWARDING_STATUS_FILE=/tmp/gluetun/forwarded_port
  VPN_PORT_FORWARDING_UP_COMMAND=/scripts/vpn-port-guard-hook.sh up
  VPN_PORT_FORWARDING_DOWN_COMMAND=/scripts/vpn-port-guard-hook.sh down
  ```
- Bind-mount `${ARR_DOCKER_DIR}/gluetun/state` into Gluetun at `/tmp/gluetun`
  and into `vpn-port-guard` at `/gluetun_state` so the forwarded port file and
  status JSON are shared.

## Environment variables

The controller accepts environment variables from Docker Compose or can use defaults:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GLUETUN_CONTROL_URL` | _(derived from host+port)_ | Full Gluetun control URL (e.g., `http://127.0.0.1:8000`). Parsed to set host and port if provided. |
| `GLUETUN_CONTROL_PORT` | `8000` | Gluetun control server port |
| `GLUETUN_API_HOST` | `127.0.0.1` | Hostname used to reach the control API |
| `GLUETUN_API_KEY` | _(empty)_ | Optional API key header (`X-API-Key`) |
| `FORWARDED_PORT_FILE` | `/tmp/gluetun/forwarded_port` | Fallback file when the control API is unreachable |
| `QBT_HOST` | _(used with QBT_PORT)_ | qBittorrent hostname (alternative to QBT_API_BASE) |
| `QBT_PORT` | _(used with QBT_HOST)_ | qBittorrent port (alternative to QBT_API_BASE) |
| `QBT_API_BASE` | `http://127.0.0.1:8080` | Base URL for qBittorrent Web API |
| `QBT_USER` | `admin` | qBittorrent username |
| `QBT_PASS` | `adminadmin` | qBittorrent password |
| `COOKIE_JAR` | `/tmp/vpn-port-guard-qbt.cookie` | Where the controller stores qBittorrent auth cookies |
| `STATUS_FILE` | `${ARR_DOCKER_DIR:-/var/lib/arr}/gluetun/state/port-guard-status.json` | Atomic status JSON output |
| `CONTROLLER_POLL_INTERVAL` | `10` | Seconds between polls (also accepts legacy `POLL_INTERVAL`) |
| `CONTROLLER_REQUIRE_PF` | `false` | When `true`, pause torrents whenever no forwarded port is available |
| `VPN_PORT_GUARD_DEBUG` | `false` | When `true`, enable detailed debug logging |

**Note**: The Compose configuration passes `GLUETUN_CONTROL_URL`, `QBT_HOST`, and `QBT_PORT`, 
which the controller automatically converts to the legacy format for backward compatibility.

The generated Compose leaves `VPN_PORT_FORWARDING` off and the hook commands empty, so `vpn-port-guard` stays dormant until you explicitly opt in via `${ARRCONF_DIR}/userr.conf`.

## Status file

The controller writes one JSON document at `${STATUS_FILE}` (default
`${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`). Writes are atomic
(`mktemp` + `mv`) so readers never see a partial file.

Fields (superset kept for backwards compatibility):

- `vpn_status`: `running` (port assigned), `down` (no port yet), or `unknown`
  (first poll)
- `forwarded_port`: integer, `0` when unavailable
- `pf_enabled`: boolean (`true` when `CONTROLLER_REQUIRE_PF=true`)
- `forwarding_state`: `active` when `forwarded_port>0`, otherwise `unavailable`
- `controller_mode`: `strict` or `preferred` (derived from `pf_enabled`)
- `qbt_status`: `active`, `paused`, `error`, or `unknown`
- `last_error`: string, empty when none
- `last_update` / `last_update_epoch`: epoch timestamp

`vpn_status="down"` simply means no forwarded port has been assigned yet. For the
actual forwarding condition, also consult `forwarding_state` (`active` vs
`unavailable`).

Quick checks from the host:

```bash
ls -l ${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json
cat ${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json
```

## Troubleshooting basics

- Control API reachable? `curl -s http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded -H "X-API-Key: ${GLUETUN_API_KEY}"`.
- Forwarded port file present? `cat /tmp/gluetun/forwarded_port` inside the
  Gluetun container should show a number when Proton has assigned one.
- qBittorrent credentials correct? `curl -i -X POST "${QBT_API_BASE}/api/v2/auth/login" --data "username=${QBT_USER}&password=${QBT_PASS}"`.
- Strict mode pauses torrents. If `pf_enabled` is `true` and `forwarding_state`
  is `unavailable`, expect `/api/v2/torrents/pause` calls until a port appears.
- Logs: `docker logs vpn-port-guard` to watch loop activity.
- **Enable debug logging** for detailed diagnostics:
  ```bash
  # Add to userr.conf or docker-compose.yml environment:
  VPN_PORT_GUARD_DEBUG=true
  ```
  Then restart the container:
  ```bash
  docker compose restart vpn-port-guard
  docker logs -f vpn-port-guard  # Watch debug output
  ```
  Debug mode shows poll cycles, API responses, and state transitions.

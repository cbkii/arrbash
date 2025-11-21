# vpn-port-guard controller

`vpn-port-guard` replaces the legacy port-manager/port-watch helpers. It is the single
component allowed to control qBittorrent during runtime. The controller lives in the
`vpn-port-guard` container and runs `scripts/vpn-port-guard.sh`, depending exclusively
on Gluetun’s HTTP control API and qBittorrent’s Web API.

## ProtonVPN + Gluetun requirements

* You need a ProtonVPN plan that supports port forwarding.
* Always use ProtonVPN’s **OpenVPN** credentials (not your account password) and
  append `+pmp` to the username before supplying it to Gluetun.
* Gluetun must run with:
  * `VPN_SERVICE_PROVIDER=protonvpn`
  * `VPN_TYPE=openvpn`
  * `VPN_PORT_FORWARDING=on`
  * `PORT_FORWARD_ONLY=on`
  * `VPN_PORT_FORWARDING_PROVIDER=protonvpn`
  * `VPN_PORT_FORWARDING_STATUS_FILE=/tmp/gluetun/forwarded_port`
  * HTTP control server bound to `:${GLUETUN_CONTROL_PORT}` with
    `HTTP_CONTROL_SERVER_AUTH=apikey` and `HTTP_CONTROL_SERVER_APIKEY` set.
* The shared bind mount `${ARR_DOCKER_DIR}/gluetun/state` is mounted inside Gluetun
  at `/tmp/gluetun` and inside `vpn-port-guard` at `/gluetun_state`. Gluetun writes the
  ProtonVPN NAT-PMP lease file here and the controller publishes
  `port-guard-status.json` for other helpers to read.
* Gluetun’s `VPN_PORT_FORWARDING_UP/DOWN_COMMAND` values call
  `/scripts/vpn-port-guard-hook.sh` (mounted read-only inside the container). The hook
  merely touches `/gluetun_state/port-guard.trigger`, prompting the controller to run an
  immediate sync pass without touching qBittorrent itself.

## Status file and shared mount

* The authoritative status JSON is written to `/gluetun_state/port-guard-status.json`
  inside the controller container and to `${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`
  on the host. The bind mount keeps the file stable across container restarts.
* A skeleton JSON is created as soon as the controller starts so aliases never chase a
  missing file while waiting for Proton to hand out a port.
* Writes are atomic (`mktemp` + `mv`) to prevent partial reads; the previous JSON remains
  visible until the new one is complete.
* Quick host-side checks:
  * `ls -l ${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`
  * `jq '.' ${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json`

## Runtime lifecycle

1. **Startup ordering**
   1. Gluetun starts, establishes the OpenVPN tunnel, and negotiates a forwarded port.
    2. `vpn-port-guard` starts after Gluetun is healthy. It immediately pauses
      qBittorrent and waits for Gluetun to report `status=running`. Once the VPN
      tunnel is up, the controller resumes qBittorrent even if Proton has not yet
      granted a forwarded port, marking `forwarding_state="unavailable"` in the
      status file until one appears.
   3. qBittorrent starts (it depends on Gluetun and `vpn-port-guard`) and only runs
      while the VPN is healthy. Exporting `CONTROLLER_REQUIRE_PF=true`
      enables strict mode, keeping qBittorrent paused whenever Proton forwarding is
      unavailable.
2. **Continuous enforcement**
   * The controller polls Gluetun every `${VPN_PORT_GUARD_POLL_SECONDS}` (15 seconds by
     default) and also reacts instantly whenever the Gluetun NAT-PMP hook touches
     `/gluetun_state/port-guard.trigger`.
   * If Gluetun reports `status != running`, qBittorrent is paused and the status
     file records `forwarding_state="unavailable"`.
   * Once Gluetun reports `status == running` with a valid port, the controller
     applies that port via qBittorrent’s Web API (disabling `random_port`), sets
     `forwarding_state="active"`, and resumes torrents.
   * When Proton has not granted a port (`forwarded_port == 0`) the controller keeps
     qBittorrent running by default (still inside Gluetun’s namespace) but leaves
     `forwarding_state="unavailable"` so you know seeding capacity is degraded.
     Setting `CONTROLLER_REQUIRE_PF=true` switches to pf-strict mode and keeps
     qBittorrent paused whenever no port is available.
   * If qBittorrent’s Web API becomes unreachable (common in long uptimes when the
     Gluetun namespace glitches), the controller pauses torrents, writes
     `qbt_status="error"`, and relies on the container’s healthcheck+restart policy
     to recover **without** bouncing Gluetun.

## Security model

* Gluetun’s control API listens on all container interfaces but still requires the API
  key. vpn-port-guard reaches it at `http://127.0.0.1:${GLUETUN_CONTROL_PORT}`
  **because** the service runs with `network_mode: service:gluetun`. Changing the
  network mode requires exposing the control API explicitly or vpn-port-guard will fail.
* qBittorrent’s Web UI remains inside the Gluetun network namespace unless you expose it
  intentionally via a reverse proxy.
* `vpn-port-guard` is the **only** service allowed to pause/resume torrents or change
  qBittorrent’s listening port at runtime. All other arrbash scripts have been reduced to
  read-only consumers of `port-guard-status.json`.

## Configuration

`vpn-port-guard` supports the following environment variables:

* `CONTROLLER_REQUIRE_PF` (default: `false`) – When `true`, enables strict mode where torrents
  are paused unless a forwarded port is available. Set to `false` for preferred mode where
  torrents continue running even without port forwarding (reduced connectability).
* `CONTROLLER_POLL_INTERVAL` (default: `15`) – Seconds between Gluetun API polls.
* `GLUETUN_API_RETRY_COUNT` (default: `3`) – Number of retry attempts for Gluetun API calls.
* `GLUETUN_API_RETRY_DELAY` (default: `2`) – Seconds to wait between Gluetun API retries.
* `QBT_API_RETRY_COUNT` (default: `3`) – Number of retry attempts for qBittorrent API calls.
* `QBT_API_RETRY_DELAY` (default: `2`) – Seconds to wait between qBittorrent API retries.

**Note**: The following legacy variables are also supported for backward compatibility but 
`CONTROLLER_REQUIRE_PF` is recommended:
* `CONTROLLER_REQUIRE_PORT_FORWARDING`
* `VPN_PORT_GUARD_REQUIRE_FORWARDING`

## Troubleshooting

### Quick diagnostics

* `arr.pf.status` / `arrvpn` – print the JSON status exported by `vpn-port-guard`
  (including `forwarding_state`, `controller_mode`, and `qbt_status`).
* `arr.pf.port` – shows the currently forwarded port (or reports it unavailable).
* `arr.pf.tail` / `arrvpn-watch` – follow the status file to watch lease changes in
  real time (falls back to a manual loop if `watch(1)` is missing).
* `arr.pf.logs` – streams controller logs for deeper inspection. Look for startup diagnostics
  that validate Gluetun and qBittorrent connectivity.
* `arr.pf.notify` – touches the trigger file to force an immediate poll (useful after
  manual Gluetun restarts).
* `arrvpn-events` – tails `/gluetun_state/port-guard-events.log` to observe Gluetun
  hook activity.

### Common issues

**Status file missing or stale**
  * `docker inspect vpn-port-guard --format '{{.State.Status}}'` should show `running`.
    If not, `./arr.sh --yes` will rebuild and restart the stack.
  * Check startup diagnostics in `arr.pf.logs` for missing dependencies (curl, jq).
  * Confirm the host path `${ARR_DOCKER_DIR}/gluetun/state` exists and is writable; the
    controller will log permission errors if it cannot create the JSON.
  * Verify the bind mount targets `/gluetun_state` inside both Gluetun and
    `vpn-port-guard`. A mismatch leaves helpers looking in the wrong place.

**Gluetun API unreachable**
  * The controller includes automatic retry logic (3 attempts by default) with exponential backoff.
  * Check `arr.pf.logs` for consecutive failure counts. After 5+ consecutive failures, verify:
    * Gluetun container is running: `docker ps | grep gluetun`
    * Gluetun control server is enabled: `GLUETUN_CONTROL_PORT` should be set
    * API key is correct: `GLUETUN_API_KEY` matches Gluetun's `HTTP_CONTROL_SERVER_APIKEY`
  * Test manually: `curl -H "X-API-Key: $GLUETUN_API_KEY" http://127.0.0.1:8000/v1/openvpn/status`

**qBittorrent API unreachable or session expired**
  * The controller automatically re-authenticates on session expiry.
  * If problems persist, check:
    * qBittorrent credentials match: `QBT_USER` and `QBT_PASS` environment variables
    * qBittorrent Web UI is enabled in settings
    * Network connectivity: `docker exec vpn-port-guard curl -I http://127.0.0.1:8082`
  * Watch for "re-authentication successful" in logs after temporary failures.

**Port not being applied to qBittorrent**
  * Check `arr.pf.logs` for detailed error messages including:
    * Invalid port range errors (valid: 1024-65535)
    * Authentication failures
    * API timeout errors
  * Verify the forwarded port in Gluetun: `arr.vpn.pf`
  * Check qBittorrent listen port: log into Web UI → Settings → Connection

**Legacy scripts removed**
  * Scripts like `vpn-port-watch.sh` and `vpn-auto-control.sh` have been removed.
  * Use the status file and aliases above instead of sourcing the old wrappers.

If the status JSON shows `forwarded_port: 0` with `forwarding_state="unavailable"`, ProtonVPN has not
granted a port yet or Gluetun lost the lease. Torrents continue downloading and seeding
peers that can reach you, but connectability is reduced until the lease returns. Enable
`CONTROLLER_REQUIRE_PF=true` if your tracker demands a fully open port and
you prefer torrents to stay paused whenever forwarding is absent. Leave it `false`
for pf-preferred mode so torrents keep running even while Proton rotates the lease.

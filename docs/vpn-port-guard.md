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
  * HTTP control server bound to `127.0.0.1:${GLUETUN_CONTROL_PORT}` with
    `HTTP_CONTROL_SERVER_AUTH=apikey` and `HTTP_CONTROL_SERVER_APIKEY` set.
* The shared bind mount `${ARR_DOCKER_DIR}/gluetun/state` is mounted inside Gluetun
  at `/tmp/gluetun` and inside `vpn-port-guard` at `/gluetun_state`. Gluetun writes the
  ProtonVPN NAT-PMP lease file here and the controller publishes
  `port-guard-status.json` for other helpers to read.
* Gluetun’s `VPN_PORT_FORWARDING_UP/DOWN_COMMAND` values call
  `/scripts/vpn-port-guard-hook.sh` (mounted read-only inside the container). The hook
  merely touches `/gluetun_state/port-guard.trigger`, prompting the controller to run an
  immediate sync pass without touching qBittorrent itself.

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

* Gluetun’s control API is only reachable from within the Docker namespace and requires
  the API key. vpn-port-guard reaches it at `http://127.0.0.1:${GLUETUN_CONTROL_PORT}`
  **because** the service runs with `network_mode: service:gluetun`. Changing the
  network mode requires exposing the control API explicitly or vpn-port-guard will fail.
* qBittorrent’s Web UI remains inside the Gluetun network namespace unless you expose it
  intentionally via a reverse proxy.
* `vpn-port-guard` is the **only** service allowed to pause/resume torrents or change
  qBittorrent’s listening port at runtime. All other arrbash scripts have been reduced to
  read-only consumers of `port-guard-status.json`.

## Troubleshooting

* `arr.pf.status` / `arrvpn` – print the JSON status exported by `vpn-port-guard`
  (including `forwarding_state`, `controller_mode`, and `qbt_status`).
* `arr.pf.port` – shows the currently forwarded port (or reports it unavailable).
* `arr.pf.tail` / `arrvpn-watch` – follow the status file to watch lease changes in
  real time (falls back to a manual loop if `watch(1)` is missing).
* `arr.pf.logs` – streams controller logs for deeper inspection.
* `arr.pf.notify` – touches the trigger file to force an immediate poll (useful after
  manual Gluetun restarts).
* `arrvpn-events` – tails `/gluetun_state/port-guard-events.log` to observe Gluetun
  hook activity.

If the status JSON shows `forwarded_port: 0` with `forwarding_state="unavailable"`, ProtonVPN has not
granted a port yet or Gluetun lost the lease. Torrents continue downloading and seeding
peers that can reach you, but connectability is reduced until the lease returns. Enable
`CONTROLLER_REQUIRE_PF=true` if your tracker demands a fully open port and
you prefer torrents to stay paused whenever forwarding is absent. Leave it `false`
for pf-preferred mode so torrents keep running even while Proton rotates the lease.

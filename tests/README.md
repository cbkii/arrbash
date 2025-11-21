# vpn-port-guard validation

These helper steps exercise the simplified vpn-port-guard controller with a tiny
mock server. The automated harness lives in `tests/test-vpn-port-guard.sh` and
uses `tests/vpn_port_guard_mock.py` to stand in for both Gluetun and
qBittorrent.

## Quick automated run

```bash
# From the repo root
bash tests/test-vpn-port-guard.sh
```

The script spins up the mock server on `127.0.0.1:18080`, runs the controller
in both preferred and strict modes, and asserts that:

- `port-guard-status.json` is written with `forwarded_port`, `forwarding_state`,
  `pf_enabled`, and `qbt_status` fields.
- qBittorrent’s `setPreferences` endpoint is called when a port is available.
- `torrents/pause` is called when `CONTROLLER_REQUIRE_PF=true` and no port is
  present.

## Manual checks

1. Start the mock server and export a forwarded port:

```bash
python3 tests/vpn_port_guard_mock.py /tmp/forwarded_port /tmp/vpg-events.log 18080 &
echo 43210 >/tmp/forwarded_port
```

2. Run the controller with a short poll interval:

```bash
GLUETUN_CONTROL_PORT=18080 GLUETUN_API_HOST=127.0.0.1 \
QBT_API_BASE=http://127.0.0.1:18080 FORWARDED_PORT_FILE=/tmp/forwarded_port \
STATUS_FILE=/tmp/port-guard-status.json POLL_INTERVAL=2 \
./scripts/vpn-port-guard.sh
```

3. Inspect the status JSON and mock event log:

```bash
cat /tmp/port-guard-status.json
cat /tmp/vpg-events.log
```

4. To test strict mode, set `CONTROLLER_REQUIRE_PF=true`, empty the forwarded
   port file (`echo 0 >/tmp/forwarded_port`), and confirm the controller writes
   `forwarding_state` as `unavailable` and hits `/api/v2/torrents/pause` in the
   event log.

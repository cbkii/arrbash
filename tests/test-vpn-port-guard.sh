#!/usr/bin/env bash
# shellcheck shell=bash
# Basic integration harness for vpn-port-guard using mock Gluetun + qBittorrent endpoints.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

PORT_GUARD_SCRIPT="${REPO_ROOT}/scripts/vpn-port-guard.sh"

if [[ ! -x "${PORT_GUARD_SCRIPT}" ]]; then
  echo "vpn-port-guard script not found" >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
forward_file="${tmp_root}/forwarded_port"
status_file="${tmp_root}/status.json"
cookie_file="${tmp_root}/cookie.txt"
event_log="${tmp_root}/server-events.log"

cat >"${forward_file}" <<'EOF_PORT'
50123
EOF_PORT

python3 "${SCRIPT_DIR}/vpn_port_guard_mock.py" "${forward_file}" "${event_log}" 18080 &
server_pid=$!
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  rm -rf -- "$tmp_root"
}
trap cleanup EXIT

run_controller() {
  local require_pf="$1"
  env \
    GLUETUN_CONTROL_PORT=18080 \
    GLUETUN_API_HOST=127.0.0.1 \
    GLUETUN_API_KEY= \
    FORWARDED_PORT_FILE="${forward_file}" \
    QBT_API_BASE="http://127.0.0.1:18080" \
    QBT_USER=admin \
    QBT_PASS=adminadmin \
    COOKIE_JAR="${cookie_file}" \
    STATUS_FILE="${status_file}" \
    POLL_INTERVAL=1 \
    CONTROLLER_REQUIRE_PF="$require_pf" \
    timeout 8s "${PORT_GUARD_SCRIPT}" || true
}

run_controller "false"

sleep 1
if [[ ! -s "${status_file}" ]]; then
  echo "Status file was not created" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  jq -e '.forwarded_port == 50123 and .forwarding_state == "active"' "${status_file}" >/dev/null
else
  grep -Eq '"forwarded_port"[[:space:]]*:[[:space:]]*50123' "${status_file}"
fi

grep -q '/api/v2/app/setPreferences' "${event_log}" || {
  echo "qBittorrent setPreferences call not observed" >&2
  exit 1
}

echo "0" >"${forward_file}"
: >"${event_log}"
run_controller "true"

sleep 1
if command -v jq >/dev/null 2>&1; then
  jq -e '.pf_enabled == true and .forwarding_state == "unavailable" and .qbt_status == "paused"' "${status_file}" >/dev/null
else
  grep -Eq '"pf_enabled"[[:space:]]*:[[:space:]]*true' "${status_file}" && \
    grep -Eq '"forwarding_state"[[:space:]]*:[[:space:]]*"unavailable"' "${status_file}" && \
    grep -Eq '"qbt_status"[[:space:]]*:[[:space:]]*"paused"' "${status_file}"
fi

grep -q '/api/v2/torrents/pause' "${event_log}" || {
  echo "Pause call not observed in strict mode" >&2
  exit 1
}

echo "vpn-port-guard test harness completed. Temp files in ${tmp_root}" >&2

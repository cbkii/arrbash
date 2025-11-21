#!/usr/bin/env bash
# shellcheck shell=bash
# vpn-port-guard: minimal controller to align qBittorrent with Gluetun's forwarded port

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck disable=SC1091
if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

log() {
  printf '[vpn-port-guard] %s\n' "$*"
}

bool_true() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | on | ON) return 0 ;;
    *) return 1 ;;
  esac
}

# Environment defaults
: "${GLUETUN_CONTROL_PORT:=8000}"
: "${GLUETUN_API_HOST:=127.0.0.1}"
: "${GLUETUN_API_KEY:=}"
: "${FORWARDED_PORT_FILE:=/tmp/gluetun/forwarded_port}"
: "${QBT_API_BASE:=http://127.0.0.1:8080}"
: "${QBT_USER:=admin}"
: "${QBT_PASS:=adminadmin}"
: "${COOKIE_JAR:=/tmp/vpn-port-guard-qbt.cookie}"
: "${STATUS_FILE:=${ARR_DOCKER_DIR:-/var/lib/arr}/gluetun/state/port-guard-status.json}"
: "${POLL_INTERVAL:=10}"
: "${CONTROLLER_REQUIRE_PF:=false}"

STATUS_DIR="$(dirname "${STATUS_FILE}")"
mkdir -p -- "${STATUS_DIR}" || {
  log "Unable to create status directory ${STATUS_DIR}"
  exit 1
}
COOKIE_DIR="$(dirname "${COOKIE_JAR}")"
mkdir -p -- "${COOKIE_DIR}" || true

_qbt_state="unknown"
_last_forwarded_port=0

json_escape() {
  local raw="$1"
  raw=${raw//\\/\\\\}
  raw=${raw//"/\\"}
  raw=${raw//$'\n'/\\n}
  printf '%s' "$raw"
}

write_status() {
  local vpn_status="$1"
  local forwarded_port="$2"
  local pf_enabled_raw="$3"
  local qbt_status="$4"
  local last_error="$5"
  local now
  now="$(date +%s 2>/dev/null || printf '0')"

  local forwarding_state
  if [[ "$forwarded_port" =~ ^[1-9][0-9]*$ ]]; then
    forwarding_state="active"
  else
    forwarding_state="unavailable"
    forwarded_port=0
  fi

  local controller_mode="preferred"
  local pf_enabled="false"
  if bool_true "$pf_enabled_raw"; then
    controller_mode="strict"
    pf_enabled="true"
  fi

  local tmp
  if ! tmp="$(mktemp "${STATUS_DIR}/port-guard-status.XXXXXX" 2>/dev/null)"; then
    log "Unable to create temporary status file"
    return 1
  fi

  local escaped_error escaped_vpn escaped_qbt
  escaped_error="$(json_escape "${last_error}")"
  escaped_vpn="$(json_escape "${vpn_status}")"
  escaped_qbt="$(json_escape "${qbt_status}")"

  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg vpn_status "$vpn_status" \
      --arg forwarding_state "$forwarding_state" \
      --arg controller_mode "$controller_mode" \
      --arg qbt_status "$qbt_status" \
      --arg last_error "$last_error" \
      --argjson forwarded_port "$forwarded_port" \
      --argjson pf_enabled "$pf_enabled" \
      --argjson last_update "$now" \
      '{
        vpn_status: $vpn_status,
        forwarded_port: $forwarded_port,
        pf_enabled: $pf_enabled,
        forwarding_state: $forwarding_state,
        controller_mode: $controller_mode,
        qbt_status: $qbt_status,
        last_update: $last_update,
        last_update_epoch: $last_update,
        last_error: $last_error
      }' >"${tmp}" || {
        log "Failed to render status JSON"
        rm -f -- "$tmp"
        return 1
      }
  else
    cat >"${tmp}" <<EOF_JSON
{
  "vpn_status": "${escaped_vpn}",
  "forwarded_port": ${forwarded_port},
  "pf_enabled": ${pf_enabled},
  "forwarding_state": "${forwarding_state}",
  "controller_mode": "${controller_mode}",
  "qbt_status": "${escaped_qbt}",
  "last_update": ${now},
  "last_update_epoch": ${now},
  "last_error": "${escaped_error}"
}
EOF_JSON
  fi

  mv -f -- "$tmp" "$STATUS_FILE"
}

parse_port_payload() {
  local payload_file="$1"
  local port=""
  if command -v jq >/dev/null 2>&1; then
    port="$(jq -r '.port // .data.port // 0' "$payload_file" 2>/dev/null || printf '0')"
  else
    port="$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "$payload_file" | head -n1 | tr -d '\n')"
  fi
  if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s' "$port"
  else
    printf '0'
  fi
}

fetch_forwarded_port() {
  local api_url="http://${GLUETUN_API_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded"
  local tmp http_code port
  tmp="$(mktemp "${STATUS_DIR}/gluetun-port.XXXXXX" 2>/dev/null || printf '')"
  if [[ -n "$tmp" ]]; then
    local curl_args=(--silent --show-error --fail --connect-timeout 5 --max-time 10 -w '%{http_code}' -o "$tmp")
    if [[ -n "${GLUETUN_API_KEY}" ]]; then
      curl_args+=(-H "X-API-Key: ${GLUETUN_API_KEY}")
    fi
    http_code="$(curl "${curl_args[@]}" "$api_url" 2>/dev/null || printf '')"
    if [[ "$http_code" == "200" ]]; then
      port="$(parse_port_payload "$tmp")"
      rm -f -- "$tmp"
      printf '%s' "$port"
      return 0
    fi
    rm -f -- "$tmp"
  fi

  if [[ -f "$FORWARDED_PORT_FILE" ]]; then
    port="$(tr -cd '0-9' <"$FORWARDED_PORT_FILE" | tr -d '\n')"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      printf '%s' "$port"
      return 0
    fi
  fi
  printf '0'
  return 1
}

qbt_login() {
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
    --connect-timeout 5 --max-time 10 \
    --data-urlencode "username=${QBT_USER}" \
    --data-urlencode "password=${QBT_PASS}" \
    "${QBT_API_BASE}/api/v2/auth/login" 2>/dev/null || printf '')"
  if [[ "$code" == "200" ]] && grep -q 'SID' "$COOKIE_JAR" 2>/dev/null; then
    return 0
  fi
  rm -f -- "$COOKIE_JAR" 2>/dev/null || true
  return 1
}

qbt_post() {
  local path="$1"; shift
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" --connect-timeout 5 --max-time 10 "$@" "${QBT_API_BASE}${path}" 2>/dev/null || printf '')"
  if [[ "$code" == "401" ]]; then
    if qbt_login; then
      code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" --connect-timeout 5 --max-time 10 "$@" "${QBT_API_BASE}${path}" 2>/dev/null || printf '')"
    fi
  fi
  [[ "$code" == "200" ]]
}

apply_qbt_port() {
  local port="$1"
  local payload
  payload="$(printf '{"listen_port":%s,"random_port":false}' "$port")"
  if qbt_post "/api/v2/app/setPreferences" --data-urlencode "json=${payload}"; then
    _qbt_state="active"
    _last_forwarded_port="$port"
    return 0
  fi
  _qbt_state="error"
  return 1
}

pause_qbt() {
  if [[ "${_qbt_state}" == "paused" ]]; then
    return 0
  fi
  if qbt_post "/api/v2/torrents/pause" --data "hashes=all"; then
    _qbt_state="paused"
    return 0
  fi
  _qbt_state="error"
  return 1
}

resume_qbt() {
  if [[ "${_qbt_state}" == "active" ]]; then
    return 0
  fi
  if qbt_post "/api/v2/torrents/resume" --data "hashes=all"; then
    _qbt_state="active"
    return 0
  fi
  _qbt_state="error"
  return 1
}

initialise() {
  write_status "init" 0 "$CONTROLLER_REQUIRE_PF" "unknown" "initializing" || true
  qbt_login || true
}

main_loop() {
  local last_error
  while true; do
    sleep "${POLL_INTERVAL}"
    last_error=""
    local vpn_status="down"
    local port
    port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      vpn_status="running"
    elif [[ -s "$FORWARDED_PORT_FILE" ]]; then
      vpn_status="running"
    else
      vpn_status="down"
    fi

    if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
      if [[ "$port" != "${_last_forwarded_port}" ]]; then
        log "Applying forwarded port ${port} to qBittorrent"
        if ! apply_qbt_port "$port"; then
          last_error="failed to set qBittorrent listen port"
        fi
      fi
      if bool_true "$CONTROLLER_REQUIRE_PF"; then
        resume_qbt || last_error="failed to resume torrents"
      else
        _qbt_state="active"
      fi
    else
      if bool_true "$CONTROLLER_REQUIRE_PF"; then
        if ! pause_qbt; then
          last_error="failed to pause torrents"
        fi
      fi
    fi

    write_status "$vpn_status" "${port:-0}" "$CONTROLLER_REQUIRE_PF" "${_qbt_state:-unknown}" "${last_error}" || true
  done
}

log "Starting vpn-port-guard (poll=${POLL_INTERVAL}s, require_pf=${CONTROLLER_REQUIRE_PF})"
initialise
main_loop

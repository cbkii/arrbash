#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

run_case() {
  local name="$1"
  shift
  local -a overrides=("$@")
  local tmp
  tmp="$(mktemp -d)"
  local stack_dir="${tmp}/stack"
  local docker_dir="${tmp}/docker"
  mkdir -p "$stack_dir" "$docker_dir"

  local status=0
  (
    set -Eeuo pipefail
    ARR_STACK_DIR="$stack_dir"
    ARR_DOCKER_DIR="$docker_dir"
    ARR_ENV_FILE="$stack_dir/.env"
    ARRSTACK_NO_MAIN=1
    source "${REPO_ROOT}/arrstack.sh"

    PUID=1000
    PGID=1000
    TIMEZONE="UTC"
    LAN_IP="192.168.0.2"
    LOCALHOST_IP="127.0.0.1"
    EXPOSE_DIRECT_PORTS=0
    SPLIT_VPN=0
    SABNZBD_ENABLED=1
    SABNZBD_USE_VPN=0
    ARRCONF_DIR="${tmp}/arrconf"
    mkdir -p "$ARRCONF_DIR"
    printf 'PROTON_USER=testuser\nPROTON_PASS=testpass\n' >"${ARRCONF_DIR}/proton.auth"
    for expr in "${overrides[@]}"; do
      eval "$expr"
    done

    write_env
    write_compose
    printf '%s\n' "$LAN_IP" >"${tmp}/lan_ip"
    printf '%s\n' "${SABNZBD_PORT:-8080}" >"${tmp}/sab_port"
  ) || status=$?

  local compose_file="${stack_dir}/docker-compose.yml"
  local env_file="${stack_dir}/.env"
  local lan_ip=""
  local sab_port=""
  if [[ -f "${tmp}/lan_ip" ]]; then
    lan_ip="$(<"${tmp}/lan_ip")"
  fi
  if [[ -f "${tmp}/sab_port" ]]; then
    sab_port="$(<"${tmp}/sab_port")"
  fi
  if (( status != 0 )) || [[ ! -f "$compose_file" ]]; then
    echo "[${name}] compose generation failed" >&2
    status=1
  else
    if [[ $(grep -c '^  sabnzbd:' "$compose_file") -ne 1 ]]; then
      echo "[${name}] unexpected sabnzbd block count" >&2
      status=1
    fi
    if grep -q 'aliases:' "$compose_file"; then
      echo "[${name}] unexpected network alias block" >&2
      status=1
    fi
    if ! grep -q 'start_period:' "$compose_file"; then
      echo "[${name}] sabnzbd healthcheck missing start_period" >&2
      status=1
    fi
    if grep -q 'apikey=' "$compose_file"; then
      echo "[${name}] sabnzbd healthcheck still references apikey" >&2
      status=1
    fi
    if grep -q 'network_mode: "service:gluetun"' "$compose_file"; then
      if [[ -n "$lan_ip" && -n "$sab_port" ]] && grep -q "${lan_ip}:${sab_port}:8080" "$compose_file"; then
        echo "[${name}] found host port mapping while sharing gluetun" >&2
        status=1
      fi
    fi
    if grep -q 'http://127.0.0.1:8080/api/v2/app/version' "$compose_file"; then
      echo "[${name}] qBittorrent healthcheck still uses 8080" >&2
      status=1
    fi
    if ! grep -q 'http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/version' "$compose_file" \
      && ! grep -q 'http://127.0.0.1:8082/api/v2/app/version' "$compose_file"; then
      echo "[${name}] qBittorrent healthcheck missing 8082 placeholder" >&2
      status=1
    fi
  fi

  if [[ -f "$env_file" ]]; then
    if ! grep -q '^QBT_WEBUI_PORT=8082' "$env_file"; then
      echo "[${name}] expected QBT_WEBUI_PORT=8082 in .env" >&2
      status=1
    fi
    if grep -q '^FORCE_SAB_VPN=' "$env_file"; then
      echo "[${name}] .env still contains FORCE_SAB_VPN" >&2
      status=1
    fi
  fi

  rm -rf "$tmp"
  return "$status"
}

main() {
  local -a cases=(
    "default:SPLIT_VPN=0"
    "default_expose:SPLIT_VPN=0 EXPOSE_DIRECT_PORTS=1"
    "split:SPLIT_VPN=1"
    "split_expose:SPLIT_VPN=1 EXPOSE_DIRECT_PORTS=1"
    "vpn_enabled:SPLIT_VPN=0 SABNZBD_USE_VPN=1"
  )

  local rc=0
  local entry
  for entry in "${cases[@]}"; do
    local name="${entry%%:*}"
    local exprs_string="${entry#*:}"
    IFS=' ' read -r -a exprs <<<"${exprs_string}"
    if run_case "$name" "${exprs[@]}"; then
      printf '[%s] OK\n' "$name"
    else
      printf '[%s] FAIL\n' "$name" >&2
      rc=1
    fi
  done
  return "$rc"
}

main "$@"

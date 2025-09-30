#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${REPO_ROOT}}"

if [[ ! -d "$STACK_DIR" ]]; then
  echo "[check-caddy-optional] Stack directory not found: ${STACK_DIR}" >&2
  exit 1
fi

compose_path="${STACK_DIR}/docker-compose.yml"
if [[ ! -f "$compose_path" ]]; then
  echo "[check-caddy-optional] docker-compose.yml not found at ${compose_path}. Run ./arrstack.sh first." >&2
  exit 1
fi

env_source="${ARR_ENV_FILE:-${STACK_DIR}/.env}"
if [[ ! -f "$env_source" ]]; then
  if [[ -f "${STACK_DIR}/.env.example" ]]; then
    env_source="${STACK_DIR}/.env.example"
  else
    env_source="${REPO_ROOT}/.env.example"
  fi
  if [[ ! -f "$env_source" ]]; then
    echo "[check-caddy-optional] No .env or .env.example found in ${STACK_DIR}." >&2
    exit 1
  fi
fi

tmp_env="$(mktemp "${STACK_DIR}/.env.caddy-check.XXXXXX")"
trap 'rm -f "$tmp_env"' EXIT
cp "$env_source" "$tmp_env"

if grep -q '^ENABLE_CADDY=' "$tmp_env"; then
  sed -i '' -e 's/^ENABLE_CADDY=.*/ENABLE_CADDY=0/' "$tmp_env" 2>/dev/null || sed -i -e 's/^ENABLE_CADDY=.*/ENABLE_CADDY=0/' "$tmp_env"
else
  printf '\nENABLE_CADDY=0\n' >>"$tmp_env"
fi

if grep -q '^ENABLE_LOCAL_DNS=' "$tmp_env"; then
  :
else
  printf 'ENABLE_LOCAL_DNS=0\n' >>"$tmp_env"
fi

if grep -q '^[[:space:]]*caddy:' "$compose_path"; then
  echo "[check-caddy-optional] Expected caddy service to be absent when ENABLE_CADDY=0." >&2
  exit 1
fi

if grep -q '":80:80"' "$compose_path"; then
  echo "[check-caddy-optional] Found an 80:80 port mapping with Caddy disabled." >&2
  exit 1
fi

if grep -q '":443:443"' "$compose_path"; then
  echo "[check-caddy-optional] Found a 443:443 port mapping with Caddy disabled." >&2
  exit 1
fi

ARR_STACK_DIR="$STACK_DIR"
ARR_ENV_FILE="${tmp_env}"
ARR_DOCKER_DIR="${ARR_STACK_DIR}/docker-data"
ARRCONF_DIR="${ARR_STACK_DIR}/arrconf"
export ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR

set +e
alias_source="${ARR_STACK_DIR}/.aliasarr"
if [[ ! -f "$alias_source" ]]; then
  alias_source="${REPO_ROOT}/.aliasarr"
fi
# shellcheck source=/dev/null
. "$alias_source"
set -e

alias_output="$(arr.open 2>&1)"

if [[ "$alias_output" != *"Caddy disabled"* ]]; then
  echo "[check-caddy-optional] arr.open did not mention that Caddy is disabled." >&2
  printf '%s\n' "$alias_output"
  exit 1
fi

if [[ "$alias_output" != *"qBittorrent -> http://"* ]]; then
  echo "[check-caddy-optional] arr.open did not list direct http:// LAN URLs." >&2
  printf '%s\n' "$alias_output"
  exit 1
fi

echo "[check-caddy-optional] PASS: Caddy disabled path looks clean."

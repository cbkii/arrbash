#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/common.sh
. "${STACK_DIR}/scripts/common.sh"

CA_ROOT="${ARR_DOCKER_DIR:-${HOME}/srv/docker-data}/caddy/data/caddy/pki/authorities/local"
CA_FILE="${CA_ROOT}/root.crt"
DEST_FILE="${1:-${HOME}/arrstack-ca.crt}"

if [[ ! -f "$CA_FILE" ]]; then
  log_warn "Caddy internal CA not found at ${CA_FILE}"
  log_warn "Start the stack at least once so Caddy can generate its local CA."
  exit 1
fi

if [[ -d "${DEST_FILE}" ]]; then
  die "Destination ${DEST_FILE} is a directory; provide a file path."
fi

dest_dir="$(dirname "${DEST_FILE}")"
if [[ ! -d "${dest_dir}" ]]; then
  if ! mkdir -p "${dest_dir}" 2>/dev/null; then
    die "Unable to create destination directory ${dest_dir}"
  fi
fi

if cp "$CA_FILE" "$DEST_FILE" 2>/dev/null; then
  chmod 600 "$DEST_FILE" 2>/dev/null || true
  log_info "CA certificate exported to ${DEST_FILE}"
  log_info "Install this on LAN devices to trust HTTPS connections"
else
  die "Failed to copy ${CA_FILE} to ${DEST_FILE}"
fi

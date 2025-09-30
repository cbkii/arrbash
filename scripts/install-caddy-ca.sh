#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: ${0##*/} [--stack-dir PATH] [--data-dir PATH]

Installs the Caddy internal CA certificate into the host trust store.
  --stack-dir PATH   Override the ARR stack directory (defaults to script parent)
  --data-dir PATH    Override the Caddy data directory (defaults to detected value)
  -h, --help         Show this help text
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/common.sh
. "${SCRIPT_DIR}/common.sh"

STACK_DIR=""
DATA_DIR_OVERRIDE=""

while (($#)); do
  case "$1" in
    --stack-dir)
      STACK_DIR="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR_OVERRIDE="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      log_warn "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$STACK_DIR" ]]; then
  STACK_DIR="${ARR_STACK_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
fi

STACK_DIR_INPUT="$STACK_DIR"
if ! STACK_DIR="$(cd "$STACK_DIR_INPUT" 2>/dev/null && pwd)"; then
  die "Stack directory not found: ${STACK_DIR_INPUT}"
fi

if [[ -n "$DATA_DIR_OVERRIDE" ]]; then
  CADDY_DATA_DIR="$DATA_DIR_OVERRIDE"
else
  ENV_FILE="${ARR_ENV_FILE:-${STACK_DIR}/.env}"
  if [[ -f "$ENV_FILE" ]]; then
    env_value="$(grep '^ARR_DOCKER_DIR=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)"
    if [[ -n "$env_value" ]]; then
      arr_docker_dir="$(unescape_env_value_from_compose "$env_value")"
      if [[ -n "$arr_docker_dir" ]]; then
        CADDY_DATA_DIR="${arr_docker_dir}/caddy/data"
      fi
    fi
  fi
fi

if [[ -z "${CADDY_DATA_DIR:-}" ]]; then
  CADDY_DATA_DIR="${STACK_DIR}/caddy/data"
fi

if [[ ! -d "$CADDY_DATA_DIR" ]]; then
  log_warn "Caddy data directory not found at: $CADDY_DATA_DIR"
  log_warn "Specify --data-dir explicitly if your stack lives elsewhere."
  exit 1
fi

ROOT_CERT="${CADDY_DATA_DIR}/caddy/pki/authorities/local/root.crt"
if [[ ! -f "$ROOT_CERT" ]]; then
  alternative="${ROOT_CERT%.crt}.pem"
  if [[ -f "$alternative" ]]; then
    ROOT_CERT="$alternative"
  else
    log_warn "Caddy root certificate not found under ${CADDY_DATA_DIR}/caddy/pki/authorities/local"
    log_warn "Start the Caddy container once so it can provision certificates, then rerun this script."
    exit 1
  fi
fi

log_info "Found Caddy root certificate: $ROOT_CERT"

OS_ID=""
OS_LIKE=""
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_LIKE="${ID_LIKE:-}"
fi

install_debian_ca() {
  if [[ $(id -u) -ne 0 ]]; then
    die "This operation requires root privileges. Re-run with sudo or as root."
  fi

  local target_dir="/usr/local/share/ca-certificates"
  local target_cert="${target_dir}/arrstack-caddy-ca.crt"

  mkdir -p "$target_dir"
  install -m 0644 "$ROOT_CERT" "$target_cert"
  log_info "Installed certificate to $target_cert"

  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates >/dev/null
    log_info "System trust store updated via update-ca-certificates"
  else
    die "update-ca-certificates not found; install 'ca-certificates' package and rerun."
  fi
}

if [[ "$OS_ID" == debian || "$OS_ID" == ubuntu || "$OS_LIKE" == *debian* || "$OS_LIKE" == *ubuntu* ]]; then
  install_debian_ca
  exit 0
fi

cat <<INSTRUCTIONS
Unsupported distribution detected.

To trust the certificate manually, copy:
  $ROOT_CERT
into your OS trust store. Example paths:
  • macOS: Keychain Access → System → drag-and-drop the certificate
  • Fedora/RHEL: /etc/pki/ca-trust/source/anchors/ then run 'update-ca-trust'
  • Arch: /etc/ca-certificates/trust-source/anchors/ then run 'trust extract-compat'

After installation, restart any applications that should trust the Caddy proxy.
INSTRUCTIONS

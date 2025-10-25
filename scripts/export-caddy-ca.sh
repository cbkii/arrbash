#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: ${0##*/} [--stack-dir PATH] [--data-dir PATH] [DEST]

Exports the Caddy internal CA certificate for distribution.
  --stack-dir PATH   Override the ARR stack directory (defaults to script parent)
  --data-dir PATH    Override the Caddy data directory (defaults to detected value)
  -h, --help         Show this help text
  DEST               Destination file for the exported certificate (optional)
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/common.sh
. "${SCRIPT_DIR}/common.sh"

STACK_DIR_OVERRIDE=""
DATA_DIR_OVERRIDE=""
DEST_OVERRIDE=""

while (($#)); do
  case "$1" in
    --stack-dir)
      if [[ $# -lt 2 ]]; then
        die "--stack-dir requires a path argument"
      fi
      STACK_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --data-dir)
      if [[ $# -lt 2 ]]; then
        die "--data-dir requires a path argument"
      fi
      DATA_DIR_OVERRIDE="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      log_warn "Unknown argument: $1"
      usage
      exit 1
      ;;
    *)
      if [[ -n "$DEST_OVERRIDE" ]]; then
        log_warn "Unexpected extra argument: $1"
        usage
        exit 1
      fi
      DEST_OVERRIDE="$1"
      shift
      ;;
  esac
done

if (($#)); then
  log_warn "Unexpected extra argument: $1"
  usage
  exit 1
fi

STACK_DIR="${STACK_DIR_OVERRIDE:-${ARR_STACK_DIR:-${SCRIPT_DIR}/..}}"
STACK_DIR_INPUT="$STACK_DIR"
if ! STACK_DIR="$(cd "$STACK_DIR_INPUT" 2>/dev/null && pwd)"; then
  die "Stack directory not found: ${STACK_DIR_INPUT}"
fi

ARR_STACK_DIR="$STACK_DIR"

ENV_FILE="$(arr_env_file)"
if [[ -f "$ENV_FILE" ]]; then
  if arr_docker_dir="$(get_env_kv "ARR_DOCKER_DIR" "$ENV_FILE" || true)" && [[ -n "$arr_docker_dir" ]]; then
    ARR_DOCKER_DIR="$arr_docker_dir"
  fi
  if [[ -z "${STACK:-}" ]]; then
    if stack_name="$(get_env_kv "STACK" "$ENV_FILE" || true)" && [[ -n "$stack_name" ]]; then
      STACK="$stack_name"
    fi
  fi
fi

STACK="${STACK:-arr}"

if [[ -n "$DATA_DIR_OVERRIDE" ]]; then
  CADDY_DATA_DIR="$DATA_DIR_OVERRIDE"
else
  CADDY_DATA_DIR="$(arr_docker_data_root)/caddy/data"
fi

CA_ROOT="${CADDY_DATA_DIR}/caddy/pki/authorities/local"
CA_FILE="${CA_ROOT}/root.crt"
if [[ ! -f "$CA_FILE" ]]; then
  alternative="${CA_FILE%.crt}.pem"
  if [[ -f "$alternative" ]]; then
    CA_FILE="$alternative"
  fi
fi

if [[ ! -f "$CA_FILE" ]]; then
  log_warn "Caddy internal CA not found under ${CA_ROOT}"
  log_warn "Start the stack at least once so Caddy can generate its local CA."
  exit 1
fi

default_dest_dir="${HOME:-.}"
if [[ -z "$DEST_OVERRIDE" ]]; then
  trimmed="${default_dest_dir%/}"
  if [[ "$trimmed" == "" ]]; then
    DEST_FILE="/${STACK}-ca.crt"
  else
    DEST_FILE="${trimmed}/${STACK}-ca.crt"
  fi
else
  DEST_FILE="$DEST_OVERRIDE"
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
  chmod 640 "$DEST_FILE" 2>/dev/null || true
  log_info "CA certificate exported to ${DEST_FILE}"
  log_info "Install this on LAN devices to trust HTTPS connections"
else
  die "Failed to copy ${CA_FILE} to ${DEST_FILE}"
fi

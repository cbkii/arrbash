#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}"
if ! STACK_DIR="$(cd "${STACK_DIR}" 2>/dev/null && pwd)"; then
  echo "Stack directory not found: ${ARR_STACK_DIR:-${STACK_DIR_DEFAULT}}" >&2
  exit 1
fi
ENV_FILE="${ARR_ENV_FILE:-${STACK_DIR}/.env}"

# shellcheck source=scripts/common.sh
. "${STACK_DIR}/scripts/common.sh"

if [[ ! -f "$ENV_FILE" ]]; then
  die ".env file not found at $ENV_FILE"
fi

if ! command -v docker >/dev/null 2>&1; then
  die "Docker CLI not found on PATH"
fi

log_info "🔧 Fixing Docker image versions..."

USE_LATEST=(
  "lscr.io/linuxserver/prowlarr"
  "lscr.io/linuxserver/bazarr"
)

backup="${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$backup"
log_info "Backed up .env to $backup"

for base_image in "${USE_LATEST[@]}"; do
  log_info "Checking $base_image..."

  case "$base_image" in
    *prowlarr) var_name="PROWLARR_IMAGE" ;;
    *bazarr) var_name="BAZARR_IMAGE" ;;
    *) continue ;;
  esac

  current_image=$(grep "^${var_name}=" "$ENV_FILE" | cut -d= -f2- || true)

  if [[ -z "$current_image" ]]; then
    log_warn "  No ${var_name} entry found in .env; skipping"
    continue
  fi

  if ! docker manifest inspect "$current_image" >/dev/null 2>&1; then
    log_warn "  Current tag doesn't exist: $current_image"
    latest_image="${base_image}:latest"
    log_info "  Updating to: $latest_image"
    sed -i "s|^${var_name}=.*|${var_name}=${latest_image}|" "$ENV_FILE"
  else
    log_info "  ✅ Current tag is valid: $current_image"
  fi

done

log_info "✅ Version fixes complete"
log_info "Run './arrstack.sh --yes' to apply changes"

#!/usr/bin/env bash
# Legacy Caddy CA exporter removed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

set -Eeuo pipefail

log_info "Caddy reverse proxy support has been removed."
log_info "No certificates were exported. Manage HTTPS with your own tooling if required."

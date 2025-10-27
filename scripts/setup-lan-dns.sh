#!/usr/bin/env bash
# Legacy LAN DNS helper removed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

set -Eeuo pipefail

msg "🧭 LAN DNS helper has been removed."
msg "Update /etc/hosts or router DNS overrides manually if you still need custom hostnames."

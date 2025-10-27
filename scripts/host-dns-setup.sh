#!/usr/bin/env bash
# Legacy host DNS helper removed.
# This script now exists solely to preserve CLI compatibility.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

set -Eeuo pipefail

msg "🧭 Host DNS takeover helper has been removed."
msg "Manage system resolv.conf or DNS forwarding with your preferred tooling."
msg "If you previously relied on local_dns, migrate to router- or host-managed DNS instead."

exit 0

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PM_SCRIPT="${REPO_ROOT}/scripts/port-manager/pm-watch.sh"

status_file="$(mktemp)"
trap 'rm -f "$status_file"' EXIT
printf '54321\n' >"$status_file"

export PM_STATUS_FILE="$status_file"
export PM_DRY_RUN=1
export PM_POLL_SECONDS=1
export PM_RUN_ONCE=1
export PM_LOG_LEVEL=debug
export QBT_USER="dummy"
export QBT_PASS="dummy"
export QBT_HOST="127.0.0.1"
export QBT_WEB_PORT=8080
export GLUETUN_CONTROL_PORT=8000
export GLUETUN_API_KEY=""

output="$(sh "$PM_SCRIPT")"

grep -q '"listen_port":54321' <<<"$output"
grep -q '"random_port":false' <<<"$output"

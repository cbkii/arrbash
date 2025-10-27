#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

failures=0

check_grep() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'ok: %s\n' "$message"
  else
    printf 'FAIL: %s\n' "$message" >&2
    printf '       looked for pattern %s in %s\n' "$pattern" "$file" >&2
    failures=$((failures + 1))
  fi
}

check_grep "'\${OPENVPN_USER}+pmp'" "${REPO_ROOT}/scripts/compose-runtime.sh" "OpenVPN runtime username appends +pmp"
check_grep 'WireGuard configuration must be downloaded with Proton' "${REPO_ROOT}/scripts/compose-runtime.sh" "WireGuard NAT-PMP guard present"
check_grep 'WireGuard port forwarding unavailable after' "${REPO_ROOT}/scripts/vpn-auto-control.sh" "WireGuard→OpenVPN fallback recorded"

if ((failures > 0)); then
  exit 1
fi

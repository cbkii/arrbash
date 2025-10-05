#!/usr/bin/env bash
# Roll back host DNS to systemd-resolved safely.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

arr_escalate_privileges "$@" || exit $?

set -Eeuo pipefail

HOST_DNS_VERBOSE="${HOST_DNS_VERBOSE:-0}"

RESOLV="/etc/resolv.conf"
RESOLVED_UNIT="systemd-resolved.service"
STUB="/run/systemd/resolve/stub-resolv.conf"
REAL="/run/systemd/resolve/resolv.conf"

msg "Stopping local_dns (dnsmasq) container (optional)"
if have_command docker || have_command docker-compose; then
  arr_resolve_compose_cmd "${HOST_DNS_VERBOSE}"
  "${DOCKER_COMPOSE_CMD[@]}" stop local_dns || true
else
  warn "Docker not available; skipping local_dns stop"
fi

msg "Re-enabling systemd-resolved"
systemctl enable --now "${RESOLVED_UNIT}"

# Prefer linking /etc/resolv.conf back to the stub file (documented by Debian/systemd manpages)
if [[ -f "${STUB}" ]]; then
  ln -sf "${STUB}" "${RESOLV}"
elif [[ -f "${REAL}" ]]; then
  ln -sf "${REAL}" "${RESOLV}"
else
  warn "Neither stub nor real managed resolv.conf present; leaving current file in place."
fi

msg "Rolled back to systemd-resolved. Current /etc/resolv.conf:"
ls -l "${RESOLV}"
cat "${RESOLV}" 2>/dev/null || true

#!/usr/bin/env bash
# Roll back host DNS to systemd-resolved safely.

set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "$0" "$@"
  fi
  if command -v doas >/dev/null 2>&1; then
    exec doas "$0" "$@"
  fi
  echo "[error] root privileges are required. Re-run with sudo or as root." >&2
  exit 1
fi

RESOLV="/etc/resolv.conf"
RESOLVED_UNIT="systemd-resolved.service"
STUB="/run/systemd/resolve/stub-resolv.conf"
REAL="/run/systemd/resolve/resolv.conf"

echo "[info] Stopping local_dns (dnsmasq) container (optional)"
docker compose stop local_dns || true

echo "[info] Re-enabling systemd-resolved"
systemctl enable --now "${RESOLVED_UNIT}"

# Prefer linking /etc/resolv.conf back to the stub file (documented by Debian/systemd manpages)
if [[ -f "${STUB}" ]]; then
  ln -sf "${STUB}" "${RESOLV}"
elif [[ -f "${REAL}" ]]; then
  ln -sf "${REAL}" "${RESOLV}"
else
  echo "[warn] Neither stub nor real managed resolv.conf present; leaving current file in place."
fi

echo "[done] Rolled back to systemd-resolved. Current /etc/resolv.conf:"
ls -l "${RESOLV}"
cat "${RESOLV}" 2>/dev/null || true

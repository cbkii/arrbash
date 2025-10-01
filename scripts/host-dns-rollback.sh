#!/usr/bin/env bash
# Roll back host DNS to systemd-resolved safely.

set -euo pipefail

HOST_DNS_VERBOSE="${HOST_DNS_VERBOSE:-0}"

resolve_docker_compose_cmd() {
  local -a candidate=()
  local version=""
  local major=""

  if docker compose version >/dev/null 2>&1; then
    candidate=(docker compose)
    version="$(docker compose version --short 2>/dev/null || true)"
    version="${version#v}"
    major="${version%%.*}"
    if [[ -n "$version" && ! "$major" =~ ^[0-9]+$ ]]; then
      version=""
    fi
  fi

  if ((${#candidate[@]} == 0)) && command -v docker-compose >/dev/null 2>&1; then
    version="$(docker-compose version --short 2>/dev/null || true)"
    version="${version#v}"
    major="${version%%.*}"
    if [[ "$major" =~ ^[0-9]+$ ]] && ((major >= 2)); then
      candidate=(docker-compose)
    else
      version=""
    fi
  fi

  if ((${#candidate[@]} == 0)); then
    echo "[error] Docker Compose v2+ is required but not found." >&2
    exit 1
  fi

  DOCKER_COMPOSE_CMD=("${candidate[@]}")

  if [[ "$HOST_DNS_VERBOSE" == "1" ]]; then
    echo "[info] Using Docker Compose command: ${DOCKER_COMPOSE_CMD[*]}${version:+ (version ${version})}"
  fi
}

DOCKER_COMPOSE_CMD=()

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
resolve_docker_compose_cmd
"${DOCKER_COMPOSE_CMD[@]}" stop local_dns || true

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

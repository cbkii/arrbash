#!/usr/bin/env bash
# Safe DNS takeover for arrstackmini host (Debian Bookworm).
# - Backs up existing systemd-resolved & resolv.conf state
# - Validates upstream DNS servers
# - Disables systemd-resolved non-destructively
# - Writes robust /etc/resolv.conf
# - Starts local_dns (dnsmasq) container on :53
# - Provides one-command rollback via scripts/host-dns-rollback.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

arrstack_escalate_privileges "$@"

# -E included to preserve ERR trap behavior in function/subshell contexts (Bash manual §"The ERR Trap").
set -Eeuo pipefail

parse_upstream_list() {
  local raw="$1"
  local -a parts=()
  local -A seen=()

  IFS=',' read -r -a parts <<<"${raw}"

  local entry
  for entry in "${parts[@]}"; do
    entry="$(trim_string "${entry}")"
    [[ -z "${entry}" ]] && continue
    if [[ -z "${seen["${entry}"]:-}" ]]; then
      seen["${entry}"]=1
      printf '%s\n' "${entry}"
    fi
  done
}

# ---- Config knobs (can be overridden in env) ----
LAN_IP="${LAN_IP:-192.168.1.50}"
SUFFIX="${LAN_DOMAIN_SUFFIX:-home.arpa}" # RFC 8375 special-use domain
MAX_HOST_UPSTREAMS=4

UPSTREAM_DNS_SERVERS="${UPSTREAM_DNS_SERVERS:-}" # may be comma-separated
if [[ -z "$UPSTREAM_DNS_SERVERS" ]]; then
  legacy_list="${UPSTREAM_DNS_1:-}"
  if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
    legacy_list+="${legacy_list:+,}${UPSTREAM_DNS_2}"
  fi
  UPSTREAM_DNS_SERVERS="$legacy_list"
fi

mapfile -t FALLBACKS < <(parse_upstream_list "$UPSTREAM_DNS_SERVERS")

if ((${#FALLBACKS[@]} == 0)); then
  FALLBACKS=(1.1.1.1 1.0.0.1)
fi

MODE="${DNS_DISTRIBUTION_MODE:-router}"

# ---- Paths & backups ----
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/arrstackmini-dns-${TS}"
ensure_dir_mode "${BACKUP_DIR}" 700

RESOLV="/etc/resolv.conf"
RESOLVED_UNIT="systemd-resolved.service"
# Common systemd-resolved managed files/symlinks (documented by Debian manpages)
STUB="/run/systemd/resolve/stub-resolv.conf" # lists 127.0.0.53
REAL="/run/systemd/resolve/resolv.conf"      # full upstreams (older dists)

msg "Backing up DNS state into ${BACKUP_DIR}"
cp -a /etc/systemd/resolved.conf "${BACKUP_DIR}/resolved.conf.bak" 2>/dev/null || true
cp -a "${RESOLV}" "${BACKUP_DIR}/resolv.conf.bak" 2>/dev/null || true
if [[ -e "${STUB}" ]]; then
  cp -a "${STUB}" "${BACKUP_DIR}/stub-resolv.conf.bak" 2>/dev/null || true
fi
if [[ -e "${REAL}" && "${REAL}" != "${STUB}" ]]; then
  cp -a "${REAL}" "${BACKUP_DIR}/resolved-upstream.conf.bak" 2>/dev/null || true
fi
ls -l "${RESOLV}" || true

msg "Capturing current upstreams from systemd-resolved (if present)"
CUR_DNS="$(resolvectl dns 2>/dev/null | awk '{for (i=2;i<=NF;i++) print $i}' || true)"
CUR_SEARCH="$(resolvectl domain 2>/dev/null | awk '{for (i=2;i<=NF;i++) print $i}' || true)"

# Also parse existing resolv.conf if it’s a real file
if [[ ! -L "${RESOLV}" && -f "${RESOLV}" ]]; then
  RESOLV_NS="$(awk '/^nameserver/{print $2}' "${RESOLV}" || true)"
  RESOLV_SEARCH="$(awk '/^search/{for (i=2;i<=NF;i++) print $i}' "${RESOLV}" || true)"
else
  RESOLV_NS=""
  RESOLV_SEARCH=""
fi

# Derive gateway router IP (optional upstream candidate)
GATEWAY_IP="$(ip route | awk '/default/{print $3; exit}' || true)"

# Merge & de-dup upstream candidates, preferring current, then gateway, then fallbacks
CANDIDATES="$(printf "%s\n%s\n%s\n%s\n" \
  "${CUR_DNS}" "${RESOLV_NS}" "${GATEWAY_IP}" "${FALLBACKS[*]}" \
  | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '!seen[$0]++')"

# Validate candidates with quick dig (A query) — keep the first responders
VALID=()
for ip in ${CANDIDATES}; do
  if command -v dig >/dev/null 2>&1; then
    if dig +time=1 +tries=1 @"${ip}" cloudflare.com A >/dev/null 2>&1; then
      VALID+=("${ip}")
    fi
  else
    # Fallback: simple UDP check with nc if 'dig' missing
    if timeout 2 bash -c "</dev/udp/${ip}/53" 2>/dev/null; then
      VALID+=("${ip}")
    fi
  fi
  if ((${#VALID[@]} >= MAX_HOST_UPSTREAMS)); then
    break
  fi
done

# Ensure we have at least one upstream
if ((${#VALID[@]} == 0)); then
  VALID=("${FALLBACKS[@]}")
fi

if ((${#VALID[@]} > MAX_HOST_UPSTREAMS)); then
  VALID=("${VALID[@]:0:MAX_HOST_UPSTREAMS}")
fi

msg "Selected upstream DNS: ${VALID[*]}"

# Build search path: prefer existing + our suffix (avoid dupes)
SEARCH_MERGED="$(printf "%s\n%s\n" "${CUR_SEARCH}" "${RESOLV_SEARCH}" | tr ' ' '\n' | awk 'NF' | awk '!seen[$0]++')"
# Prepend our suffix if not present
if ! printf '%s\n' "${SEARCH_MERGED}" | grep -qx "${SUFFIX}"; then
  if [[ -n "${SEARCH_MERGED}" ]]; then
    SEARCH_MERGED="${SUFFIX}"$'\n'"${SEARCH_MERGED}"
  else
    SEARCH_MERGED="${SUFFIX}"
  fi
fi
SEARCH_LINE="$(printf '%s\n' "${SEARCH_MERGED}" | paste -sd' ' -)"

# ---- Disable systemd-resolved cleanly (free :53) ----
# (Documented behaviour: it maintains stub file and typically symlinks /etc/resolv.conf there.)
# Debian manpages: systemd-resolved(8), resolved.conf(5)
msg "Preparing to free port 53 from ${RESOLVED_UNIT}"
if systemctl is-active --quiet "${RESOLVED_UNIT}"; then
  msg "Stopping ${RESOLVED_UNIT}"
  systemctl stop "${RESOLVED_UNIT}"
else
  msg "${RESOLVED_UNIT} already stopped"
fi

if systemctl is-enabled --quiet "${RESOLVED_UNIT}"; then
  msg "Disabling ${RESOLVED_UNIT}"
  systemctl disable "${RESOLVED_UNIT}"
else
  msg "${RESOLVED_UNIT} already disabled"
fi

# Replace /etc/resolv.conf (remove symlink if present)
if [[ -L "${RESOLV}" ]]; then
  target="$(readlink -f "${RESOLV}" 2>/dev/null || true)"
  case "${target}" in
    "${STUB}")
      msg "/etc/resolv.conf is a symlink to systemd-resolved stub (${STUB}); removing"
      ;;
    "${REAL}")
      msg "/etc/resolv.conf is a symlink to resolved upstreams (${REAL}); removing"
      ;;
    "")
      msg "/etc/resolv.conf is a symlink; removing"
      ;;
    *)
      msg "/etc/resolv.conf is a symlink to ${target}; removing"
      ;;
  esac
  rm -f "${RESOLV}"
fi

# Write a robust, static resolv.conf
# man resolv.conf(5): nameserver/search/options
{
  echo "# Generated by arrstackmini host-dns-setup.sh on ${TS}"
  echo "# Upstreams selected from: current systemd-resolved, existing resolv.conf, gateway, fallbacks."
  echo "search ${SEARCH_LINE}"
  for ip in "${VALID[@]}"; do
    echo "nameserver ${ip}"
  done
  # Reasonable defaults; ndots lowers false-positive suffix expansions; timeout/retries conservative
  echo "options timeout:2 attempts:2 rotate"
} >"${RESOLV}"

ensure_file_mode "${RESOLV}" 644

msg "New /etc/resolv.conf:"
cat "${RESOLV}"

# ---- Start/Restart local_dns (dnsmasq) container ----
msg "Starting local_dns container"
docker compose up -d local_dns

msg "Verifying port 53 is bound by dnsmasq"
if command -v ss >/dev/null 2>&1; then
  if [[ -z "$(ss -H -lnu 'sport = :53' 2>/dev/null)" && -z "$(ss -H -lnt 'sport = :53' 2>/dev/null)" ]]; then
    die ":53 not bound; check for conflicting services"
  fi
elif command -v lsof >/dev/null 2>&1; then
  if [[ -z "$(lsof -nP -iUDP:53 2>/dev/null)" && -z "$(lsof -nP -iTCP:53 -sTCP:LISTEN 2>/dev/null)" ]]; then
    die ":53 not bound; check for conflicting services"
  fi
else
  warn "Unable to verify port 53 binding (missing 'ss' and 'lsof')."
fi

# ---- Functional tests ----
set +e
msg "Testing DNS -> qbittorrent.${SUFFIX} via ${LAN_IP}"
dig +short @"${LAN_IP}" "qbittorrent.${SUFFIX}"
DIG_RC=$?
msg "Testing HTTPS (Caddy) -> qbittorrent.${SUFFIX} (forced resolve)"
curl -kI --max-time 5 --resolve "qbittorrent.${SUFFIX}:443:${LAN_IP}" "https://qbittorrent.${SUFFIX}/"
CURL_RC=$?
set -e

if [[ "${DIG_RC}" -ne 0 ]]; then
  warn "dig failed; check local_dns logs: docker logs -n 200 arr_local_dns"
fi
if [[ "${CURL_RC}" -ne 0 ]]; then
  warn "curl HTTPS test failed; check Caddy/gluetun/ports"
fi

msg "Host DNS takeover complete. Backups in ${BACKUP_DIR}"
if [[ "$MODE" == "per-device" ]]; then
  msg "Per-device DNS: set DNS=${LAN_IP} on important clients and disable custom Private DNS on Android."
else
  msg "Router DHCP: set DNS server = ${LAN_IP} so LAN clients use local DNS automatically."
fi

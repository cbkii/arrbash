#!/usr/bin/env bash
# shellcheck enable=require-variable-braces
# shellcheck enable=quote-safe-variables

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

# Escalation insertion point: call this at top of scripts that need root
arrstack_escalate_privileges "$@"

set -Eeuo pipefail

log() {
  msg "$@"
}

is_debian_like() {
  if [[ ! -r /etc/os-release ]]; then
    return 1
  fi

  # shellcheck disable=SC1091
  . /etc/os-release

  local id_like_lower="${ID_LIKE:-}" id_lower="${ID:-}"
  id_like_lower="${id_like_lower,,}"
  id_lower="${id_lower,,}"

  if [[ "${id_lower}" == debian* || "${id_lower}" == raspbian* ]]; then
    return 0
  fi

  if [[ "${id_like_lower}" == *debian* || "${id_like_lower}" == *raspbian* ]]; then
    return 0
  fi

  return 1
}

validate_ipv4() {
  local ip="$1"
  if [[ ! "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    die "Invalid IPv4 address: ${ip}"
  fi

  local segment
  IFS='.' read -r -a segment <<<"${ip}"
  for part in "${segment[@]}"; do
    if ((part < 0 || part > 255)); then
      die "Invalid IPv4 segment in ${ip}"
    fi
  done
}

fuzzy_remove_entries() {
  local file="$1"
  local begin_marker="$2"
  local end_marker="$3"

  awk -v begin="${begin_marker}" -v end="${end_marker}" '
    BEGIN { skip=0 }
    $0 == begin { skip=1; next }
    $0 == end { skip=0; next }
    skip { next }
    {
      line = tolower($0)
      if (index(line, "arrstack-managed") > 0) {
        next
      }
      print $0
    }
  ' "${file}"
}

rewrite_hosts_file() {
  local file="$1"
  local content="$2"
  local tmp

  if ! tmp="$(arrstack_mktemp_file "${file}.XXXXXX")"; then
    die "Unable to create temporary file for ${file}"
  fi
  trap 'rm -f "${tmp}"' EXIT

  printf '%s\n' "${content}" >"${tmp}"
  chmod 644 "${tmp}" 2>/dev/null || true

  if ! cat "${tmp}" >"${file}" 2>/dev/null; then
    rm -f "${tmp}"
    trap - EXIT
    die "Failed to update ${file}; try running with elevated privileges"
  fi

  rm -f "${tmp}"
  trap - EXIT
}

configure_docker_dns() {
  local lan_ip="$1"
  local daemon_json="/etc/docker/daemon.json"

  if [[ -z "${lan_ip}" || "${lan_ip}" == "0.0.0.0" ]]; then
    warn "LAN IP not provided; skipping Docker DNS configuration."
    return 0
  fi

  local -a dns_chain=()
  dns_chain+=("${lan_ip}")

  local csv="${UPSTREAM_DNS_SERVERS:-}"
  if [[ -z "${csv}" ]]; then
    if [[ -n "${UPSTREAM_DNS_1:-}" ]]; then
      csv+="${UPSTREAM_DNS_1}"
    fi
    if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
      csv+="${csv:+,}${UPSTREAM_DNS_2}"
    fi
  fi
  if [[ -z "${csv}" ]]; then
    csv="1.1.1.1,1.0.0.1"
  fi

  IFS=',' read -r -a _upstreams <<<"${csv}"
  declare -A seen=()
  local resolver
  for resolver in "${_upstreams[@]}"; do
    resolver="$(trim_string "${resolver}")"
    [[ -z "${resolver}" ]] && continue
    if [[ -z "${seen["${resolver}"]:-}" ]]; then
      seen["${resolver}"]=1
      dns_chain+=("${resolver}")
    fi
  done

  local dns_json="[]"
  if ((${#dns_chain[@]} > 0)); then
    local first=1
    dns_json="["
    for resolver in "${dns_chain[@]}"; do
      [[ -z "${resolver}" ]] && continue
      if ((first)); then
        dns_json+="\"${resolver}\""
        first=0
      else
        dns_json+=", \"${resolver}\""
      fi
    done
    dns_json+="]"
  fi

  local rootless=0
  if command -v docker >/dev/null 2>&1; then
    local security_opts
    security_opts="$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || echo '')"
    if [[ "${security_opts}" == *"rootless"* ]]; then
      rootless=1
    fi
  fi

  if ((rootless)); then
    warn "Rootless Docker detected; configure ~/.config/docker/daemon.json manually with DNS ${dns_chain[*]}."
    return 0
  fi

  local tmp=""
  if ! tmp="$(arrstack_mktemp_file "${daemon_json}.XXXXXX" 644)"; then
    warn "Unable to create temporary file for ${daemon_json}; skipping Docker DNS configuration."
    return 1
  fi

  if [[ -f "${daemon_json}" ]]; then
    local backup
    backup="${daemon_json}.arrstack.$(date +%Y%m%d-%H%M%S).bak"
    if cp "${daemon_json}" "${backup}" 2>/dev/null; then
      log "Backed up existing ${daemon_json} to ${backup}"
    else
      warn "Failed to back up ${daemon_json}; continuing with update."
    fi

    if command -v jq >/dev/null 2>&1; then
      if ! jq --argjson dns "${dns_json}" '.dns = $dns' "${daemon_json}" >"${tmp}" 2>/dev/null; then
        warn "Failed to update ${daemon_json} with jq; leaving existing configuration untouched."
        rm -f "${tmp}"
        return 1
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if ! DNS_JSON="${dns_json}" python3 - "${daemon_json}" "${tmp}" <<'PYTHON'
import json, os, sys
source = sys.argv[1]
target = sys.argv[2]
dns = json.loads(os.environ["DNS_JSON"])
try:
    with open(source, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

data["dns"] = dns
with open(target, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
PYTHON
      then
        warn "Failed to update ${daemon_json} with python3; leaving existing configuration untouched."
        rm -f "${tmp}"
        return 1
      fi
    else
      warn "Neither jq nor python3 available; cannot update ${daemon_json}."
      rm -f "${tmp}"
      return 1
    fi
  else
    if ! printf '{"dns": %s}\n' "${dns_json}" >"${tmp}" 2>/dev/null; then
      warn "Failed to write Docker daemon DNS configuration."
      rm -f "${tmp}"
      return 1
    fi
  fi

  chmod 644 "${tmp}" 2>/dev/null || true
  if ! mv -f "${tmp}" "${daemon_json}" 2>/dev/null; then
    warn "Unable to install ${daemon_json}; check permissions."
    rm -f "${tmp}"
    return 1
  fi

  log "Configured Docker daemon DNS chain: ${dns_chain[*]}"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet docker; then
      if ! systemctl reload docker >/dev/null 2>&1; then
        warn "systemctl reload docker failed; restart Docker manually to apply DNS changes."
      else
        log "Reloaded Docker daemon with updated DNS chain."
      fi
    else
      warn "Docker service not active under systemd; restart Docker manually to apply DNS changes."
    fi
  else
    warn "systemctl not available; restart Docker manually to apply DNS changes."
  fi

  return 0
}

main() {
  local IFS=$'\n\t'
  if [[ $# -lt 2 ]]; then
    die "Usage: $0 <domain_suffix> <lan_ip>"
  fi

  local domain_suffix="$1"
  local lan_ip="$2"

  if [[ -z "${domain_suffix}" ]]; then
    die "Domain suffix is required"
  fi

  if [[ -z "${lan_ip}" ]]; then
    die "LAN IP is required"
  fi

  if [[ "${lan_ip}" == "0.0.0.0" ]]; then
    warn "LAN_IP is 0.0.0.0; skipping hosts update"
    exit 3
  fi

  if ! is_debian_like; then
    log "Non-Debian system detected; skipping hosts update"
    exit 0
  fi

  validate_ipv4 "${lan_ip}"

  local hosts_file="/etc/hosts"
  if [[ ! -w "${hosts_file}" ]]; then
    if [[ ${EUID} -ne 0 ]]; then
      die "Insufficient permissions to modify ${hosts_file}; rerun with sudo"
    fi
  fi

  local begin_marker="# >>> arrstack-managed hosts >>>"
  local end_marker="# <<< arrstack-managed hosts <<<"

  local sanitized
  sanitized="$(fuzzy_remove_entries "${hosts_file}" "${begin_marker}" "${end_marker}")"

  local services=(qbittorrent sonarr radarr prowlarr bazarr flaresolverr gluetun caddy)
  local host_line
  host_line="${lan_ip}"
  local service
  for service in "${services[@]}"; do
    host_line+=" ${service}.${domain_suffix}"
  done
  host_line+=" # arrstack-managed ${domain_suffix}"

  local newline=$'\n'
  local new_content
  if [[ -n "${sanitized}" ]]; then
    new_content="${sanitized}${newline}${begin_marker}${newline}${host_line}${newline}${end_marker}"
  else
    new_content="${begin_marker}${newline}${host_line}${newline}${end_marker}"
  fi

  rewrite_hosts_file "${hosts_file}" "${new_content}"
  log "Updated ${hosts_file} with arrstack-managed host entries"

  configure_docker_dns "${lan_ip}" || true
}

main "$@"

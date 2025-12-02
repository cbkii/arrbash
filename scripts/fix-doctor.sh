#!/usr/bin/env bash
# -E included to preserve ERR trap behavior in function/subshell contexts (Bash manual §"The ERR Trap").
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/stack-common.sh
. "${REPO_ROOT}/scripts/stack-common.sh"

# shellcheck source=scripts/env-userconf.sh
. "${REPO_ROOT}/scripts/env-userconf.sh"

if [[ -f "${REPO_ROOT}/arrconf/userr.conf.defaults.sh" ]]; then
  set +u
  # shellcheck disable=SC1091
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
  set -u
fi

arr_resolve_userconf_paths ARR_USERCONF_PATH ARR_USERCONF_OVERRIDE_PATH

if [[ -f "${ARR_USERCONF_PATH}" ]]; then
  set +u
  # shellcheck disable=SC1091
  # shellcheck source=/dev/null
  . "${ARR_USERCONF_PATH}"
  set -u
fi

doctor_ok() {
  msg "$*"
}

doctor_fail() {
  warn "$*"
}

doctor_warn() {
  warn "$*"
}

doctor_note() {
  msg "$*"
}

# Reports whether a specific service port is free/bound, noting missing tooling
report_port() {
  local label="$1"
  local proto="$2"
  local bind_ip="$3"
  local port="$4"

  local details=""
  local rc
  if arr_port_probe_conflicts "$proto" "$port" details "$bind_ip"; then
    rc=0
  else
    rc=$?
  fi

  case "$rc" in
    0)
      printf -v message '%s port %s/%s is already in use on %s.' "$label" "$port" "${proto^^}" "$bind_ip"
      doctor_warn "$message"
      if [[ -n "$details" ]]; then
        while IFS= read -r entry; do
          [[ -z "$entry" ]] && continue
          doctor_warn "Listener: ${entry}"
        done <<<"$(printf '%s\n' "$details" | head -n 3)"
      fi
      ;;
    1)
      printf -v message '%s port %s/%s is free on %s.' "$label" "$port" "${proto^^}" "$bind_ip"
      doctor_ok "$message"
      ;;
    2)
      printf -v message 'Cannot check %s (%s %s:%s): missing port inspection tooling.' "$label" "${proto^^}" "$bind_ip" "$port"
      doctor_warn "$message"
      ;;
  esac
}

# Lists normalized bind addresses for a port using ss or lsof output
port_bind_addresses() {
  local proto="$1"
  local port="$2"

  if have_command ss; then
    local flag="lnt"
    if [[ "$proto" == "udp" ]]; then
      flag="lnu"
    fi

    ss -H -${flag} "sport = :${port}" 2>/dev/null \
      | awk '{print $4}' \
      | while IFS= read -r addr; do
        [[ -z "$addr" ]] && continue
        printf '%s\n' "$(normalize_bind_address "${addr%:*}")"
      done
  elif have_command lsof; then
    local -a spec
    if [[ "$proto" == "udp" ]]; then
      spec=(-iUDP:"${port}")
    else
      spec=(-iTCP:"${port}" -sTCP:LISTEN)
    fi

    lsof -nP "${spec[@]}" 2>/dev/null \
      | awk 'NR>1 {print $9}' \
      | while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        name="${name%%->*}"
        name="${name% (LISTEN)}"
        printf '%s\n' "$(normalize_bind_address "${name%:*}")"
      done
  fi
}

# Audits exposed services versus expected LAN bindings and warns on unsafe listeners
check_network_security() {
  step "Auditing bind addresses for safety"

  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    doctor_warn "Cannot verify LAN bindings because LAN_IP is unset or 0.0.0.0."
  fi

  if [[ -z "${EXPOSE_DIRECT_PORTS:-}" ]]; then
    EXPOSE_DIRECT_PORTS=0
  fi

  local qbt_http_port="${QBT_PORT:-${QBT_INT_PORT:-8080}}"

  local -a direct_ports=("${qbt_http_port}" "${SONARR_PORT}" "${RADARR_PORT}" "${PROWLARR_PORT}" "${BAZARR_PORT}" "${FLARR_PORT}")
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    local sab_port_value="${SABNZBD_PORT:-}"
    if [[ -z "$sab_port_value" ]]; then
      sab_port_value="${SABNZBD_INT_PORT:-8081}"
    fi
    direct_ports+=("${sab_port_value}")
  fi

  if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
    if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
      doctor_warn "Direct ports enabled but LAN_IP is not set; they would bind to 0.0.0.0."
    else
      local port
      for port in "${direct_ports[@]}"; do
        local -a bindings=()
        mapfile -t bindings < <(port_bind_addresses tcp "$port")
        if ((${#bindings[@]} == 0)); then
          doctor_warn "Expected listener on ${LAN_IP}:${port} but nothing is bound."
          continue
        fi
        local had_lan=0
        local has_wildcard=0
        local addr
        for addr in "${bindings[@]}"; do
          case "$addr" in
            "${LAN_IP}")
              had_lan=1
              ;;
            "0.0.0.0" | "::" | "*")
              has_wildcard=1
              ;;
          esac
        done
        if ((has_wildcard)); then
          doctor_warn "Port ${port}/TCP is bound to 0.0.0.0; restrict it to LAN_IP=${LAN_IP} to avoid WAN exposure."
        fi
        if ((had_lan == 0)); then
          doctor_warn "Port ${port}/TCP does not appear to bind to ${LAN_IP}; confirm your port mappings."
        fi
      done
    fi
  else
    local port
    for port in "${direct_ports[@]}"; do
      local -a bindings=()
      mapfile -t bindings < <(port_bind_addresses tcp "$port")
      if ((${#bindings[@]} > 0)); then
        doctor_warn "Direct ports disabled but port ${port}/TCP is still listening on ${bindings[*]}."
      fi
    done
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    local qbt_conf=""
    local docker_root
    docker_root="$(arr_docker_data_root)"

    arr_qbt_migrate_legacy_conf "$docker_root"
    local qbt_conf_new
    local qbt_conf_legacy

    qbt_conf_new="$(arr_qbt_conf_path "$docker_root")"
    qbt_conf_legacy="$(arr_qbt_legacy_conf_path "$docker_root")"
    if [[ -f "$qbt_conf_new" ]]; then
      qbt_conf="$qbt_conf_new"
    elif [[ -f "$qbt_conf_legacy" ]]; then
      qbt_conf="$qbt_conf_legacy"
      doctor_warn "Legacy qBittorrent.conf detected at ${qbt_conf_legacy}; migrate to ${qbt_conf_new}."
    fi
    if [[ -n "$qbt_conf" && -f "$qbt_conf" ]]; then
      local ui_port
      ui_port="$(arr_read_sensitive_file "$qbt_conf" | grep '^WebUI\\Port=' | cut -d= -f2- | tr -d '\r' || true)"
      local host_port="${QBT_PORT:-${QBT_INT_PORT:-8080}}"
      if [[ -n "$ui_port" && "$ui_port" != "$host_port" ]]; then
        doctor_warn "qBittorrent WebUI internal port is ${ui_port} but host mapping expects ${host_port}"
      fi
    fi
  fi

  local -a gluetun_bindings=()
  mapfile -t gluetun_bindings < <(port_bind_addresses tcp "$GLUETUN_CONTROL_PORT")
  local unsafe_gluetun=0
  local bind
  for bind in "${gluetun_bindings[@]:-}"; do
    if [[ -n "$bind" && "$bind" != "${LOCALHOST_IP}" ]]; then
      unsafe_gluetun=1
      break
    fi
  done
  if ((unsafe_gluetun)); then
    doctor_warn "Gluetun control API is reachable on ${gluetun_bindings[*]}; restrict it to LOCALHOST_IP=${LOCALHOST_IP}."
  fi

  doctor_note "HTTPS termination is not managed by arrbash; review any listeners on ports 80/443."
}

test_lan_connectivity() {
  step "Testing LAN accessibility..."

  doctor_note "LAN exposure relies on direct host ports; validate reachability as needed."
}

# Verifies upstream DNS responders and surfaces missing tooling
doctor_dns_health() {
  step "Checking upstream DNS reachability"

  local -a resolvers=()
  mapfile -t resolvers < <(collect_upstream_dns_servers)

  if ((${#resolvers[@]} == 0)); then
    doctor_warn "No upstream DNS servers defined. Configure UPSTREAM_DNS_SERVERS or legacy UPSTREAM_DNS_1/2."
    return
  fi

  local resolver
  local tool_missing=0
  for resolver in "${resolvers[@]}"; do
    if probe_dns_resolver "$resolver" "cloudflare.com" 2; then
      doctor_ok "Resolver ${resolver} responded within 2s"
      continue
    fi

    local rc=$?
    if ((rc == 2)); then
      doctor_warn "DNS probe skipped: install dig, drill, kdig, or nslookup to verify upstream reachability."
      tool_missing=1
      break
    fi

    doctor_warn "Resolver ${resolver} did not answer probe queries (check connectivity or replace it)."
  done

  if ((tool_missing)); then
    doctor_note "Configured upstream DNS servers: ${resolvers[*]}"
  fi
}

# Compares Docker daemon DNS configuration with expected LAN/upstream chain
check_docker_dns_configuration() {
  step "Inspecting Docker daemon DNS settings"

  if ! command -v docker >/dev/null 2>&1; then
    doctor_warn "docker CLI not available; cannot inspect daemon DNS configuration."
    return
  fi

  local dns_json
  if ! dns_json="$(docker info --format '{{json .DNS}}' 2>/dev/null)"; then
    doctor_warn "Unable to query docker info; ensure Docker is running and accessible."
    return
  fi

  if [[ -z "$dns_json" || "$dns_json" == "null" ]]; then
    doctor_warn "Docker daemon reports no custom DNS servers; containers may inherit host defaults."
    return
  fi

  local -a docker_dns=()
  if command -v jq >/dev/null 2>&1; then
    mapfile -t docker_dns < <(docker info --format '{{json .DNS}}' | jq -r '.[]' 2>/dev/null || true)
  else
    dns_json="${dns_json#[}"
    dns_json="${dns_json%]}"
    IFS=',' read -r -a docker_dns <<<"${dns_json}"
    local idx trimmed
    for idx in "${!docker_dns[@]}"; do
      trimmed="$(trim_string "${docker_dns[idx]//\"/}")"
      docker_dns[idx]="${trimmed}"
    done
  fi

  local -a cleaned=()
  local entry
  for entry in "${docker_dns[@]}"; do
    [[ -z "${entry}" ]] && continue
    cleaned+=("${entry}")
  done
  docker_dns=("${cleaned[@]}")

  if ((${#docker_dns[@]} == 0)); then
    doctor_warn "Docker daemon DNS list empty; containers may fall back to host defaults."
    return
  fi

  doctor_note "Docker daemon DNS chain: ${docker_dns[*]}"

  local -a expected=()
  if [[ -n "${LAN_IP:-}" && "${LAN_IP}" != "0.0.0.0" ]]; then
    expected+=("${LAN_IP}")
  fi
  local -a upstream_chain=()
  mapfile -t upstream_chain < <(collect_upstream_dns_servers)
  expected+=("${upstream_chain[@]}")

  if ((${#expected[@]} > 0)); then
    if [[ "${docker_dns[*]}" == "${expected[*]}" ]]; then
      doctor_ok "Docker DNS matches expected LAN + upstream resolver order."
    else
      doctor_warn "Docker DNS order differs from expected (${expected[*]})."
    fi
  fi
}

doctor_check_sabnzbd() {
  if [[ "${SABNZBD_ENABLED:-0}" != "1" ]]; then
    doctor_note "SABnzbd disabled"
    return 0
  fi

  if ! command -v jq >/dev/null 2>&1; then
    doctor_fail "jq missing (required for SAB parsing)"
    return 1
  fi

  local helper="${ARR_STACK_DIR%/}/scripts/sab-helper.sh"
  if [[ ! -x "$helper" ]]; then
    helper="${REPO_ROOT}/scripts/stack-sab-helper.sh"
  fi

  if [[ ! -x "$helper" ]]; then
    doctor_warn "SABnzbd helper missing; skipping API check"
    return 0
  fi

  local sab_helper_scheme="${SABNZBD_HELPER_SCHEME:-http}"
  local sab_helper_host="${SABNZBD_HOST:-${LOCALHOST_IP:-localhost}}"
  local sab_helper_url="${sab_helper_scheme}://${sab_helper_host}:${SABNZBD_PORT}"

  local sab_status=0
  if "$helper" version >/dev/null 2>&1; then
    doctor_ok "SABnzbd API reachable"
  else
    sab_status=1
    doctor_fail "SABnzbd unreachable at ${sab_helper_url}"
  fi

  local sab_api_state="${ARR_SAB_API_KEY_STATE:-empty}"
  case "$sab_api_state" in
    placeholder)
      doctor_warn "SABnzbd API key still placeholder; update Settings → General"
      ;;
    empty)
      doctor_warn "SABnzbd API key not configured; helper uploads will fail"
      ;;
  esac

  if [[ "${SABNZBD_USE_VPN:-0}" != "1" && "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    doctor_warn "SABnzbd exposed on LAN; ensure access is limited to trusted networks."
  fi

  if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
    local gluetun_disabled=0
    if [[ "${ENABLE_GLUETUN:-1}" == "0" ]]; then
      gluetun_disabled=1
    fi
    case "${VPN_SERVICE_PROVIDER:-protonvpn}" in
      '' | none | disabled | off)
        gluetun_disabled=1
        ;;
    esac

    if ((gluetun_disabled)); then
      doctor_warn "SABNZBD_USE_VPN=1 but Gluetun not enabled"
    else
      local compose_file="${ARR_STACK_DIR%/}/docker-compose.yml"
      if [[ ! -f "$compose_file" ]] || ! grep -Eq '^[[:space:]]*gluetun:' "$compose_file"; then
        doctor_warn "SABNZBD_USE_VPN=1 but Gluetun not enabled"
      fi
    fi
  fi

  return $sab_status
}

LAN_IP="${LAN_IP:-}"
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS:-0}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
QBT_INT_PORT="${QBT_INT_PORT:-8080}"
QBT_PORT="${QBT_PORT:-${QBT_INT_PORT}}"
SONARR_INT_PORT="${SONARR_INT_PORT:-8989}"
SONARR_PORT="${SONARR_PORT:-${SONARR_INT_PORT}}"
RADARR_INT_PORT="${RADARR_INT_PORT:-7878}"
RADARR_PORT="${RADARR_PORT:-${RADARR_INT_PORT}}"
PROWLARR_INT_PORT="${PROWLARR_INT_PORT:-9696}"
PROWLARR_PORT="${PROWLARR_PORT:-${PROWLARR_INT_PORT}}"
BAZARR_INT_PORT="${BAZARR_INT_PORT:-6767}"
BAZARR_PORT="${BAZARR_PORT:-${BAZARR_INT_PORT}}"
FLARR_INT_PORT="${FLARR_INT_PORT:-8191}"
FLARR_PORT="${FLARR_PORT:-${FLARR_INT_PORT}}"
SABNZBD_INT_PORT="${SABNZBD_INT_PORT:-8081}"

if [[ "${ARR_INTERNAL_PORT_CONFLICTS:-0}" == "1" ]]; then
  doctor_warn "Duplicate host port assignments detected in configuration:"
  if [[ -n "${ARR_INTERNAL_PORT_CONFLICT_DETAIL:-}" ]]; then
    while IFS= read -r conflict_line; do
      [[ -z "$conflict_line" ]] && continue
      msg "• ${conflict_line}"
    done < <(printf '%s\n' "${ARR_INTERNAL_PORT_CONFLICT_DETAIL}")
  fi
fi

doctor_note "Local DNS helper removed; skipping port 53 availability checks."
doctor_note "LAN reverse-proxy shortcuts are no longer generated. Use direct host:port access."
printf -v message 'LAN IP: %s' "${LAN_IP:-<unset>}"
doctor_note "$message"
doctor_dns_health
check_docker_dns_configuration

step "Checking host reachability"
if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  doctor_warn "LAN_IP is unset or 0.0.0.0; skipping ping check."
elif have_command ping; then
  if ping -c 1 -W 1 "${LAN_IP}" >/dev/null 2>&1; then
    doctor_ok "Host responded to ping at ${LAN_IP}"
  else
    doctor_warn "Host did not respond to ping at ${LAN_IP}"
  fi
else
  doctor_warn "'ping' command not found; skipping reachability test."
fi

if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  doctor_warn "Skipping LAN port checks because LAN_IP is not set to a specific address."
else
  if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
    report_port "qBittorrent UI" tcp "${LAN_IP}" "${QBT_PORT}"
    report_port "Sonarr UI" tcp "${LAN_IP}" "${SONARR_PORT}"
    report_port "Radarr UI" tcp "${LAN_IP}" "${RADARR_PORT}"
    report_port "Prowlarr UI" tcp "${LAN_IP}" "${PROWLARR_PORT}"
    report_port "Bazarr UI" tcp "${LAN_IP}" "${BAZARR_PORT}"
    report_port "FlareSolverr" tcp "${LAN_IP}" "${FLARR_PORT}"
  else
    doctor_note "Direct LAN ports are disabled (EXPOSE_DIRECT_PORTS=0)."
  fi

  doctor_note "Reverse proxy helper removed; qBittorrent is reachable via Gluetun-published ports."
fi

check_network_security

if [[ -n "${LOCALHOST_IP}" ]]; then
  report_port "Gluetun control" tcp "${LOCALHOST_IP}" "${GLUETUN_CONTROL_PORT}"
fi

doctor_note "DNS hostname checks skipped: local DNS helper removed."

test_lan_connectivity

doctor_check_sabnzbd

lan_target="${LAN_IP:-<unset>}"
step "From another LAN device you can try:"
if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
  msg "curl -I http://${lan_target}:${QBT_PORT}"
  msg "curl -I http://${lan_target}:${SONARR_PORT}"
  msg "curl -I http://${lan_target}:${RADARR_PORT}"
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    msg "curl -I http://${lan_target}:${SABNZBD_PORT}"
  fi
else
  msg "(Direct ports disabled; set EXPOSE_DIRECT_PORTS=1 to enable IP:PORT access.)"
fi

doctor_note "Local DNS helper removed; rely on LAN IP access instead."

exit 0

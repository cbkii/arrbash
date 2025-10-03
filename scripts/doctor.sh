#!/usr/bin/env bash
# -E included to preserve ERR trap behavior in function/subshell contexts (Bash manual §"The ERR Trap").
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

if [[ -f "${REPO_ROOT}/arrconf/userr.conf.defaults.sh" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=arrconf/userr.conf.defaults.sh
  . "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"
fi

ARR_USERCONF_PATH="${ARR_USERCONF_PATH:-${ARR_BASE:-${HOME}/srv}/userr.conf}"
ARR_USERCONF_SOURCE="${ARR_USERCONF_PATH}"

if [[ -f "${ARR_USERCONF_PATH}" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=/dev/null
  . "${ARR_USERCONF_PATH}"
fi

if [[ "${ARR_USERCONF_PATH}" == "${ARR_USERCONF_SOURCE}" ]]; then
  ARR_USERCONF_PATH="${ARR_BASE:-${HOME}/srv}/userr.conf"
fi
unset ARR_USERCONF_SOURCE

# Uses ss to determine if a port is bound at a conflicting address
port_in_use_with_ss() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  local flag="t"
  if [[ "$proto" == "udp" ]]; then
    flag="u"
  fi

  local output
  output="$(ss -H -ln${flag} "sport = :${port}" 2>/dev/null || true)"
  if [[ -z "$output" ]]; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local addr_field
    addr_field="$(awk '{print $5}' <<<"$line")"
    if [[ -z "$addr_field" ]]; then
      addr_field="$(awk '{print $4}' <<<"$line")"
    fi
    [[ -z "$addr_field" ]] && continue
    local host="${addr_field%:*}"
    local port_field="${addr_field##*:}"
    host="${host%%%*}"
    if [[ "$port_field" != "$port" ]]; then
      continue
    fi
    if address_conflicts "$bind_ip" "$host"; then
      return 0
    fi
  done <<<"$output"

  return 1
}

# Uses lsof to detect port conflicts when ss is unavailable
port_in_use_with_lsof() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  local -a cmd=(lsof -nP)
  if [[ "$proto" == "udp" ]]; then
    cmd+=(-iUDP:"${port}")
  else
    cmd+=(-iTCP:"${port}" -sTCP:LISTEN)
  fi

  local output
  output="$("${cmd[@]}" 2>/dev/null || true)"
  if [[ -z "$output" ]]; then
    return 1
  fi

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^COMMAND ]] && continue
    local name
    name="$(awk '{print $9}' <<<"$line" 2>/dev/null || true)"
    [[ -z "$name" ]] && continue
    name="${name%%->*}"
    name="${name% (LISTEN)}"
    local host="${name%:*}"
    local port_field="${name##*:}"
    port_field="${port_field%%[^0-9]*}"
    host="${host##*@}"
    if [[ "$port_field" != "$port" ]]; then
      continue
    fi
    if address_conflicts "$bind_ip" "$host"; then
      return 0
    fi
  done <<<"$output"

  return 1
}

PORT_TOOL=""
if have_command ss; then
  PORT_TOOL="ss"
elif have_command lsof; then
  PORT_TOOL="lsof"
fi

# Chooses the best available port checker for the current host
port_in_use() {
  local proto="$1"
  local bind_ip="$2"
  local port="$3"

  case "$PORT_TOOL" in
    ss)
      port_in_use_with_ss "$proto" "$bind_ip" "$port"
      return $?
      ;;
    lsof)
      port_in_use_with_lsof "$proto" "$bind_ip" "$port"
      return $?
      ;;
    *)
      return 2
      ;;
  esac
}

doctor_ok() {
  printf '[doctor][ok] %s\n' "$*"
}

doctor_fail() {
  printf '[doctor][error] %s\n' "$*"
}

doctor_warn() {
  printf '[doctor][warn] %s\n' "$*"
}

doctor_note() {
  printf '[doctor][info] %s\n' "$*"
}

# Reports whether a specific service port is free/bound, noting missing tooling
report_port() {
  local label="$1"
  local proto="$2"
  local bind_ip="$3"
  local port="$4"

  if [[ -z "$PORT_TOOL" ]]; then
    printf '[doctor][warn] Cannot check %s (%s %s:%s): missing \"ss\"/\"lsof\".\n' "$label" "${proto^^}" "$bind_ip" "$port"
    return
  fi

  if port_in_use "$proto" "$bind_ip" "$port"; then
    printf '[doctor][warn] %s port %s/%s is already in use on %s.\n' "$label" "$port" "${proto^^}" "$bind_ip"
  else
    printf '[doctor][ok] %s port %s/%s is free on %s.\n' "$label" "$port" "${proto^^}" "$bind_ip"
  fi
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
  echo "[doctor] Auditing bind addresses for safety"

  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    echo "[doctor][warn] Cannot verify LAN bindings because LAN_IP is unset or 0.0.0.0."
  fi

  if [[ -z "${EXPOSE_DIRECT_PORTS:-}" ]]; then
    EXPOSE_DIRECT_PORTS=0
  fi

  local -a direct_ports=("${QBT_HTTP_PORT_HOST}" "${SONARR_PORT}" "${RADARR_PORT}" "${PROWLARR_PORT}" "${BAZARR_PORT}" "${FLARESOLVERR_PORT}")
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    direct_ports+=("${SABNZBD_PORT:-8780}")
  fi

  if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
    if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
      echo "[doctor][warn] Direct ports enabled but LAN_IP is not set; they would bind to 0.0.0.0."
    else
      local port
      for port in "${direct_ports[@]}"; do
        local -a bindings=()
        mapfile -t bindings < <(port_bind_addresses tcp "$port")
        if ((${#bindings[@]} == 0)); then
          echo "[doctor][warn] Expected listener on ${LAN_IP}:${port} but nothing is bound."
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
          echo "[doctor][warn] Port ${port}/TCP is bound to 0.0.0.0; restrict it to LAN_IP=${LAN_IP} to avoid WAN exposure."
        fi
        if ((had_lan == 0)); then
          echo "[doctor][warn] Port ${port}/TCP does not appear to bind to ${LAN_IP}; confirm your port mappings."
        fi
      done
    fi
  else
    local port
    for port in "${direct_ports[@]}"; do
      local -a bindings=()
      mapfile -t bindings < <(port_bind_addresses tcp "$port")
      if ((${#bindings[@]} > 0)); then
        echo "[doctor][warn] Direct ports disabled but port ${port}/TCP is still listening on ${bindings[*]}."
      fi
    done
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    local qbt_conf="${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
    if [[ -f "$qbt_conf" ]]; then
      local ui_port
      ui_port="$(grep '^WebUI\\Port=' "$qbt_conf" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true)"
      local host_port="${QBT_HTTP_PORT_HOST:-8080}"
      if [[ -n "$ui_port" && "$ui_port" != "$host_port" ]]; then
        echo "[doctor][warn] qBittorrent WebUI internal port is ${ui_port} but host mapping expects ${host_port}"
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
    echo "[doctor][warn] Gluetun control API is reachable on ${gluetun_bindings[*]}; restrict it to LOCALHOST_IP=${LOCALHOST_IP}."
  fi

  if [[ "${ENABLE_CADDY}" != "1" ]]; then
    local port
    for port in 80 443; do
      local -a bindings=()
      mapfile -t bindings < <(port_bind_addresses tcp "$port")
      if ((${#bindings[@]} > 0)); then
        echo "[doctor][warn] Port ${port}/TCP is in use while ENABLE_CADDY=0 (${bindings[*]}). If you expected the proxy, set ENABLE_CADDY=1 and rerun ./arrstack.sh."
      fi
    done
  fi
}

# Probes LAN-facing HTTP endpoints through Caddy to validate local routing
test_lan_connectivity() {
  echo "[doctor] Testing LAN accessibility..."

  if [[ "${ENABLE_CADDY}" != "1" ]]; then
    echo "[doctor][info] Skipping Caddy HTTP checks (ENABLE_CADDY=0)."
    return
  fi

  if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    echo "[doctor][warn] LAN_IP unset or 0.0.0.0; skipping LAN connectivity checks."
    return
  fi

  if ! have_command curl; then
    echo "[doctor][warn] 'curl' not available; cannot probe LAN HTTP endpoints."
    return
  fi

  if curl -fsS -m 5 "http://${LAN_IP}/healthz" >/dev/null 2>&1; then
    echo "[doctor][ok] Caddy responds on http://${LAN_IP}/healthz"
  else
    echo "[doctor][error] Caddy not accessible on http://${LAN_IP}/healthz"
  fi

  local service
  for service in qbittorrent sonarr radarr prowlarr bazarr; do
    if curl -fsS -m 5 -H "Host: ${service}.${SUFFIX}" "http://${LAN_IP}/" >/dev/null 2>&1; then
      echo "[doctor][ok] ${service} accessible via Caddy on ${LAN_IP}"
    else
      echo "[doctor][warn] ${service} not accessible via Caddy on ${LAN_IP}"
    fi
  done
}

# Verifies upstream DNS responders and surfaces missing tooling
doctor_dns_health() {
  echo "[doctor] Checking upstream DNS reachability"

  local -a resolvers=()
  mapfile -t resolvers < <(collect_upstream_dns_servers)

  if ((${#resolvers[@]} == 0)); then
    echo "[doctor][warn] No upstream DNS servers defined. Configure UPSTREAM_DNS_SERVERS or legacy UPSTREAM_DNS_1/2."
    return
  fi

  local resolver
  local tool_missing=0
  for resolver in "${resolvers[@]}"; do
    if probe_dns_resolver "$resolver" "cloudflare.com" 2; then
      echo "[doctor][ok] Resolver ${resolver} responded within 2s"
      continue
    fi

    local rc=$?
    if ((rc == 2)); then
      echo "[doctor][warn] DNS probe skipped: install dig, drill, kdig, or nslookup to verify upstream reachability."
      tool_missing=1
      break
    fi

    echo "[doctor][warn] Resolver ${resolver} did not answer probe queries (check connectivity or replace it)."
  done

  if ((tool_missing)); then
    echo "[doctor][info] Configured upstream DNS servers: ${resolvers[*]}"
  fi
}

# Compares Docker daemon DNS configuration with expected LAN/upstream chain
check_docker_dns_configuration() {
  echo "[doctor] Inspecting Docker daemon DNS settings"

  if ! command -v docker >/dev/null 2>&1; then
    echo "[doctor][warn] docker CLI not available; cannot inspect daemon DNS configuration."
    return
  fi

  local dns_json
  if ! dns_json="$(docker info --format '{{json .DNS}}' 2>/dev/null)"; then
    echo "[doctor][warn] Unable to query docker info; ensure Docker is running and accessible."
    return
  fi

  if [[ -z "$dns_json" || "$dns_json" == "null" ]]; then
    echo "[doctor][warn] Docker daemon reports no custom DNS servers; containers may inherit host defaults."
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
    echo "[doctor][warn] Docker daemon DNS list empty; containers may fall back to host defaults."
    return
  fi

  echo "[doctor][info] Docker daemon DNS chain: ${docker_dns[*]}"

  local -a expected=()
  if [[ -n "${LAN_IP:-}" && "${LAN_IP}" != "0.0.0.0" ]]; then
    expected+=("${LAN_IP}")
  fi
  local -a upstream_chain=()
  mapfile -t upstream_chain < <(collect_upstream_dns_servers)
  expected+=("${upstream_chain[@]}")

  if ((${#expected[@]} > 0)); then
    if [[ "${docker_dns[*]}" == "${expected[*]}" ]]; then
      echo "[doctor][ok] Docker DNS matches expected LAN + upstream resolver order."
    else
      echo "[doctor][warn] Docker DNS order differs from expected (${expected[*]})."
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
    helper="${REPO_ROOT}/scripts/sab-helper.sh"
  fi

  if [[ ! -x "$helper" ]]; then
    doctor_warn "SABnzbd helper missing; skipping API check"
    return 0
  fi

  local sab_status=0
  if "$helper" version >/dev/null 2>&1; then
    doctor_ok "SABnzbd API reachable"
  else
    sab_status=1
    doctor_fail "SABnzbd unreachable at ${SABNZBD_URL}"
  fi

  if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
    local gluetun_disabled=0
    if [[ "${ENABLE_GLUETUN:-1}" == "0" ]]; then
      gluetun_disabled=1
    fi
    case "${VPN_SERVICE_PROVIDER:-protonvpn}" in
      ''|none|disabled|off)
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

SUFFIX="${LAN_DOMAIN_SUFFIX:-}"
LAN_IP="${LAN_IP:-}"
DNS_IP="${LAN_IP:-127.0.0.1}"
ENABLE_LOCAL_DNS="${ENABLE_LOCAL_DNS:-0}"
LOCAL_DNS_SERVICE_ENABLED="${LOCAL_DNS_SERVICE_ENABLED:-1}"
ENABLE_CADDY="${ENABLE_CADDY:-0}"
EXPOSE_DIRECT_PORTS="${EXPOSE_DIRECT_PORTS:-0}"
LOCALHOST_IP="${LOCALHOST_IP:-127.0.0.1}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
DNS_DISTRIBUTION_MODE="${DNS_DISTRIBUTION_MODE:-router}"
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

if [[ "${ENABLE_LOCAL_DNS}" == "1" ]]; then
  echo "[doctor] Checking if port 53 is free (or already bound):"
  if have_command ss; then
    if [[ -n "$(ss -H -lnu 'sport = :53' 2>/dev/null)" ]] || [[ -n "$(ss -H -lnt 'sport = :53' 2>/dev/null)" ]]; then
      echo "[doctor][warn] Something is listening on port 53. Could conflict with local_dns service."
      if have_command systemctl && systemctl is-active --quiet systemd-resolved; then
        echo "[doctor][hint] systemd-resolved is active and commonly owns :53 on Bookworm."
        echo "[doctor][hint] Run: ./scripts/host-dns-setup.sh (safe takeover with backup & rollback)."
      fi
    else
      echo "[doctor][ok] Port 53 appears free."
    fi
  elif have_command lsof; then
    if [[ -n "$(lsof -nP -iUDP:53 2>/dev/null)" ]] || [[ -n "$(lsof -nP -iTCP:53 -sTCP:LISTEN 2>/dev/null)" ]]; then
      echo "[doctor][warn] Something is listening on port 53. Could conflict with local_dns service."
    else
      echo "[doctor][ok] Port 53 appears free."
    fi
  else
    echo "[doctor][warn] Cannot test port 53 status (missing 'ss' and 'lsof')."
  fi
else
  echo "[doctor][info] Skipping port 53 availability check (local DNS disabled)."
fi

if [[ "${ENABLE_CADDY}" == "1" ]]; then
  printf '[doctor] LAN domain suffix: %s\n' "${SUFFIX:-<unset>}"
else
  echo "[doctor][info] Skipping LAN domain suffix reporting (ENABLE_CADDY=0)."
fi
printf '[doctor] LAN IP: %s\n' "${LAN_IP:-<unset>}"
printf '[doctor] Using DNS server at: %s\n' "${DNS_IP}"
doctor_dns_health
check_docker_dns_configuration

printf '[doctor] DNS distribution mode: %s\n' "${DNS_DISTRIBUTION_MODE}"

if [[ "${ENABLE_LOCAL_DNS}" == "1" ]]; then
  if [[ "${LOCAL_DNS_SERVICE_ENABLED}" == "1" ]]; then
    echo "[doctor] Local DNS container: enabled"
  else
    echo "[doctor][warn] Local DNS requested but the container is disabled."
  fi
else
  echo "[doctor][info] Local DNS disabled in configuration."
fi

echo "[doctor] Checking host reachability"
if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  echo "[doctor][warn] LAN_IP is unset or 0.0.0.0; skipping ping check."
elif have_command ping; then
  if ping -c 1 -W 1 "${LAN_IP}" >/dev/null 2>&1; then
    echo "[doctor][ok] Host responded to ping at ${LAN_IP}"
  else
    echo "[doctor][warn] Host did not respond to ping at ${LAN_IP}"
  fi
else
  echo "[doctor][warn] 'ping' command not found; skipping reachability test."
fi

if [[ -z "${LAN_IP}" || "${LAN_IP}" == "0.0.0.0" ]]; then
  echo "[doctor][warn] Skipping LAN port checks because LAN_IP is not set to a specific address."
else
  if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
    report_port "qBittorrent UI" tcp "${LAN_IP}" "${QBT_HTTP_PORT_HOST}"
    report_port "Sonarr UI" tcp "${LAN_IP}" "${SONARR_PORT}"
    report_port "Radarr UI" tcp "${LAN_IP}" "${RADARR_PORT}"
    report_port "Prowlarr UI" tcp "${LAN_IP}" "${PROWLARR_PORT}"
    report_port "Bazarr UI" tcp "${LAN_IP}" "${BAZARR_PORT}"
    report_port "FlareSolverr" tcp "${LAN_IP}" "${FLARESOLVERR_PORT}"
  else
    echo "[doctor][info] Direct LAN ports are disabled (EXPOSE_DIRECT_PORTS=0)."
  fi

  if [[ "${ENABLE_CADDY}" == "1" ]]; then
    report_port "Caddy HTTP" tcp "${LAN_IP}" 80
    report_port "Caddy HTTPS" tcp "${LAN_IP}" 443
  else
    echo "[doctor][info] Skipping Caddy port checks (ENABLE_CADDY=0)."
  fi

  if [[ "${ENABLE_LOCAL_DNS}" == "1" && "${LOCAL_DNS_SERVICE_ENABLED}" == "1" ]]; then
    report_port "Local DNS" udp "${LAN_IP}" 53
    report_port "Local DNS" tcp "${LAN_IP}" 53
  else
    echo "[doctor][info] Skipping port 53 checks because local DNS is disabled."
  fi
fi

check_network_security

if [[ -n "${LOCALHOST_IP}" ]]; then
  report_port "Gluetun control" tcp "${LOCALHOST_IP}" "${GLUETUN_CONTROL_PORT}"
fi

if [[ "${ENABLE_LOCAL_DNS}" == "1" && "${LOCAL_DNS_SERVICE_ENABLED}" == "1" ]]; then
  if [[ "${ENABLE_CADDY}" != "1" ]]; then
    echo "[doctor][info] Skipping LAN hostname resolution checks (ENABLE_CADDY=0)."
  else
    echo "[doctor] Testing DNS resolution of qbittorrent.${SUFFIX} via local resolver"
    if ! have_command dig; then
      echo "[doctor][warn] 'dig' command not found; skipping DNS lookup."
    else
      res_udp="$(dig +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
      if [[ -z "$res_udp" ]]; then
        echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP} (UDP)"
      else
        echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res_udp} (UDP)"
      fi

      res_tcp="$(dig +tcp +short @"${DNS_IP}" qbittorrent."${SUFFIX}" 2>/dev/null || true)"
      if [[ -z "$res_tcp" ]]; then
        echo "[doctor][error] qbittorrent.${SUFFIX} did NOT resolve via ${DNS_IP} (TCP)"
      else
        echo "[doctor][ok] qbittorrent.${SUFFIX} resolves to ${res_tcp} (TCP)"
      fi
    fi
  fi
else
  echo "[doctor][info] DNS checks skipped: local DNS is disabled."
fi

if [[ "${ENABLE_CADDY}" == "1" ]]; then
  echo "[doctor] Testing CA fetch over HTTP (bootstrap)"
  if have_command curl && have_command openssl; then
    if cert_output="$(curl -fsS "http://ca.${SUFFIX}/root.crt" 2>/dev/null | openssl x509 -noout -subject -issuer 2>/dev/null)"; then
      printf '[doctor][ok] CA download succeeded:%s%s\n' "${cert_output:+\n}" "${cert_output}"
    else
      echo "[doctor][warn] Could not fetch CA over HTTP"
    fi
  else
    echo "[doctor][warn] Skipping CA fetch test: missing 'curl' or 'openssl'."
  fi

  echo "[doctor] Testing HTTPS endpoint"
  if ! have_command curl; then
    echo "[doctor][warn] 'curl' command not found; skipping HTTPS probe."
  else
    curl_args=(-k --silent --max-time 5)
    if [[ -n "${LAN_IP}" && "${LAN_IP}" != "0.0.0.0" ]]; then
      curl_args+=(--resolve "qbittorrent.${SUFFIX}:443:${LAN_IP}" --resolve "qbittorrent.${SUFFIX}:80:${LAN_IP}")
    fi
    if curl "${curl_args[@]}" "https://qbittorrent.${SUFFIX}/" -o /dev/null; then
      echo "[doctor][ok] HTTPS endpoint reachable"
    else
      echo "[doctor][warn] HTTPS endpoint not reachable. Could be DNS, Caddy, or firewall issue."
    fi
  fi
else
  echo "[doctor][info] Skipping Caddy CA and HTTPS checks (ENABLE_CADDY=0)."
fi

test_lan_connectivity

doctor_check_sabnzbd

if [[ "${ENABLE_LOCAL_DNS}" == "1" ]]; then
  case "${DNS_DISTRIBUTION_MODE}" in
    router)
      echo "[doctor][info] DNS distribution mode 'router': set DHCP Option 6 (DNS server) on your router to ${LAN_IP}."
      ;;
    per-device)
      echo "[doctor][info] DNS distribution mode 'per-device': point important clients at ${LAN_IP} and keep Android Private DNS Off/Automatic."
      ;;
    *)
      echo "[doctor][warn] Unknown DNS_DISTRIBUTION_MODE='${DNS_DISTRIBUTION_MODE}'. Expected 'router' or 'per-device'."
      ;;
  esac
else
  echo "[doctor][info] DNS distribution mode ignored (local DNS disabled)."
fi

lan_target="${LAN_IP:-<unset>}"
echo "[doctor] From another LAN device you can try:"
if [[ "${EXPOSE_DIRECT_PORTS}" == "1" ]]; then
  echo "  curl -I http://${lan_target}:${QBT_HTTP_PORT_HOST}"
  echo "  curl -I http://${lan_target}:${SONARR_PORT}"
  echo "  curl -I http://${lan_target}:${RADARR_PORT}"
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    echo "  curl -I http://${lan_target}:${SABNZBD_PORT}"
  fi
else
  echo "  (Direct ports disabled; set EXPOSE_DIRECT_PORTS=1 to enable IP:PORT access.)"
fi

if [[ "${ENABLE_LOCAL_DNS}" == "1" && "${ENABLE_CADDY}" == "1" ]]; then
  echo "  nslookup qbittorrent.${SUFFIX} ${lan_target}"
  echo "[doctor][note] If DNS queries fail:"
  echo "  - Ensure the client and ${lan_target} are on the same VLAN/subnet;"
  echo "  - Some routers block DNS to LAN hosts; allow UDP/TCP 53 to ${lan_target};"
  echo "  - Temporarily set the client DNS to ${lan_target} and retry."
elif [[ "${ENABLE_LOCAL_DNS}" == "1" ]]; then
  echo "  (DNS hostname troubleshooting tips skipped; ENABLE_CADDY=0.)"
fi

if [[ "${ENABLE_CADDY}" == "1" ]]; then
  echo "  curl -k https://qbittorrent.${SUFFIX}/ --resolve qbittorrent.${SUFFIX}:443:${lan_target}"
fi

exit 0

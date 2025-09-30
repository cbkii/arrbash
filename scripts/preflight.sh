# shellcheck shell=bash

install_missing() {
  msg "🔧 Checking dependencies"

  require_dependencies docker

  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    die "Docker daemon is not running or not accessible"
  fi

  local compose_version_raw=""
  local compose_version_clean=""
  local compose_major=""

  DOCKER_COMPOSE_CMD=()

  if docker compose version >/dev/null 2>&1; then
    compose_version_raw="$(docker compose version --short 2>/dev/null || true)"
    compose_version_clean="${compose_version_raw#v}"
    compose_major="${compose_version_clean%%.*}"
    if [[ "$compose_major" =~ ^[0-9]+$ ]] && ((compose_major >= 2)); then
      DOCKER_COMPOSE_CMD=(docker compose)
    else
      compose_version_raw=""
      compose_version_clean=""
    fi
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)) && command -v docker-compose >/dev/null 2>&1; then
    compose_version_raw="$(docker-compose version --short 2>/dev/null || true)"
    compose_version_clean="${compose_version_raw#v}"
    compose_major="${compose_version_clean%%.*}"
    if [[ "$compose_major" =~ ^[0-9]+$ ]] && ((compose_major >= 2)); then
      DOCKER_COMPOSE_CMD=(docker-compose)
    else
      compose_version_raw=""
      compose_version_clean=""
    fi
  fi

  if ((${#DOCKER_COMPOSE_CMD[@]} == 0)); then
    die "Docker Compose v2+ is required but not found"
  fi

  require_dependencies curl jq openssl

  if ! command -v certutil >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo apt-get install -y libnss3-tools"
    elif command -v yum >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo yum install -y nss-tools"
    elif command -v dnf >/dev/null 2>&1; then
      msg "  Tip: install certutil for smoother Caddy TLS trust: sudo dnf install -y nss-tools"
    else
      msg "  Tip: certutil not found (optional); Caddy may print a trust-store warning."
    fi
  fi

  msg "  Docker: $(docker version --format '{{.Server.Version}}')"
  local compose_cmd_display="${DOCKER_COMPOSE_CMD[*]}"
  local compose_version_display="${compose_version_raw:-${compose_version_clean:-unknown}}"
  if [[ -n "$compose_version_display" && "$compose_version_display" != "unknown" ]]; then
    msg "  Compose: ${compose_cmd_display} ${compose_version_display}"
  else
    msg "  Compose: ${compose_cmd_display} (unknown)"
  fi
}

collect_port_requirements() {
  local _requirements_name="$1"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"

  _requirements_ref=()

  local lan_ip_known=1
  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    lan_ip_known=0
  fi

  _requirements_ref+=("tcp|${GLUETUN_CONTROL_PORT}|Gluetun control API|${LOCALHOST_IP:-127.0.0.1}")

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
    if ((lan_ip_known == 0)); then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before exposing ports."
    fi

    local expected="${LAN_IP}"
    _requirements_ref+=("tcp|${QBT_HTTP_PORT_HOST}|qBittorrent WebUI|${expected}")
    _requirements_ref+=("tcp|${SONARR_PORT}|Sonarr WebUI|${expected}")
    _requirements_ref+=("tcp|${RADARR_PORT}|Radarr WebUI|${expected}")
    _requirements_ref+=("tcp|${PROWLARR_PORT}|Prowlarr WebUI|${expected}")
    _requirements_ref+=("tcp|${BAZARR_PORT}|Bazarr WebUI|${expected}")
    _requirements_ref+=("tcp|${FLARESOLVERR_PORT}|FlareSolverr API|${expected}")
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    if ((lan_ip_known == 0)); then
      die "SPLIT_VPN=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before enabling split VPN mode."
    fi

    _requirements_ref+=("tcp|${QBT_HTTP_PORT_HOST}|qBittorrent WebUI|${LAN_IP}")
  fi

  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]] && ((lan_ip_known)); then
    _requirements_ref+=("tcp|80|Caddy HTTP|${LAN_IP}")
    _requirements_ref+=("tcp|443|Caddy HTTPS|${LAN_IP}")
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    local dns_expected="*"
    if ((lan_ip_known)); then
      dns_expected="$LAN_IP"
    fi
    _requirements_ref+=("tcp|53|Local DNS (TCP)|${dns_expected}")
    _requirements_ref+=("udp|53|Local DNS (UDP)|${dns_expected}")
  fi
}

port_in_use_with_details() {
  local proto="$1"
  local port="$2"
  local _details_name="$3"
  # shellcheck disable=SC2178
  local -n _details_ref="$_details_name"

  _details_ref=""

  local tool=""
  if command -v ss >/dev/null 2>&1; then
    tool="ss"
  elif command -v lsof >/dev/null 2>&1; then
    tool="lsof"
  elif command -v netstat >/dev/null 2>&1; then
    tool="netstat"
  else
    return 2
  fi

  case "$tool" in
    ss)
      local -a args=()
      case "$proto" in
        tcp) args=(-H -ltnp) ;;
        udp) args=(-H -lunp) ;;
        *) return 1 ;;
      esac
      local output=""
      output="$(ss "${args[@]}" 2>/dev/null | awk -v port="$port" '
        {
          split($5, parts, ":")
          candidate = parts[length(parts)]
          if (candidate == port) {
            print $0
          }
        }
      ')"
      if [[ -n "$output" ]]; then
        _details_ref="$output"
        return 0
      fi
      ;;
    lsof)
      local output=""
      case "$proto" in
        tcp)
          output="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
          ;;
        udp)
          output="$(lsof -nP -iUDP:"$port" 2>/dev/null || true)"
          ;;
        *)
          return 1
          ;;
      esac
      if [[ -n "$output" ]]; then
        _details_ref="$output"
        return 0
      fi
      ;;
    netstat)
      local output=""
      output="$(netstat -tunlp 2>/dev/null | awk -v port="$port" '
        NR > 2 {
          split($4, parts, ":")
          candidate = parts[length(parts)]
          if (candidate == port) {
            print $0
          }
        }
      ')"
      if [[ -n "$output" ]]; then
        _details_ref="$output"
        return 0
      fi
      ;;
  esac

  return 1
}

port_conflict_guidance() {
  warn "    Resolve the conflicts by stopping or reconfiguring the services listed above."
  warn "    Common fixes include:"
  warn "      • Stopping existing arrstack containers: ${DOCKER_COMPOSE_CMD[*]} down"
  warn "      • Freeing the port from host services (e.g. sudo systemctl stop <service>)"
  warn "      • Updating LAN_IP or port overrides in ${ARR_USERCONF_PATH}"
}

: "${ARRSTACK_PORT_CONFLICT_AUTO_FIX:=1}"
_arrstack_port_conflict_quickfix_attempted=0

attempt_port_conflict_quickfix() {
  if [[ "${ARRSTACK_PORT_CONFLICT_AUTO_FIX}" != "1" ]]; then
    return 1
  fi

  if [[ "${_arrstack_port_conflict_quickfix_attempted:-0}" == "1" ]]; then
    return 1
  fi

  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi

  if ! declare -f safe_cleanup >/dev/null 2>&1; then
    return 1
  fi

  _arrstack_port_conflict_quickfix_attempted=1
  msg "    Attempting automatic quick fix: stopping existing arrstack containers"
  safe_cleanup
  return 0
}

simple_port_check() {
  msg "  Checking required host ports"

  local mode_raw="${ARRSTACK_PORT_CHECK_MODE:-enforce}"
  local mode="${mode_raw,,}"

  case "$mode" in
    enforce|warn|skip)
      ;;
    "")
      mode="enforce"
      ;;
    *)
      warn "    Unknown ARRSTACK_PORT_CHECK_MODE='${mode_raw}'. Falling back to enforce."
      mode="enforce"
      ;;
  esac

  if [[ "$mode" == "skip" ]]; then
    warn "    Port availability checks skipped (ARRSTACK_PORT_CHECK_MODE=skip). Services may fail to bind if ports are busy."
    return 0
  fi

  local quickfix_used=0

  while :; do
    local -a requirements=()
    collect_port_requirements requirements

    if ((${#requirements[@]} == 0)); then
      msg "    No host port reservations required for the selected configuration."
      return
    fi

    local -a conflicts=()
    local rc=0
    local requirement=""
    local tool_missing_reported=0

    for requirement in "${requirements[@]}"; do
      IFS='|' read -r proto port label expected <<<"$requirement"
      local details=""
      rc=0
      if ! port_in_use_with_details "$proto" "$port" details; then
        rc=$?
      fi

      case "$rc" in
        0)
          conflicts+=("$label|$proto|$port|$expected|$details")
          ;;
        1)
          msg "    ✓ ${label} (${proto^^} ${port}) available"
          ;;
        2)
          if ((tool_missing_reported == 0)); then
            warn "    Unable to inspect ports automatically (missing ss/lsof/netstat)."
            warn "    Skipping port availability checks; ensure required ports are free manually."
            tool_missing_reported=1
          fi
          ;;
      esac
    done

    if ((tool_missing_reported)); then
      return
    fi

    if ((${#conflicts[@]} == 0)); then
      if ((quickfix_used)); then
        msg "    All required ports are free after quick fix."
      else
        msg "    All required ports are free."
      fi
      return
    fi

    warn "    Port conflicts detected:"
    local entry=""
    for entry in "${conflicts[@]}"; do
      IFS='|' read -r label proto port expected details <<<"$entry"
      warn "      - ${label} (${proto^^} ${port}) is already in use."
      if [[ -n "$expected" && "$expected" != "*" ]]; then
        warn "        Expected bind address: ${expected}"
      fi
      if [[ -n "$details" ]]; then
        local line
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          warn "        Listener: $line"
        done < <(printf '%s\n' "$details" | head -n 3)
      fi
    done

    port_conflict_guidance
    if ((quickfix_used == 0)) && attempt_port_conflict_quickfix; then
      quickfix_used=1
      msg "    Retrying port availability check after quick fix..."
      continue
    fi

    if [[ "$mode" == "warn" ]]; then
      warn "    Continuing despite port conflicts (ARRSTACK_PORT_CHECK_MODE=warn). Services may fail to bind."
      return 0
    fi

    die "Resolve port conflicts and rerun ./arrstack.sh"
  done
}

validate_dns_configuration() {
  if [[ "${ENABLE_LOCAL_DNS:-0}" -ne 1 ]]; then
    return
  fi

  if [[ -z "${LAN_DOMAIN_SUFFIX:-}" ]]; then
    die "Local DNS requires LAN_DOMAIN_SUFFIX to be set to a non-empty domain suffix."
  fi

  local -a resolvers=()
  mapfile -t resolvers < <(collect_upstream_dns_servers)

  if ((${#resolvers[@]} == 0)); then
    die "Local DNS requires at least one upstream resolver via UPSTREAM_DNS_SERVERS or the legacy UPSTREAM_DNS_1/2 variables."
  fi

  local -a healthy=()
  local -a unhealthy=()
  local probe_rc=0
  local resolver

  for resolver in "${resolvers[@]}"; do
    local rc=0
    if probe_dns_resolver "$resolver" "cloudflare.com" 2; then
      healthy+=("$resolver")
      continue
    fi

    rc=$?
    if ((rc == 2)); then
      probe_rc=2
      warn "Skipping DNS reachability probe: install dig, drill, kdig, or nslookup to enable upstream validation."
      healthy=("${resolvers[@]}")
      unhealthy=()
      break
    fi

    unhealthy+=("$resolver")
  done

  if ((probe_rc != 2)); then
    if ((${#healthy[@]} == 0)); then
      die "None of the upstream DNS servers responded (${resolvers[*]}). Update UPSTREAM_DNS_SERVERS with reachable resolvers before continuing."
    fi

    if ((${#unhealthy[@]} > 0)); then
      warn "Upstream DNS servers unreachable during preflight probe: ${unhealthy[*]}"
    fi
  fi
}

preflight() {
  msg "🚀 Preflight checks"

  acquire_lock

  msg "  Permission profile: ${ARR_PERMISSION_PROFILE} (umask $(umask))"

  if [[ ! -f "${ARRCONF_DIR}/proton.auth" ]]; then
    die "Missing ${ARRCONF_DIR}/proton.auth - create it with PROTON_USER and PROTON_PASS"
  fi

  load_proton_credentials

  msg "  OpenVPN username (enforced '+pmp'): $(obfuscate_sensitive "$OPENVPN_USER_VALUE" 2 4)"

  if ((PROTON_USER_PMP_ADDED)); then
    warn "Proton username '${PROTON_USER_VALUE}' missing '+pmp'; using '${OPENVPN_USER_VALUE}'"
  fi

  install_missing

  if [[ "${PF_ASYNC_ENABLE:-1}" == "1" ]] && ! command -v jq >/dev/null 2>&1; then
    warn "[pf] jq is not installed; async port forwarding state will be parsed without JSON tooling."
  fi

  if gluetun_version_requires_auth_config 2>/dev/null; then
    local auth_config_path="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
    if [[ -d "${ARR_DOCKER_DIR}/gluetun" && ! -f "$auth_config_path" ]]; then
      warn "[pf] Gluetun control API requires role-based auth; the installer will create ${auth_config_path}."
    fi
  fi

  if [[ -n "${GLUETUN_IMAGE:-}" ]] && gluetun_version_requires_auth_config 2>/dev/null && [[ -z "${GLUETUN_API_KEY:-}" ]]; then
    warn "Gluetun 3.40+ requires an API key. It will be auto-generated during setup."
  fi

  validate_dns_configuration
  simple_port_check

  if [[ -f "${ARR_ENV_FILE}" ]]; then
    local existing_openvpn_user=""
    existing_openvpn_user="$(grep '^OPENVPN_USER=' "${ARR_ENV_FILE}" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    if [[ -n "$existing_openvpn_user" ]]; then
      local existing_unescaped
      existing_unescaped="$(unescape_env_value_from_compose "$existing_openvpn_user")"
      if [[ "$existing_unescaped" != *"+pmp" ]]; then
        warn "OPENVPN_USER in ${ARR_ENV_FILE} is '${existing_unescaped}' and will be updated to include '+pmp'."
      fi
    fi
  fi

  show_configuration_preview

  if [[ "${ASSUME_YES}" != 1 ]]; then
    local response=""

    warn "Continue with ProtonVPN OpenVPN setup? [y/N]: "
    if ! IFS= read -r response; then
      response=""
    fi

    if ! [[ ${response,,} =~ ^[[:space:]]*(y|yes)[[:space:]]*$ ]]; then
      die "Aborted"
    fi
  fi
}

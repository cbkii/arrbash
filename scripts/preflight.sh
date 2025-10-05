# shellcheck shell=bash

# Verifies required tooling (docker/compose/curl/jq) and records versions for logs
install_missing() {
  msg "🔧 Checking dependencies"

  require_dependencies docker

  if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    die "Docker daemon is not running or not accessible"
  fi

  DOCKER_COMPOSE_CMD=()
  ARR_COMPOSE_VERSION=""
  arr_resolve_compose_cmd
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
  local compose_version_display="${ARR_COMPOSE_VERSION:-unknown}"
  if [[ -n "$compose_version_display" && "$compose_version_display" != "unknown" ]]; then
    msg "  Compose: ${compose_cmd_display} ${compose_version_display}"
  else
    msg "  Compose: ${compose_cmd_display} (unknown)"
  fi
}

# Locates the first userr.conf override relative to the repo parent
preflight_find_userconf_override() {
  local target_name="userr.conf" search_root=".." repo_root="" canonical=""

  if [[ -n "${REPO_ROOT:-}" ]]; then
    if repo_root="$(cd "${REPO_ROOT}" 2>/dev/null && pwd -P)"; then
      if search_root="$(cd "${repo_root}/.." 2>/dev/null && pwd -P)"; then
        :
      else
        search_root=".."
      fi
    fi
  else
    if search_root="$(cd ".." 2>/dev/null && pwd -P)"; then
      :
    else
      search_root=".."
    fi
  fi

  local current_path="${ARR_USERCONF_PATH:-}"
  if [[ -n "$current_path" && -f "$current_path" ]]; then
    canonical="$(readlink -f "$current_path" 2>/dev/null || printf '%s' "$current_path")"
    printf '%s\n' "$canonical"
    return 0
  fi

  if [[ ! -d "$search_root" ]]; then
    return 1
  fi

  local root_candidate="${search_root%/}/$target_name"
  if [[ -f "$root_candidate" ]]; then
    canonical="$(readlink -f "$root_candidate" 2>/dev/null || printf '%s' "$root_candidate")"
    printf '%s\n' "$canonical"
    return 0
  fi

  local -a sibling_dirs=()
  local entry=""
  while IFS= read -r -d '' entry; do
    if [[ -n "$repo_root" ]] && [[ "$entry" == "$repo_root" ]]; then
      continue
    fi
    sibling_dirs+=("$entry")
  done < <(find "$search_root" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | LC_ALL=C sort -z)

  for entry in "${sibling_dirs[@]}"; do
    local candidate="${entry%/}/$target_name"
    if [[ -f "$candidate" ]]; then
      canonical="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
      printf '%s\n' "$canonical"
      return 0
    fi

    local found=""
    found="$(find "$entry" -type f -name "$target_name" -print -quit 2>/dev/null || true)"
    if [[ -n "$found" ]]; then
      canonical="$(readlink -f "$found" 2>/dev/null || printf '%s' "$found")"
      printf '%s\n' "$canonical"
      return 0
    fi
  done

  return 1
}

# Builds list of host ports the stack expects based on current configuration
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

  local qbt_http_port="${QBT_PORT:-${QBT_INT_PORT:-8082}}"

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    if ((lan_ip_known == 0)); then
      die "EXPOSE_DIRECT_PORTS=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before exposing ports."
    fi

    local expected="${LAN_IP}"
    _requirements_ref+=("tcp|${qbt_http_port}|qBittorrent WebUI|${expected}")
    _requirements_ref+=("tcp|${SONARR_PORT}|Sonarr WebUI|${expected}")
    _requirements_ref+=("tcp|${RADARR_PORT}|Radarr WebUI|${expected}")
    _requirements_ref+=("tcp|${PROWLARR_PORT}|Prowlarr WebUI|${expected}")
    _requirements_ref+=("tcp|${BAZARR_PORT}|Bazarr WebUI|${expected}")
    _requirements_ref+=("tcp|${FLARR_PORT}|FlareSolverr API|${expected}")
    if [[ "${SABNZBD_ENABLED:-0}" == "1" && "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
      local sab_port_check="${SABNZBD_PORT:-}"
      if [[ -z "$sab_port_check" || ! "$sab_port_check" =~ ^[0-9]+$ ]]; then
        sab_port_check="${SABNZBD_INT_PORT:-8080}"
      fi
      _requirements_ref+=("tcp|${sab_port_check}|SABnzbd WebUI|${expected}")
    fi
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    if ((lan_ip_known == 0)); then
      die "SPLIT_VPN=1 requires LAN_IP to be set to your host's private IPv4 address before installation."
    fi
    if ! is_private_ipv4 "${LAN_IP}"; then
      die "LAN_IP='${LAN_IP}' is not a private IPv4 address. Set LAN_IP correctly before enabling split VPN mode."
    fi

    _requirements_ref+=("tcp|${qbt_http_port}|qBittorrent WebUI|${LAN_IP}")
  fi

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    local caddy_http_port
    local caddy_https_port
    arr_resolve_port caddy_http_port "${CADDY_HTTP_PORT:-}" 80 \
      "    Invalid CADDY_HTTP_PORT=${CADDY_HTTP_PORT:-}; defaulting to 80."
    arr_resolve_port caddy_https_port "${CADDY_HTTPS_PORT:-}" 443 \
      "    Invalid CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT:-}; defaulting to 443."
    CADDY_HTTP_PORT="$caddy_http_port"
    CADDY_HTTPS_PORT="$caddy_https_port"

    local caddy_expected="*"
    if ((lan_ip_known)); then
      caddy_expected="$LAN_IP"
    else
      if [[ "${ARR_WARNED_CADDY_LAN_UNKNOWN:-0}" != "1" ]]; then
        warn "    LAN_IP unknown; validating Caddy ports on all interfaces. Set LAN_IP in ${ARR_USERCONF_PATH:-userr.conf} to lock bindings."
        ARR_WARNED_CADDY_LAN_UNKNOWN=1
      fi
    fi
    _requirements_ref+=("tcp|${caddy_http_port}|Caddy HTTP|${caddy_expected}")
    _requirements_ref+=("tcp|${caddy_https_port}|Caddy HTTPS|${caddy_expected}")
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    local dns_expected="*"
    if ((lan_ip_known)); then
      dns_expected="$LAN_IP"
    fi
    _requirements_ref+=("tcp|53|Local DNS (TCP)|${dns_expected}")
    _requirements_ref+=("udp|53|Local DNS (UDP)|${dns_expected}")
  fi
}

detect_internal_port_conflicts() {
  local _requirements_name="$1"
  local _collisions_name="$2"
  # shellcheck disable=SC2178
  local -n _requirements_ref="$_requirements_name"
  # shellcheck disable=SC2178
  local -n _collisions_ref="$_collisions_name"

  _collisions_ref=()

  declare -A _label_map=()

  local entry=""
  for entry in "${_requirements_ref[@]}"; do
    IFS='|' read -r proto port label _expected <<<"$entry"
    local key="${proto}|${port}"
    if [[ -z "${_label_map[$key]:-}" ]]; then
      _label_map[$key]="$label"
    else
      _label_map[$key]+=$'\n'"$label"
    fi
  done

  local key=""
  for key in "${!_label_map[@]}"; do
    if [[ "${_label_map[$key]}" == *$'\n'* ]]; then
      _collisions_ref+=("${key}|${_label_map[$key]}")
    fi
  done
}

# Checks port availability and returns raw listener details for diagnostics
port_in_use_with_details() {
  local proto="$1"
  local port="$2"
  local _details_name="$3"
  local expected_addr="${4:-*}"
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

  local output=""
  case "$tool" in
    ss)
      local -a args=()
      case "$proto" in
        tcp) args=(-H -ltnp) ;;
        udp) args=(-H -lunp) ;;
        *) return 1 ;;
      esac
      output="$(ss "${args[@]}" 2>/dev/null | awk -v port="$port" '
        {
          split($5, parts, ":")
          candidate = parts[length(parts)]
          if (candidate == port) {
            print $0
          }
        }
      ')"
      ;;
    lsof)
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
      ;;
    netstat)
      output="$(netstat -tunlp 2>/dev/null | awk -v port="$port" '
        NR > 2 {
          split($4, parts, ":")
          candidate = parts[length(parts)]
          if (candidate == port) {
            print $0
          }
        }
      ')"
      ;;
  esac

  if [[ -n "$output" ]]; then
    local restore_extglob=0
    if ! shopt -q extglob; then
      shopt -s extglob
      restore_extglob=1
    fi
    local wildcard_v4="0.0.0.0"
    local wildcard_v6="::"
    local conflict=0

    local exp="${expected_addr//[\[\] ]/}"
    if [[ -z "$exp" || "$exp" == "*" ]]; then
      conflict=1
    else
      local exp_is_ipv6=0
      if [[ "$exp" == *:* ]]; then
        exp_is_ipv6=1
      fi
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local candidate=""
        # More precise patterns for IPv4 and IPv6 addresses followed by port
        local ipv4_port_pattern="([0-9]{1,3}\.){3}[0-9]{1,3}:${port}"
        local ipv6_port_pattern="(\[?[0-9A-Fa-f:]+\]?|::):${port}"
        candidate="$(printf '%s\n' "$line" | grep -oE "$ipv4_port_pattern" | head -n1 || true)"
        if [[ -z "$candidate" ]]; then
          candidate="$(printf '%s\n' "$line" | grep -oE "$ipv6_port_pattern" | head -n1 || true)"
        fi
        if [[ -z "$candidate" ]]; then
          continue
        fi
        candidate="${candidate%:"$port"}"
        candidate="${candidate//[\[\]]/}"
        if [[ "$candidate" == "*" ]]; then
          if ((exp_is_ipv6)); then
            candidate="$wildcard_v6"
          else
            candidate="$wildcard_v4"
          fi
        fi

        if [[ "$candidate" == "$exp" ]]; then
          conflict=1
          break
        fi
        if ((exp_is_ipv6)); then
          if [[ "$candidate" == "$wildcard_v6" ]]; then
            conflict=1
            break
          fi
        else
          if [[ "$candidate" == "$wildcard_v4" ]]; then
            conflict=1
            break
          fi
        fi
      done <<< "$output"
    fi

    if ((restore_extglob)); then
      shopt -u extglob
    fi

    if ((conflict)); then
      _details_ref="$output"
      return 0
    fi
    return 1
  fi

  return 1
}

# Provides actionable suggestions when required ports are already bound
port_conflict_guidance() {
  warn "    Resolve the conflicts by stopping or reconfiguring the services listed above."
  warn "    Common fixes include:"
  warn "      • Stopping existing ${STACK} containers: ${DOCKER_COMPOSE_CMD[*]} down"
  warn "      • Freeing the port from host services (e.g. sudo systemctl stop <service>)"
  warn "      • Updating LAN_IP or port overrides in ${ARR_USERCONF_PATH}"
}

: "${ARR_PORT_CONFLICT_AUTO_FIX:=1}"
_arr_port_conflict_quickfix_attempted=0

# Tries stopping existing ${STACK} containers once to clear port conflicts
attempt_port_conflict_quickfix() {
  if [[ "${ARR_PORT_CONFLICT_AUTO_FIX}" != "1" ]]; then
    return 1
  fi

  if [[ "${_arr_port_conflict_quickfix_attempted:-0}" == "1" ]]; then
    return 1
  fi

  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi

  if ! declare -f safe_cleanup >/dev/null 2>&1; then
    return 1
  fi

  _arr_port_conflict_quickfix_attempted=1
  msg "    Attempting automatic quick fix: stopping existing ${STACK} containers"
  safe_cleanup
  return 0
}

# Ensures host ports required by the stack are free (or warns per mode)
simple_port_check() {
  msg "  Checking required host ports"

  local mode_raw="${ARR_PORT_CHECK_MODE:-enforce}"
  local mode="${mode_raw,,}"

  case "$mode" in
    enforce | warn | skip) ;;
    "")
      mode="enforce"
      ;;
    *)
      warn "    Unknown ARR_PORT_CHECK_MODE='${mode_raw}'. Falling back to enforce."
      mode="enforce"
      ;;
  esac

  if [[ "$mode" == "skip" ]]; then
    warn "    Port availability checks skipped (ARR_PORT_CHECK_MODE=skip). Services may fail to bind if ports are busy."
    return 0
  fi

  local quickfix_used=0
  ARR_INTERNAL_PORT_CONFLICTS=0
  ARR_INTERNAL_PORT_CONFLICT_DETAIL=""

  while :; do
    local -a requirements=()
    collect_port_requirements requirements

    if ((${#requirements[@]} == 0)); then
      msg "    No host port reservations required for the selected configuration."
      return
    fi

    local -a internal_conflicts=()
    detect_internal_port_conflicts requirements internal_conflicts
    if ((${#internal_conflicts[@]} > 0)); then
      ARR_INTERNAL_PORT_CONFLICTS=1
      local -a detail_lines=()
      local -a summary_tokens=()
      local conflict_entry=""
      for conflict_entry in "${internal_conflicts[@]}"; do
        IFS='|' read -r key labels <<<"$conflict_entry"
        local proto="${key%%|*}"
        local port="${key##*|}"
        local label_list
        label_list="$(printf '%s\n' "$labels" | paste -sd', ' -)"
        detail_lines+=("${proto^^} ${port}: ${label_list}")
        summary_tokens+=("${proto^^} ${port} (${label_list})")
      done
      ARR_INTERNAL_PORT_CONFLICT_DETAIL="$(printf '%s\n' "${detail_lines[@]}")"

      if [[ "$mode" == "warn" ]]; then
        local summary_joined="${summary_tokens[*]}"
        if ((${#summary_tokens[@]} > 0)); then
          summary_joined="$(printf '%s; ' "${summary_tokens[@]}")"
          summary_joined="${summary_joined%; }"
        fi
        warn "    Port conflicts detected (ARR_PORT_CHECK_MODE=warn): ${summary_joined}; adjust ${ARR_USERCONF_PATH:-userr.conf} to assign unique host ports."
      else
        warn "    Stack configuration port conflicts detected:"
        local detail_line=""
        for detail_line in "${detail_lines[@]}"; do
          warn "      - ${detail_line}"
        done
        warn "    Adjust ${ARR_USERCONF_PATH:-userr.conf} overrides so each service uses a unique host port."
        die "Resolve internal stack port conflicts (duplicate host bindings) and rerun ./arr.sh"
      fi
    fi

    local -a conflicts=()
    local rc=0
    local requirement=""
    local tool_missing_reported=0

    for requirement in "${requirements[@]}"; do
      IFS='|' read -r proto port label expected <<<"$requirement"
      local details=""
      rc=0
      if ! port_in_use_with_details "$proto" "$port" details "$expected"; then
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
      sleep 3
      continue
    fi

    if [[ "$mode" == "warn" ]]; then
      warn "    Continuing despite port conflicts (ARR_PORT_CHECK_MODE=warn). Services may fail to bind."
      return 0
    fi

    die "Resolve port conflicts and rerun ./arr.sh"
  done
}

# Validates that local DNS prerequisites are satisfied and upstream resolvers respond
validate_dns_configuration() {
  if [[ "${ENABLE_LOCAL_DNS:-0}" != "1" ]]; then
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

# Runs installer preflight: locks, dependency validation, prompts, and previews
preflight() {
  step "🚀 Preflight checks"

  acquire_lock

  msg "  Permission profile: ${ARR_PERMISSION_PROFILE} (umask $(umask))"

  local default_userconf="${ARR_BASE:-${HOME}/srv}/userr.conf"
  local default_userconf_canon
  default_userconf_canon="$(arr_canonical_path "$default_userconf")"

  if [[ -z "${ARR_USERCONF_PATH:-}" ]]; then
    local _pf_userconf_source="default"
    arr_resolve_userconf_paths ARR_USERCONF_PATH ARR_USERCONF_OVERRIDE_PATH _pf_userconf_source
  fi

  if [[ -n "${ARR_USERCONF_OVERRIDE_PATH:-}" && "${ARR_USERCONF_OVERRIDE_PATH}" == "${default_userconf_canon}" ]]; then
    # shellcheck disable=SC2034  # consumed by scripts/config.sh
    ARR_USERCONF_OVERRIDE_PATH=""
  fi

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

  if [[ "${ASSUME_YES}" != "1" ]]; then
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

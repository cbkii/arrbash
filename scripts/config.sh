# shellcheck shell=bash

# Ensures Proton credentials are minimally viable (length/whitespace constraints)
validate_proton_creds() {
  local user="$1"
  local pass="$2"

  if [ ${#user} -lt 3 ] || [ ${#pass} -lt 6 ]; then
    return 1
  fi

  if [[ "$user" =~ [[:space:]] ]] || [[ "$pass" =~ [[:space:]] ]]; then
    return 1
  fi

  if [[ "$user" =~ [[:cntrl:]] ]] || [[ "$pass" =~ [[:cntrl:]] ]]; then
    return 1
  fi

  return 0
}

# Loads Proton auth file, coercing +pmp suffix required by docs
load_proton_credentials() {
  local proton_file="${ARRCONF_DIR}/proton.auth"

  PROTON_USER_VALUE=""
  PROTON_PASS_VALUE=""
  OPENVPN_USER_VALUE=""
  PROTON_USER_PMP_ADDED=0

  if [[ -f "$proton_file" ]]; then
    PROTON_USER_VALUE="$(grep '^PROTON_USER=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
    PROTON_PASS_VALUE="$(grep '^PROTON_PASS=' "$proton_file" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
  fi

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    die "Missing or empty PROTON_USER/PROTON_PASS in ${proton_file}"
  fi

  local enforced
  enforced="${PROTON_USER_VALUE%+pmp}+pmp"
  if [[ "$enforced" != "$PROTON_USER_VALUE" ]]; then
    PROTON_USER_PMP_ADDED=1
  fi

  OPENVPN_USER_VALUE="$enforced"
  : "$PROTON_USER_PMP_ADDED"
}

# Displays a human-readable summary of key settings with sensitive fields masked
show_configuration_preview() {
  step "🔎 Configuration preview"

  if [[ -z "$PROTON_USER_VALUE" || -z "$PROTON_PASS_VALUE" ]]; then
    load_proton_credentials
  fi

  local proton_user="${PROTON_USER_VALUE}"
  local proton_pass="${PROTON_PASS_VALUE}"
  local openvpn_user="${OPENVPN_USER_VALUE}"

  local proton_user_display="${proton_user:-'(not set)'}"
  local proton_pass_display
  proton_pass_display="$(obfuscate_sensitive "$proton_pass")"

  local qbt_pass_display
  qbt_pass_display="$(obfuscate_sensitive "${QBT_PASS:-}")"

  local openvpn_user_display
  if [[ -n "$openvpn_user" ]]; then
    openvpn_user_display="$(obfuscate_sensitive "$openvpn_user" 2 4)"
  else
    openvpn_user_display="(not set)"
  fi

  local gluetun_api_key_display
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    gluetun_api_key_display="$(obfuscate_sensitive "${GLUETUN_API_KEY}")"
  else
    gluetun_api_key_display="(will be generated during setup)"
  fi

  local lan_ip_display
  if [[ -n "${LAN_IP:-}" ]]; then
    lan_ip_display="${LAN_IP}"
  else
    lan_ip_display="(binds to 0.0.0.0 by default)"
  fi

  local vpn_mode_display
  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    vpn_mode_display="split (only qbittorrent behind VPN)"
  else
    vpn_mode_display="full-tunnel (all services through VPN)"
  fi

  local vpn_auto_summary="disabled"
  if [[ "${VPN_AUTO_RECONNECT_ENABLED:-0}" == "1" ]]; then
    local threshold_display="${VPN_SPEED_THRESHOLD_KBPS:-12}"
    local interval_display="${VPN_CHECK_INTERVAL_MINUTES:-20}"
    local window_display="anytime"
    if [[ -n "${VPN_ALLOWED_HOURS_START:-}" && -n "${VPN_ALLOWED_HOURS_END:-}" ]]; then
      local start_fmt end_fmt
      start_fmt=$(printf '%02d' "${VPN_ALLOWED_HOURS_START:-0}" 2>/dev/null || printf '%02d' 0)
      end_fmt=$(printf '%02d' "${VPN_ALLOWED_HOURS_END:-0}" 2>/dev/null || printf '%02d' 0)
      window_display="${start_fmt}–${end_fmt} UTC"
    fi
    local cap_display="${VPN_ROTATION_MAX_PER_DAY:-6}"
    if [[ ! "$cap_display" =~ ^[0-9]+$ ]]; then
      cap_display=6
    fi
    local cap_fragment
    if ((cap_display == 0)); then
      cap_fragment="rotation cap unlimited"
    else
      cap_fragment="rotation cap ${cap_display}/day"
    fi
    local jitter_display="${VPN_ROTATION_JITTER_SECONDS:-0}"
    if [[ ! "$jitter_display" =~ ^[0-9]+$ ]]; then
      jitter_display=0
    fi
    local jitter_fragment=""
    if ((jitter_display > 0)); then
      jitter_fragment="; jitter 0-${jitter_display}s"
    fi
    vpn_auto_summary="enabled (threshold ${threshold_display} KB/s; interval ${interval_display}m; window ${window_display}; ${cap_fragment}${jitter_fragment})"
  fi

  local qbt_whitelist_final="${QBT_AUTH_WHITELIST:-127.0.0.1/32,::1/128}"
  local lan_private_subnet
  if lan_private_subnet="$(lan_ipv4_subnet_cidr "${LAN_IP:-}" 2>/dev/null)" && [[ -n "$lan_private_subnet" ]]; then
    qbt_whitelist_final+="${qbt_whitelist_final:+,}${lan_private_subnet}"
  fi
  qbt_whitelist_final="$(normalize_csv "$qbt_whitelist_final")"

  local server_names_display="${SERVER_NAMES:-}"
  if [[ -z "$server_names_display" ]]; then
    server_names_display="(automatic selection)"
  fi

  local rotation_order_display="${PVPN_ROTATE_COUNTRIES:-}" 
  if [[ -z "$rotation_order_display" ]]; then
    rotation_order_display="(disabled)"
  fi

  local userconf_edit_target="${ARR_USERCONF_PATH}"
  if [[ -n "${ARR_USERCONF_OVERRIDE_PATH:-}" ]]; then
    userconf_edit_target="${ARR_USERCONF_OVERRIDE_PATH}"
  fi

  local upstream_dns_display="${UPSTREAM_DNS_SERVERS:-}"
  if [[ -z "$upstream_dns_display" ]]; then
    local upstream_parts=()
    if [[ -n "${UPSTREAM_DNS_1:-}" ]]; then
      upstream_parts+=("${UPSTREAM_DNS_1}")
    fi
    if [[ -n "${UPSTREAM_DNS_2:-}" ]]; then
      upstream_parts+=("${UPSTREAM_DNS_2}")
    fi
    if ((${#upstream_parts[@]} > 0)); then
      upstream_dns_display="$(IFS=,; printf '%s' "${upstream_parts[*]}")"
    else
      upstream_dns_display="(docker defaults)"
    fi
  fi

  local dns_suffix_display="${LAN_DOMAIN_SUFFIX:-home.arpa}"
  local local_dns_summary="disabled (suffix ${dns_suffix_display})"
  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    local_dns_summary="enabled (${dns_suffix_display}; mode ${DNS_DISTRIBUTION_MODE:-router}; upstream ${upstream_dns_display})"
  fi

  local caddy_domain_suffix="${CADDY_DOMAIN_SUFFIX:-${LAN_DOMAIN_SUFFIX:-}}"
  local caddy_domain_display
  if [[ -n "$caddy_domain_suffix" ]]; then
    caddy_domain_display="$caddy_domain_suffix"
  else
    caddy_domain_display="(not set)"
  fi

  local caddy_summary="disabled (${caddy_domain_display})"
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    caddy_summary="enabled (${caddy_domain_display}; HTTP ${CADDY_HTTP_PORT}; HTTPS ${CADDY_HTTPS_PORT})"
  fi

  local caddy_auth_user_display="${CADDY_BASIC_AUTH_USER:-(not set)}"
  local caddy_auth_hash_display="(will be generated)"
  if [[ -n "${CADDY_BASIC_AUTH_HASH:-}" ]]; then
    caddy_auth_hash_display="present"
  fi

  local direct_ports_summary="disabled"
  if [[ "${EXPOSE_DIRECT_PORTS:-1}" == "1" ]]; then
    direct_ports_summary="enabled"
  fi

  local sab_host_display="${SABNZBD_HOST:-${LOCALHOST_IP:-127.0.0.1}}"
  local sab_port_display="${SABNZBD_PORT:-${SABNZBD_INT_PORT:-8080}}"
  local sab_vpn_display="LAN"
  if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
    sab_vpn_display="VPN"
    sab_port_display="(not exposed; VPN mode)"
  fi
  local sab_category_display="${SABNZBD_CATEGORY:-${STACK}}"
  local sab_timeout_display="${SABNZBD_TIMEOUT:-15}"
  local sabnzbd_summary="disabled"
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    sabnzbd_summary="enabled (${sab_vpn_display}; host ${sab_host_display}; port ${sab_port_display}; category ${sab_category_display}; timeout ${sab_timeout_display}s)"
  fi

  local sab_api_key_display="(not set; will sync from sabnzbd.ini)"
  if [[ -n "${SABNZBD_API_KEY:-}" ]]; then
    sab_api_key_display="$(obfuscate_sensitive "${SABNZBD_API_KEY}")"
  fi

  local configarr_summary="disabled"
  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    configarr_summary="enabled"
  fi

  local usenet_client_display="${ARRBASH_USENET_CLIENT:-(not set)}"

  local caddy_lan_bypass_line=""
  if [[ "${ENABLE_CADDY:-0}" == "1" && -n "${CADDY_LAN_CIDRS:-}" ]]; then
    printf -v caddy_lan_bypass_line '  • Caddy LAN bypass CIDRs: %s\n' "${CADDY_LAN_CIDRS}"
  fi

  local sab_port_line
  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
      printf -v sab_port_line '  • SABnzbd: (not exposed; VPN mode)\n'
    else
      printf -v sab_port_line '  • SABnzbd: %s\n' "${SABNZBD_PORT}"
    fi
  else
    printf -v sab_port_line '  • SABnzbd: (disabled)\n'
  fi

  local caddy_http_line caddy_https_line
  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    printf -v caddy_http_line '  • Caddy HTTP: %s\n' "${CADDY_HTTP_PORT}"
    printf -v caddy_https_line '  • Caddy HTTPS: %s\n' "${CADDY_HTTPS_PORT}"
  else
    printf -v caddy_http_line '  • Caddy HTTP: (disabled)\n'
    printf -v caddy_https_line '  • Caddy HTTPS: (disabled)\n'
  fi

  cat <<CONFIG
------------------------------------------------------------
ARR Stack configuration preview
------------------------------------------------------------
Paths
  • Stack directory: ${ARR_STACK_DIR}
  • Docker data root: ${ARR_DOCKER_DIR}
  • Config directory: ${ARRCONF_DIR}
  • Downloads: ${DOWNLOADS_DIR}
  • Completed downloads: ${COMPLETED_DIR}
  • TV library: ${TV_DIR}
  • Movies library: ${MOVIES_DIR}
$([[ -n "${SUBS_DIR:-}" ]] && printf '  • Subtitles directory: %s\n' "${SUBS_DIR}")

Network & system
  • Timezone: ${TIMEZONE}
  • LAN IP: ${lan_ip_display}
  • Localhost IP override: ${LOCALHOST_IP}
  • VPN mode: ${vpn_mode_display}
  • Server countries: ${SERVER_COUNTRIES}
  • Server names: ${server_names_display}
  • Rotation order: ${rotation_order_display}
  • VPN auto-reconnect: ${vpn_auto_summary}
  • VPN samples required: ${VPN_CONSECUTIVE_CHECKS:-3}
  • VPN cooldown (minutes): ${VPN_COOLDOWN_MINUTES:-60}
  • VPN retry budget (minutes): ${VPN_MAX_RETRY_MINUTES:-20}
  • User/Group IDs: ${PUID}/${PGID}
  • Local DNS: ${local_dns_summary}
  • Caddy reverse proxy: ${caddy_summary}
  • Direct LAN ports: ${direct_ports_summary}
  • LAN domain suffix: ${LAN_DOMAIN_SUFFIX:-home.arpa}
  • Caddy domain suffix: ${caddy_domain_display}

Credentials & secrets
  • Proton username: ${proton_user_display}
  • Proton OpenVPN username (+pmp enforced): ${openvpn_user_display}
  • Proton password: ${proton_pass_display}
  • Gluetun API key: ${gluetun_api_key_display}
  • qBittorrent username: ${QBT_USER}
  • qBittorrent password: ${qbt_pass_display}
  • qBittorrent auth whitelist: ${qbt_whitelist_final}
  • SABnzbd API key: ${sab_api_key_display}
  • Caddy Basic Auth user: ${caddy_auth_user_display}
  • Caddy Basic Auth password hash: ${caddy_auth_hash_display}

Ports
  • Gluetun control: ${GLUETUN_CONTROL_PORT}
  • qBittorrent WebUI (host): ${QBT_PORT}
  • Sonarr: ${SONARR_PORT}
  • Radarr: ${RADARR_PORT}
  • Prowlarr: ${PROWLARR_PORT}
  • Bazarr: ${BAZARR_PORT}
  • FlareSolverr: ${FLARR_PORT}
${sab_port_line}${caddy_http_line}${caddy_https_line}

Services & automation
  • ConfigArr: ${configarr_summary}
  • SABnzbd: ${sabnzbd_summary}
  • Usenet client label: ${usenet_client_display}
$caddy_lan_bypass_line
Files that will be created/updated
  • Environment file: ${ARR_ENV_FILE}
  • Compose file: ${ARR_STACK_DIR}/docker-compose.yml

If anything looks incorrect, edit ${userconf_edit_target} before continuing.
------------------------------------------------------------
CONFIG

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
      warn "SPLIT_VPN=1: Caddy will be disabled automatically (unsupported in split mode)."
    fi
    if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
      warn "SPLIT_VPN=1: Local DNS will be disabled automatically (unsupported in split mode)."
    fi
  fi
}

# Accepts explicit credentials but falls back to global PU/PW for backward compatibility.
# Validates core configuration inputs and ports before rendering assets
validate_config() {
  local _vu="${1:-${PU:-}}"
  local _vp="${2:-${PW:-}}"

  if [ -n "${LAN_IP:-}" ] && [ "${LAN_IP}" != "0.0.0.0" ]; then
    validate_ipv4 "${LAN_IP}" || die "Invalid LAN_IP: ${LAN_IP}"
  fi
  validate_port "${GLUETUN_CONTROL_PORT}" || die "Invalid GLUETUN_CONTROL_PORT: ${GLUETUN_CONTROL_PORT}"
  validate_port "${QBT_PORT}" || die "Invalid QBT_PORT: ${QBT_PORT}"
  validate_port "${SONARR_PORT}" || die "Invalid SONARR_PORT: ${SONARR_PORT}"
  validate_port "${RADARR_PORT}" || die "Invalid RADARR_PORT: ${RADARR_PORT}"
  validate_port "${PROWLARR_PORT}" || die "Invalid PROWLARR_PORT: ${PROWLARR_PORT}"
  validate_port "${BAZARR_PORT}" || die "Invalid BAZARR_PORT: ${BAZARR_PORT}"
  validate_port "${FLARR_PORT}" || die "Invalid FLARR_PORT: ${FLARR_PORT}"

  validate_proton_creds "${_vu}" "${_vp}" || die "Invalid ProtonVPN credentials format"
}

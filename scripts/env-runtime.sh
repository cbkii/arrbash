# shellcheck shell=bash
# Purpose: Prepare runtime environment values and hydrate persisted credentials.
# Inputs: Consumes numerous ARR_* variables, SPLIT_VPN, ARR_ENV_FILE, LAN_IP, ARR_USERCONF_PATH.
# Outputs: Normalizes environment variables in-place and prompts for direct port exposure when needed.
# Exit codes: Functions return non-zero when validations fail (e.g., LAN_IP invalid) or user aborts prompts.
# shellcheck disable=SC2034
if [[ -n "${__CONFIG_ENV_LOADED:-}" ]]; then
  return 0
fi
__CONFIG_ENV_LOADED=1

arr_prompt_direct_port_exposure() {
  local lan_ip="$1"
  local ip_hint="$lan_ip"

  if [[ -z "$ip_hint" || "$ip_hint" == "0.0.0.0" ]] || ! validate_ipv4 "$ip_hint"; then
    local detected_ip=""
    detected_ip="$(LC_ALL=C hostname -I 2>/dev/null | LC_ALL=C awk 'NF {print $1}' | LC_ALL=C tr -d '\n')"
    if [[ -z "$detected_ip" ]] || [[ "$detected_ip" == "0.0.0.0" ]] || ! validate_ipv4 "$detected_ip"; then
      ip_hint="127.0.0.1"
    else
      ip_hint="$detected_ip"
    fi
  fi

  msg "EXPOSE_DIRECT_PORTS=1 will publish the following LAN URLs:"
  printf '  %-11s → http://%s:%s\n' "qBittorrent" "$ip_hint" "$QBT_PORT"
  printf '  %-11s → http://%s:%s\n' "Sonarr" "$ip_hint" "$SONARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Radarr" "$ip_hint" "$RADARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Lidarr" "$ip_hint" "$LIDARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Prowlarr" "$ip_hint" "$PROWLARR_PORT"
  printf '  %-11s → http://%s:%s\n' "Bazarr" "$ip_hint" "$BAZARR_PORT"
  printf '  %-11s → http://%s:%s\n' "FlareSolverr" "$ip_hint" "$FLARR_PORT"

  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    msg "ASSUME_YES=1; continuing without additional confirmation."
    return 0
  fi

  printf 'Expose these ports on the LAN? [y/N]: '
  local response=""
  if ! read -r response; then
    warn "Could not read confirmation response; disabling EXPOSE_DIRECT_PORTS for safety."
    EXPOSE_DIRECT_PORTS=0
    return 0
  fi

  case "${response,,}" in
    y | yes)
      msg "Continuing with EXPOSE_DIRECT_PORTS=1."
      ;;
    *)
      warn "Disabling EXPOSE_DIRECT_PORTS for this run; rerun with --yes to skip the prompt."
      EXPOSE_DIRECT_PORTS=0
      ;;
  esac
}


prepare_env_context() {
  step "📝 Preparing environment values"

  hydrate_user_credentials_from_env_file
  hydrate_sab_api_key_from_config
  hydrate_qbt_host_port_from_env_file
  hydrate_qbt_webui_port_from_config

  local direct_ports_raw="${EXPOSE_DIRECT_PORTS:-0}"
  EXPOSE_DIRECT_PORTS="$(arr_normalize_bool "$direct_ports_raw")"
  local split_vpn_raw="${SPLIT_VPN:-0}"
  local split_vpn
  split_vpn="$(arr_normalize_bool "$split_vpn_raw")"
  case "$split_vpn_raw" in
    ''|0|1|true|TRUE|false|FALSE|yes|YES|no|NO|on|ON|off|OFF) ;;
    *)
      warn "Invalid SPLIT_VPN=${split_vpn_raw}; defaulting to 0 (full tunnel)."
      split_vpn=0
      ;;
  esac
  SPLIT_VPN="$split_vpn"

  local direct_ports_requested="${EXPOSE_DIRECT_PORTS}"
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  local user_supplied_lan_ip="${LAN_IP:-}"
  if [[ -n "$user_supplied_lan_ip" ]]; then
    if ! validate_ipv4 "$user_supplied_lan_ip"; then
      die "Invalid LAN_IP provided (${user_supplied_lan_ip}). Fix ${userconf_path} or unset to auto-detect."
    fi
    LAN_IP="$user_supplied_lan_ip"
    msg "Using configured LAN_IP: $LAN_IP"
  else
    if detected_ip="$(detect_lan_ip 2>/dev/null)"; then
      LAN_IP="$detected_ip"
      msg "Auto-detected LAN_IP: $LAN_IP"
    else
      LAN_IP="0.0.0.0"
      warn "LAN_IP could not be detected automatically; set it in ${userconf_path} so services bind to the correct interface."
      warn "Determine the address with: hostname -I | awk \"{print \\\$1}\""
    fi
  fi

  export LAN_IP

  local -a lan_requirements=()
  if ((direct_ports_requested == 1)); then
    lan_requirements+=("EXPOSE_DIRECT_PORTS=1")
  fi
  if ((split_vpn == 1)); then
    lan_requirements+=("SPLIT_VPN=1")
  fi
  if ((${#lan_requirements[@]} > 0)); then
    local requirement_msg="${lan_requirements[0]}"
    if ((${#lan_requirements[@]} == 2)); then
      requirement_msg="${lan_requirements[0]} and ${lan_requirements[1]}"
    fi
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      die "${requirement_msg} requires LAN_IP to be set to your host's private IPv4 address in ${userconf_path}."
    fi
    if ! is_private_ipv4 "$LAN_IP"; then
      die "LAN_IP='${LAN_IP}' must be a private IPv4 address when ${requirement_msg} is enabled. Update ${userconf_path}."
    fi
  fi

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    arr_prompt_direct_port_exposure "$LAN_IP"
  fi

  local sab_enabled_raw="${SABNZBD_ENABLED:-0}"
  local sab_enabled
  sab_enabled="$(arr_normalize_bool "$sab_enabled_raw")"
  SABNZBD_ENABLED="$sab_enabled"
  export SABNZBD_ENABLED

  local sab_use_vpn_raw="${SABNZBD_USE_VPN:-0}"
  local sab_use_vpn
  sab_use_vpn="$(arr_normalize_bool "$sab_use_vpn_raw")"
  case "$sab_use_vpn_raw" in
    ''|0|1|true|TRUE|false|FALSE|yes|YES|no|NO|on|ON|off|OFF) ;;
    *)
      warn "Invalid SABNZBD_USE_VPN=${sab_use_vpn_raw}; defaulting to 0 (direct mode)."
      sab_use_vpn=0
    ;;
  esac

  local gluetun_available=0
  if declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1; then
    local svc=""
    for svc in "${ARR_DOCKER_SERVICES[@]:-}"; do
      if [[ "$svc" == "gluetun" ]]; then
        gluetun_available=1
        break
      fi
    done
  fi

  if ((gluetun_available)); then
    if [[ "${ENABLE_GLUETUN:-1}" == "0" ]]; then
      gluetun_available=0
    fi
  fi

  if ((gluetun_available)); then
    case "${VPN_SERVICE_PROVIDER:-protonvpn}" in
      '' | none | disabled | off)
        gluetun_available=0
        ;;
    esac
  fi

  if ((sab_enabled)) && ((sab_use_vpn == 1)) && ((gluetun_available == 0)); then
    warn "SABNZBD_USE_VPN=1 ignored (Gluetun disabled)"
    sab_use_vpn=0
  fi

  SABNZBD_USE_VPN="$sab_use_vpn"
  export SABNZBD_USE_VPN

  local sab_timeout_raw
  arr_resolve_positive_int sab_timeout_raw "${SABNZBD_TIMEOUT:-}" 15 \
    "Invalid SABNZBD_TIMEOUT=${SABNZBD_TIMEOUT:-}; defaulting to 15 seconds."
  SABNZBD_TIMEOUT="$sab_timeout_raw"

  local sab_internal_port_raw
  arr_resolve_port sab_internal_port_raw "${SABNZBD_INT_PORT:-}" 8080 \
    "Invalid SABNZBD_INT_PORT=${SABNZBD_INT_PORT:-}; defaulting to 8080."
  SABNZBD_INT_PORT="$sab_internal_port_raw"

  local sab_port_raw
  arr_resolve_port sab_port_raw "${SABNZBD_PORT:-}" "$SABNZBD_INT_PORT" \
    "Invalid SABNZBD_PORT=${SABNZBD_PORT:-}; defaulting to ${SABNZBD_INT_PORT}."
  SABNZBD_PORT="$sab_port_raw"

  local sab_host_default="${LOCALHOST_IP:-localhost}"
  local sab_host_value="${SABNZBD_HOST:-}"
  if [[ -z "$sab_host_value" ]]; then
    sab_host_value="$sab_host_default"
  fi

  local sab_host_auto=0
  if ((sab_enabled)) && ((sab_use_vpn == 1)); then
    local sab_host_lower="${sab_host_value,,}"
    local sab_default_lower="${sab_host_default,,}"
    case "$sab_host_lower" in
      "$sab_default_lower" | 127.0.0.1 | localhost | "$LOCALHOST_IP")
        sab_host_value="sabnzbd"
        sab_host_auto=1
        ;;
    esac

    if ((sab_host_auto == 0)); then
      case "$sab_host_lower" in
        sabnzbd | gluetun) ;;
        *)
          warn "SABnzbd is routed through the VPN; ensure SABNZBD_HOST='${sab_host_value}' is reachable (sabnzbd is recommended)."
          ;;
      esac
    fi
  fi

  SABNZBD_HOST="$sab_host_value"
  export ARR_SAB_HOST_AUTO="$sab_host_auto"
  export SABNZBD_INT_PORT SABNZBD_PORT SABNZBD_HOST

  local qbt_webui_default="${QBT_INT_PORT:-8082}"
  local qbt_host_default="$qbt_webui_default"
  local qbt_webui_port="$qbt_webui_default"
  local qbt_host_port="$qbt_host_default"
  local qbt_webui_status="default"
  local qbt_host_status="default"

  if [[ -n "${ARR_QBT_INT_PORT_CONFIG:-}" ]]; then
    qbt_webui_port="${ARR_QBT_INT_PORT_CONFIG}"
    qbt_webui_status="preserved"
  fi

  if [[ -n "${ARR_QBT_HOST_PORT_ENV:-}" ]]; then
    qbt_host_port="${ARR_QBT_HOST_PORT_ENV}"
    qbt_host_status="preserved"
  elif [[ -n "${QBT_PORT:-}" ]]; then
    qbt_host_port="${QBT_PORT}"
  fi

  local qbt_host_port_raw="$qbt_host_port"
  arr_resolve_port qbt_host_port "$qbt_host_port_raw" "$qbt_host_default" \
    "Invalid QBT_PORT=${qbt_host_port_raw}; defaulting to ${qbt_host_default}."
  if [[ "$qbt_host_port" == "$qbt_host_default" && "$qbt_host_port_raw" != "$qbt_host_default" ]]; then
    qbt_host_status="default"
  fi

  if [[ "$qbt_webui_status" == "preserved" && "$qbt_webui_port" != "$qbt_webui_default" ]]; then
    arr_record_preserve_note "Preserved qBittorrent WebUI port ${qbt_webui_port}"
  fi
  if [[ "$qbt_host_status" == "preserved" && "$qbt_host_port" != "$qbt_host_default" ]]; then
    arr_record_preserve_note "Preserved qBittorrent host port ${qbt_host_port}"
  fi

  local qbt_webui_port_raw="$qbt_webui_port"
  arr_resolve_port qbt_webui_port "$qbt_webui_port_raw" "$qbt_webui_default" \
    "Invalid qBittorrent WebUI port ${qbt_webui_port_raw}; using ${qbt_webui_default}."
  if [[ "$qbt_webui_port" == "$qbt_webui_default" && "$qbt_webui_port_raw" != "$qbt_webui_default" ]]; then
    qbt_webui_status="default"
  fi

  QBT_INT_PORT="$qbt_webui_port"
  QBT_PORT="$qbt_host_port"
  export ARR_QBT_INT_PORT_STATUS="$qbt_webui_status"
  export ARR_QBT_HOST_PORT_STATUS="$qbt_host_status"
  export QBT_INT_PORT QBT_PORT QBT_WEB_PORT

  local qbt_bind_addr_value="${QBT_BIND_ADDR:-0.0.0.0}"
  if [[ -z "$qbt_bind_addr_value" ]]; then
    qbt_bind_addr_value="0.0.0.0"
  fi
  QBT_BIND_ADDR="$qbt_bind_addr_value"

  local qbt_enforce_value="${QBT_ENFORCE_WEBUI:-1}"
  case "$qbt_enforce_value" in
    0 | 1) ;;
    *)
      qbt_enforce_value=1
      ;;
  esac
  QBT_ENFORCE_WEBUI="$qbt_enforce_value"
  export QBT_ENFORCE_WEBUI

  local sab_api_state="empty"
  local sab_api_value="${SABNZBD_API_KEY:-}"
  if [[ -n "$sab_api_value" ]]; then
    local sab_api_upper="${sab_api_value^^}"
    if [[ "$sab_api_upper" == REPLACE_WITH_* ]]; then
      sab_api_state="placeholder"
    else
      sab_api_state="set"
    fi
  fi
  ARR_SAB_API_KEY_STATE="$sab_api_state"
  export ARR_SAB_API_KEY_STATE
  case "$sab_api_state" in
    set)
      if [[ -z "${ARR_SAB_API_KEY_SOURCE:-}" ]]; then
        ARR_SAB_API_KEY_SOURCE="provided"
      fi
      ;;
    placeholder)
      ARR_SAB_API_KEY_SOURCE="placeholder"
      ;;
    empty)
      ARR_SAB_API_KEY_SOURCE="empty"
      ;;
  esac

  load_proton_credentials

  PU="$OPENVPN_USER_VALUE"
  PW="$PROTON_PASS_VALUE"

  validate_config "$PU" "$PW"

  if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
    local existing_project_name=""
    if existing_project_name="$(get_env_kv "COMPOSE_PROJECT_NAME" "$ARR_ENV_FILE" 2>/dev/null)"; then
      COMPOSE_PROJECT_NAME="$existing_project_name"
    else
      COMPOSE_PROJECT_NAME="${STACK}"
    fi
  fi
  if [[ ! ${VPN_SERVICE_PROVIDER+x} ]]; then
    VPN_SERVICE_PROVIDER="protonvpn"
  fi

  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_openvpn_user >/dev/null 2>&1; then
    OPENVPN_USER="$(arr_derive_openvpn_user)"
  else
    OPENVPN_USER=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_openvpn_password >/dev/null 2>&1; then
    OPENVPN_PASSWORD="$(arr_derive_openvpn_password)"
  else
    OPENVPN_PASSWORD=""
  fi

  if type -t arr_derive_gluetun_firewall_outbound_subnets >/dev/null 2>&1; then
    GLUETUN_FIREWALL_OUTBOUND_SUBNETS="$(arr_derive_gluetun_firewall_outbound_subnets)"
  else
    GLUETUN_FIREWALL_OUTBOUND_SUBNETS=""
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_gluetun_firewall_input_ports >/dev/null 2>&1; then
    GLUETUN_FIREWALL_INPUT_PORTS="$(arr_derive_gluetun_firewall_input_ports)"
  else
    GLUETUN_FIREWALL_INPUT_PORTS=""
  fi
  local publish_qbt_via_gluetun=0
  local qbt_publish_port_candidate
  qbt_publish_port_candidate="${QBT_PORT:-${QBT_INT_PORT:-8082}}"
  if [[ -n "$qbt_publish_port_candidate" ]]; then
    publish_qbt_via_gluetun=1
  fi
  if ((publish_qbt_via_gluetun)); then
    local qbt_publish_port
    qbt_publish_port="$qbt_publish_port_candidate"
    if [[ -z "$qbt_publish_port" || ! "$qbt_publish_port" =~ ^[0-9]+$ ]]; then
      local port_display="${QBT_PORT:-${QBT_INT_PORT:-<unset>}}"
      die "Invalid qBittorrent WebUI port '${port_display}'; set QBT_PORT in ${userconf_path} to a numeric value."
    fi
    local firewall_ports_csv=""
    firewall_ports_csv="$(normalize_csv "${GLUETUN_FIREWALL_INPUT_PORTS:-}")"
    GLUETUN_FIREWALL_INPUT_PORTS="$firewall_ports_csv"
    local has_qbt_port=0
    if [[ -n "$firewall_ports_csv" ]]; then
      local -a _firewall_tokens=()
      IFS=',' read -ra _firewall_tokens <<<"$firewall_ports_csv"
      local token
      for token in "${_firewall_tokens[@]}"; do
        token="${token//[[:space:]]/}"
        if [[ "$token" == "$qbt_publish_port" ]]; then
          has_qbt_port=1
          break
        fi
      done
    fi
    if ((has_qbt_port == 0)); then
      local firewall_display="${firewall_ports_csv:-<unset>}"
      die "Gluetun FIREWALL_INPUT_PORTS (${firewall_display}) must include qBittorrent port ${qbt_publish_port}. Update ${userconf_path} or overrides to keep the WebUI reachable."
    fi
  fi
  # shellcheck disable=SC2034  # consumed by env template generation
  if type -t arr_derive_compose_profiles_csv >/dev/null 2>&1; then
    COMPOSE_PROFILES="$(arr_derive_compose_profiles_csv)"
  else
    COMPOSE_PROFILES=""
  fi

  local -a upstream_dns_servers=()
  if declare -f collect_upstream_dns_servers >/dev/null 2>&1; then
    mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers 2>/dev/null || true)
  fi
  arr_assign_upstream_dns_env "${upstream_dns_servers[@]}"

  local qbt_whitelist_raw
  qbt_whitelist_raw="${QBT_AUTH_WHITELIST:-}"
  if [[ -z "$qbt_whitelist_raw" ]]; then
    qbt_whitelist_raw="${LOCALHOST_IP}/32,::1/128"
  fi
  local lan_private_subnet=""
  if lan_private_subnet="$(lan_ipv4_subnet_cidr "$LAN_IP" 2>/dev/null)"; then
    :
  else
    lan_private_subnet=""
  fi
  if [[ -n "$lan_private_subnet" ]]; then
    qbt_whitelist_raw+="${qbt_whitelist_raw:+,}${lan_private_subnet}"
  fi
  QBT_AUTH_WHITELIST="$(normalize_csv "$qbt_whitelist_raw")"
  export QBT_AUTH_WHITELIST

  if declare -f arr_collect_all_expected_env_keys >/dev/null 2>&1; then
    while IFS= read -r _env_key; do
      [[ -z "$_env_key" ]] && continue
      if [[ ! ${!_env_key+x} ]]; then
        printf -v "$_env_key" '%s' ""
      fi
      # shellcheck disable=SC2163
      export "$_env_key"
    done < <(arr_collect_all_expected_env_keys)
  fi

  ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"
}

# Appends the shared SABnzbd service definition to the provided compose fragment.
# The caller handles network configuration and passes 1 as the second argument
# when direct-mode ports should be exposed on the LAN.

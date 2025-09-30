# shellcheck shell=bash
show_summary() {

  msg "🎉 Setup complete!!"
  warn "Check these details and revisit the README for any manual steps you may need to perform from here"

  msg "LAN binding target: ${LAN_IP:-<unset>}"

  # Always show qBittorrent access information prominently
  local qbt_pass_msg=""
  if [[ -f "$ARR_ENV_FILE" ]]; then
    local configured_pass
    configured_pass="$(grep "^QBT_PASS=" "$ARR_ENV_FILE" | cut -d= -f2- || true)"
    if [[ -n "$configured_pass" && "$configured_pass" != "adminadmin" ]]; then
      qbt_pass_msg="Password: ${configured_pass} (from .env)"
    else
      qbt_pass_msg="Password: Check docker logs qbittorrent"
    fi
  fi

  local ip_hint="${LAN_IP:-}"
  if [[ -z "$ip_hint" || "$ip_hint" == "0.0.0.0" ]]; then
    ip_hint="<LAN_IP>"
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    msg "VPN Mode: split (only qbittorrent behind VPN)"
    msg "Configure *Arr download client host as: http://${ip_hint}:${QBT_HTTP_PORT_HOST}"
  else
    msg "VPN Mode: full-tunnel (all services through VPN)"
    warn "Consider SPLIT_VPN=1 for improved indexer reliability."
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
WebUI:    http://${ip_hint}:${QBT_HTTP_PORT_HOST}
Username: ${QBT_USER}
${qbt_pass_msg}
================================================

QBT_INFO

  if [[ -n "${ARRSTACK_PRESERVE_NOTES:-}" ]]; then
    msg "Credential preservation decisions:"
    while IFS= read -r preserve_note; do
      [[ -z "$preserve_note" ]] && continue
      msg "  - ${preserve_note}"
    done < <(printf '%s\n' "${ARRSTACK_PRESERVE_NOTES}")
  fi

  local vt_summary_message="${VUETORRENT_STATUS_MESSAGE:-}"
  if [[ -z "$vt_summary_message" ]]; then
    if [[ "${VUETORRENT_MODE}" == "manual" ]]; then
      vt_summary_message="VueTorrent manual mode active at ${VUETORRENT_ROOT}."
    else
      vt_summary_message="VueTorrent via LSIO Docker mod (WebUI root ${VUETORRENT_ROOT})."
    fi
  fi

  if [[ "${VUETORRENT_STATUS_LEVEL:-msg}" == "warn" ]]; then
    warn "$vt_summary_message"
  else
    msg "$vt_summary_message"
  fi

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" -eq 1 ]]; then
    cat <<'DIRECT'
Direct LAN URLs (ipdirect profile enabled):
DIRECT
    cat <<DIRECT_URLS
  qBittorrent:  http://${ip_hint}:${QBT_HTTP_PORT_HOST}
  Sonarr:       http://${ip_hint}:${SONARR_PORT}
  Radarr:       http://${ip_hint}:${RADARR_PORT}
  Prowlarr:     http://${ip_hint}:${PROWLARR_PORT}
  Bazarr:       http://${ip_hint}:${BAZARR_PORT}
  FlareSolverr: http://${ip_hint}:${FLARESOLVERR_PORT}
DIRECT_URLS
  else
    cat <<'DIRECT_DISABLED'
Direct LAN URLs are not published (EXPOSE_DIRECT_PORTS=0).
Access services from the host network (docker compose exec/port-forward) or add your own reverse proxy.
DIRECT_DISABLED
  fi

  if [[ "${ENABLE_CADDY:-0}" -eq 1 ]]; then
    local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"
    cat <<CADDY_INFO

Proxy profile enabled (Caddy reverse proxy):
  http://qbittorrent.${domain_suffix}
  https://qbittorrent.${domain_suffix} (trust the internal CA)
  Health endpoint: http://${ip_hint}/healthz
Remote clients must authenticate with '${CADDY_BASIC_AUTH_USER}' using the password stored in ${ARR_DOCKER_DIR}/caddy/credentials.
CADDY_INFO
  else
    if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
      cat <<'NO_CADDY_SPLIT'

Reverse proxy disabled in split VPN mode (SPLIT_VPN=1).
Multi-network proxy support is planned for a future release.
NO_CADDY_SPLIT
    else
      cat <<NO_CADDY

Reverse proxy disabled (ENABLE_CADDY=0).
Access the services via the direct LAN URLs above.
Set ENABLE_CADDY=1 in ${ARR_USERCONF_PATH} and rerun ./arrstack.sh to publish HTTPS hostnames signed by the internal CA.
NO_CADDY
    fi
    if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
      cat <<'DNS_HTTP'
Local DNS is enabled. Hostnames will resolve but continue serving plain HTTP until Caddy is enabled.
DNS_HTTP
    fi
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" -eq 1 ]]; then
    if [[ ${LOCAL_DNS_SERVICE_ENABLED:-0} -eq 1 ]]; then
      msg "Local DNS is enabled. Point DHCP Option 6 (or per-device DNS) at ${LAN_IP:-<unset>} so hostnames resolve."
    else
      warn "Local DNS requested but the container is disabled (port 53 conflict). Resolve the conflict and rerun."
    fi
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" || -z "${LAN_IP:-}" ]]; then
    cat <<WARNING
⚠️  SECURITY WARNING
   LAN_IP is unset or 0.0.0.0 so services listen on all interfaces.
   Update ${ARR_USERCONF_PATH} with a specific LAN_IP to limit exposure.

WARNING
  fi

  if [[ "${QBT_USER}" == "admin" && "${QBT_PASS}" == "adminadmin" ]]; then
    cat <<'WARNING'
⚠️  DEFAULT CREDENTIALS
   qBittorrent is using admin/adminadmin.
   Change this in the WebUI and update QBT_USER/QBT_PASS in .env.

WARNING
  fi

  if [[ "${VPN_SERVICE_PROVIDER:-}" == "protonvpn" && "${VPN_PORT_FORWARDING:-on}" == "on" ]]; then
    local pf_state_file=""
    local pf_log_file=""
    if declare -f pf_state_path >/dev/null 2>&1; then
      pf_state_file="$(pf_state_path)"
    else
      pf_state_file="${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_STATE_FILE:-pf-state.json}"
    fi
    if declare -f pf_log_path >/dev/null 2>&1; then
      pf_log_file="$(pf_log_path)"
    else
      pf_log_file="${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_LOG_FILE:-port-forwarding.log}"
    fi

    local pf_summary_port="0"
    local pf_status_value=""
    local pf_status_message=""
    local pf_attempts="0"
    local pf_cycles="0"
    local pf_last_success=""

    if [[ -f "$pf_state_file" ]]; then
      if command -v jq >/dev/null 2>&1; then
        pf_summary_port="$(jq -r '.port // 0' "$pf_state_file" 2>/dev/null || printf '0')"
        pf_status_value="$(jq -r '.status // ""' "$pf_state_file" 2>/dev/null || printf '')"
        pf_status_message="$(jq -r '.message // ""' "$pf_state_file" 2>/dev/null || printf '')"
        pf_attempts="$(jq -r '.attempts // 0' "$pf_state_file" 2>/dev/null || printf '0')"
        pf_cycles="$(jq -r '.cycles // 0' "$pf_state_file" 2>/dev/null || printf '0')"
        pf_last_success="$(jq -r '.last_success // ""' "$pf_state_file" 2>/dev/null || printf '')"
      else
        pf_summary_port="$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$pf_state_file" | head -n1 || printf '0')"
        pf_status_value="$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pf_state_file" | head -n1 || printf '')"
        pf_status_message="$(sed -n 's/.*"message"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pf_state_file" | head -n1 || printf '')"
        pf_attempts="$(sed -n 's/.*"attempts"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$pf_state_file" | head -n1 || printf '0')"
        pf_cycles="$(sed -n 's/.*"cycles"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$pf_state_file" | head -n1 || printf '0')"
        pf_last_success="$(sed -n 's/.*"last_success"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pf_state_file" | head -n1 || printf '')"
      fi
    else
      pf_summary_port="${PF_ENSURED_PORT:-0}"
      pf_status_value="${PF_ENSURE_STATUS_MESSAGE:-pending}"
    fi

    if [[ ! "$pf_summary_port" =~ ^[0-9]+$ ]]; then
      pf_summary_port="0"
    fi

    case "$pf_status_value" in
      acquired)
        if [[ "$pf_summary_port" != "0" ]]; then
          msg "✅ Proton port forwarding active: Port ${pf_summary_port} (attempts=${pf_attempts}, cycles=${pf_cycles})"
          if [[ -n "$pf_last_success" ]]; then
            msg "   Last refreshed: ${pf_last_success}"
          fi
        fi
        ;;
      disabled)
        msg "[pf] Proton port forwarding disabled in configuration."
        ;;
      pending | "")
        warn "⚠️  ProtonVPN port forwarding pending${pf_status_message:+ (${pf_status_message})}."
        msg "   State file: ${pf_state_file}"
        msg "   Log file:   ${pf_log_file}"
        msg "   Follow progress with 'arr.vpn.port.watch' or retry via 'arr.vpn.port.sync'."
        ;;
      timeout | timeout-soft | failed)
        warn "⚠️  ProtonVPN port forwarding ${pf_status_value}${pf_status_message:+ (${pf_status_message})}."
        msg "   Attempts: ${pf_attempts}, cycles: ${pf_cycles}"
        msg "   State file: ${pf_state_file}"
        msg "   Log file:   ${pf_log_file}"
        msg "   Run 'arr.vpn.port.sync' after Gluetun stabilises to retry."
        ;;
      *)
        warn "⚠️  ProtonVPN port forwarding status: ${pf_status_value:-unknown}${pf_status_message:+ (${pf_status_message})}."
        msg "   State file: ${pf_state_file}"
        msg "   Log file:   ${pf_log_file}"
        ;;
    esac
  fi

  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && -n "${COLLAB_PERMISSION_WARNINGS:-}" ]]; then
    warn "Collaborative profile notes:"
    while IFS= read -r collab_warning; do
      [[ -z "$collab_warning" ]] && continue
      warn "  - ${collab_warning}"
    done < <(printf '%s\n' "${COLLAB_PERMISSION_WARNINGS}")
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" -eq 1 ]]; then
    local configarr_config="${ARR_DOCKER_DIR}/configarr/config.yml"
    local configarr_secrets="${ARR_DOCKER_DIR}/configarr/secrets.yml"
    cat <<CONFIGARR
Configarr:
  Manual sync: arr.config.sync
  Config:      ${configarr_config}
  Secrets:     ${configarr_secrets}

CONFIGARR
    if [[ -n "${CONFIGARR_POLICY_RESOLUTION:-}" ]]; then
      cat <<POLICY
  Policy:
    Resolutions: ${CONFIGARR_POLICY_RESOLUTION}
    Episode cap: ${CONFIGARR_POLICY_EP_GB} GB (~${CONFIGARR_POLICY_EP_MBMIN} MB/min)
    Season target: ${CONFIGARR_POLICY_SEASON_GB} GB (informational)
    Runtime basis: ${CONFIGARR_POLICY_RUNTIME} min
    Language bias (${CONFIGARR_POLICY_LANG}): ${CONFIGARR_POLICY_ENGLISH}
    Multi penalty: ${CONFIGARR_POLICY_MULTI}
    x265 HD penalty: ${CONFIGARR_POLICY_X265}
    Junk reinforcement: ${CONFIGARR_POLICY_JUNK}

POLICY
    fi
    if [[ -n "${API_KEYS_SYNCED_MESSAGE:-}" ]]; then
      msg "${API_KEYS_SYNCED_MESSAGE}"
      if [[ -n "${API_KEYS_SYNCED_DETAILS:-}" ]]; then
        while IFS= read -r detail_line; do
          [[ -z "$detail_line" ]] && continue
          msg "  - ${detail_line}"
        done < <(printf '%s\n' "${API_KEYS_SYNCED_DETAILS}")
      fi
    fi

    local secrets_have_placeholders=0
    if [[ -f "$configarr_secrets" ]] && grep -Fq 'REPLACE_WITH_' "$configarr_secrets"; then
      secrets_have_placeholders=1
    fi

    if [[ "${API_KEYS_SYNCED_PLACEHOLDERS:-0}" -eq 1 || secrets_have_placeholders -eq 1 ]]; then
      warn "Configarr secrets still contain placeholder API keys. Run ./arrstack.sh --sync-api-keys after Sonarr/Radarr/Prowlarr finish initial setup."
    fi
  fi

  cat <<SUMMARY
Gluetun control server (local only): http://${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}

Helper commands:
  source ${ARR_STACK_DIR}/.aliasarr
  arr.help       # Show all available aliases
  arr.vpn.status # Check VPN status and forwarded port
  arr.logs       # Follow container logs via docker compose

SUMMARY
}

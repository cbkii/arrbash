# shellcheck shell=bash

# Formats epoch seconds into ISO8601 or '(none)' when unset
summary_format_epoch() {
  local epoch="$1"
  if [[ -z "$epoch" || ! "$epoch" =~ ^[0-9]+$ || "$epoch" -le 0 ]]; then
    printf '(none)'
    return 0
  fi
  date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '%s' "$epoch"
}

# Presents post-install recap with access URLs, credentials, and PF status
show_summary() {

  if arr_run_failure_flag_exists; then
    local failure_reason failure_code failure_key
    failure_reason="$(arr_read_run_failure_reason 2>/dev/null || printf 'VPN not running.')"
    failure_code="$(arr_read_run_failure_code 2>/dev/null || printf '')"
    failure_key="$(arr_read_run_failure_reason_key 2>/dev/null || printf '')"
    msg "❌ Setup FAILED"
    warn "$failure_reason"
    msg "Next steps:"
    case "${failure_key:-$failure_code}" in
      VPN_NOT_RUNNING)
        msg "  1. Inspect Gluetun logs: docker logs --tail=200 gluetun"
        msg "  2. Verify VPN credentials and network access in ${ARR_USERCONF_PATH}."
        msg "  3. Restart with: ./arrstack.sh start"
        ;;
      PF_NOT_ACQUIRED)
        msg "  1. Review Proton PF log: ${ARR_DOCKER_DIR}/gluetun/${PF_ASYNC_LOG_FILE:-port-forwarding.log}"
        msg "  2. Confirm your Proton server supports port forwarding or rotate regions."
        msg "  3. Retry the lease with: arr.vpn.port.sync"
        ;;
      *)
        msg "  1. Check ${ARR_STACK_DIR}/logs for detailed error messages."
        msg "  2. Address the issue noted above."
        msg "  3. Re-run ./arrstack.sh start"
        ;;
    esac
    return 0
  fi

  msg "🎉 Setup complete!!"
  warn "Check these details and revisit the README for any manual steps you may need to perform from here"

  msg "LAN binding target: ${LAN_IP:-<unset>}"

  # Always show qBittorrent access information prominently
  local qbt_pass_msg=""
  if [[ -f "$ARR_ENV_FILE" ]]; then
    local configured_pass=""
    if configured_pass="$(get_env_kv "QBT_PASS" "$ARR_ENV_FILE" 2>/dev/null)"; then
      if [[ -n "$configured_pass" && "$configured_pass" != "adminadmin" ]]; then
        qbt_pass_msg="Password: ${configured_pass} (from .env)"
      else
        qbt_pass_msg="Password: Check docker logs qbittorrent"
      fi
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
    msg "Configure *Arr download client host as: http://${ip_hint}:${QBT_PORT}"
  else
    msg "VPN Mode: full-tunnel (all services through VPN)"
    warn "Consider SPLIT_VPN=1 for improved indexer reliability."
  fi

  cat <<QBT_INFO
================================================
qBittorrent Access Information:
================================================
WebUI:    http://${ip_hint}:${QBT_PORT}
Username: ${QBT_USER}
${qbt_pass_msg}
================================================

QBT_INFO

  local qbt_container_status="${ARR_QBT_INT_PORT_STATUS:-default}"
  local qbt_host_status="${ARR_QBT_HOST_PORT_STATUS:-default}"
  local container_suffix=""
  local host_suffix=""
  case "$qbt_container_status" in
    preserved) container_suffix="(preserved)" ;;
    *) container_suffix="(default)" ;;
  esac
  case "$qbt_host_status" in
    preserved) host_suffix="(preserved)" ;;
    *) host_suffix="(default)" ;;
  esac
  msg "qBittorrent ports: container ${QBT_INT_PORT} ${container_suffix}, host ${QBT_PORT} ${host_suffix}"

  case "${ARR_PF_STATUS:-}" in
    acquired)
      msg "Port forwarding ready: ${ARR_PF_NOTICE:-Forwarded port acquired.}"
      ;;
    not_acquired)
      warn "Port forwarding not acquired. This is optional and depends on your VPN provider/plan/server. ${ARR_PF_NOTICE:-Check your VPN plan or region.} Services are running without a forwarded port; inspect PF logs if you need inbound peers."
      ;;
  esac

  if [[ "${ARR_TIMEZONE_AUTO_FALLBACK:-0}" == "1" && "${TIMEZONE:-}" == "UTC" && "${ARR_TIMEZONE_DETECTION_METHOD:-auto}" != "user" ]]; then
    warn "TIMEZONE was auto-detected as UTC (likely due to detection failure). If you are not in the UTC timezone, update TIMEZONE in ${ARR_USERCONF_PATH} to match your locale."
  fi

  if [[ "${ARR_INTERNAL_PORT_CONFLICTS:-0}" == "1" ]]; then
    warn "Stack configuration has duplicate host port assignments:"
    if [[ -n "${ARR_INTERNAL_PORT_CONFLICT_DETAIL:-}" ]]; then
      while IFS= read -r conflict_line; do
        [[ -z "$conflict_line" ]] && continue
        warn "  - ${conflict_line}"
      done < <(printf '%s\n' "${ARR_INTERNAL_PORT_CONFLICT_DETAIL}")
    fi
  fi

  if [[ -n "${ARR_PRESERVE_NOTES:-}" ]]; then
    msg "Credential preservation decisions:"
    while IFS= read -r preserve_note; do
      [[ -z "$preserve_note" ]] && continue
      msg "  - ${preserve_note}"
    done < <(printf '%s\n' "${ARR_PRESERVE_NOTES}")
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

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    warn "LAN services are exposed on http://${ip_hint}:PORT (EXPOSE_DIRECT_PORTS=1). Restrict access to trusted networks."
    msg "Service           → URL"
    msg "---------------------------"
    printf '  %-15s → http://%s:%s\n' "qBittorrent" "$ip_hint" "$QBT_PORT"
    printf '  %-15s → http://%s:%s\n' "Sonarr" "$ip_hint" "$SONARR_PORT"
    printf '  %-15s → http://%s:%s\n' "Radarr" "$ip_hint" "$RADARR_PORT"
    printf '  %-15s → http://%s:%s\n' "Prowlarr" "$ip_hint" "$PROWLARR_PORT"
    printf '  %-15s → http://%s:%s\n' "Bazarr" "$ip_hint" "$BAZARR_PORT"
    printf '  %-15s → http://%s:%s\n' "FlareSolverr" "$ip_hint" "$FLARR_PORT"
  else
    msg "Direct LAN URLs are not published (EXPOSE_DIRECT_PORTS=0)."
    msg "Access services from the host network (docker compose exec/port-forward) or add your own reverse proxy."
  fi

  if [[ "${ARR_PORT_CHECKS_SKIPPED:-0}" == "1" ]]; then
    warn "Host port checks were skipped. Verify these bindings manually:"
    if [[ -n "${ARR_PORT_CHECKS_EXPECTED:-}" ]]; then
      while IFS= read -r manual_port; do
        [[ -z "$manual_port" ]] && continue
        warn "  - ${manual_port}"
      done < <(printf '%s\n' "${ARR_PORT_CHECKS_EXPECTED}")
    fi
  fi

  if ((ARR_HOST_RESTARTS_ATTEMPTED > 0)); then
    msg "Host restart recap: attempted ${ARR_HOST_RESTARTS_ATTEMPTED}, succeeded ${ARR_HOST_RESTARTS_SUCCEEDED}."
    if ((ARR_HOST_RESTARTS_ATTEMPTED > ARR_HOST_RESTARTS_SUCCEEDED)); then
      warn "Restart Docker manually to apply resolver configuration changes."
    fi
  fi

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
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
    if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
      cat <<'DNS_HTTP'
Local DNS is enabled. Hostnames will resolve but continue serving plain HTTP until Caddy is enabled.
DNS_HTTP
    fi
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    if [[ "${LOCAL_DNS_STATE:-inactive}" == "active" ]]; then
      msg "Local DNS is enabled. Point DHCP Option 6 (or per-device DNS) at ${LAN_IP:-<unset>} so hostnames resolve."
    else
      warn "Local DNS requested but not active: ${LOCAL_DNS_STATE_REASON:-Local DNS is disabled}. Resolve the issue and rerun."
    fi
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" || -z "${LAN_IP:-}" ]]; then
    cat <<WARNING
⚠️  SECURITY WARNING
   LAN_IP is unset or 0.0.0.0 so services listen on all interfaces.
   Update ${ARR_USERCONF_PATH} with a specific LAN_IP to limit exposure.
   Detect LAN IP with: hostname -I | awk "{print \$1}"

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
        warn "PF not acquired yet${pf_status_message:+ (${pf_status_message})}."
        msg "   Check state file: ${pf_state_file}"
        msg "   Review log:   ${pf_log_file}"
        msg "   Retry with:    arr.vpn.port.sync"
        ;;
      timeout | timeout-soft | failed)
        warn "PF not acquired (${pf_status_value}${pf_status_message:+, ${pf_status_message}})."
        msg "   Attempts: ${pf_attempts}, cycles: ${pf_cycles}"
        msg "   Check state file: ${pf_state_file}"
        msg "   Review log:   ${pf_log_file}"
        msg "   Retry with:    arr.vpn.port.sync (confirm server supports port forwarding)"
        ;;
      *)
        warn "ProtonVPN port forwarding status: ${pf_status_value:-unknown}${pf_status_message:+ (${pf_status_message})}."
        msg "   Check state file: ${pf_state_file}"
        msg "   Review log:   ${pf_log_file}"
        ;;
    esac
  fi

  local vpn_auto_status_file="${ARR_STACK_DIR%/}/.vpn-auto-reconnect-status.json"
  local vpn_auto_state_base="${ARR_DOCKER_DIR:-}"
  if [[ -z "$vpn_auto_state_base" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      vpn_auto_state_base="${ARR_STACK_DIR%/}/docker-data"
    else
      vpn_auto_state_base="${HOME:-.}/srv/docker-data"
    fi
  fi
  local vpn_auto_state_file="${vpn_auto_state_base%/}/gluetun/auto-reconnect/state.json"

  if [[ "${VPN_AUTO_RECONNECT_ENABLED:-0}" == "1" ]]; then
    msg "VPN Auto-Reconnect:"
    local auto_required="${VPN_CONSECUTIVE_CHECKS:-3}"
    [[ "$auto_required" =~ ^[0-9]+$ ]] || auto_required=3
    local auto_status="unknown"
    local auto_detail=""
    local auto_consecutive="0"
    local auto_country=""
    local auto_last_reconnect=""
    local auto_cooldown="0"
    local auto_retry_backoff="0"
    local auto_retry_total="0"
    local auto_next_decision="0"
    local auto_last_low=""
    local auto_classification="monitoring"
    local auto_rotation_count="0"
    local auto_rotation_cap="0"
    local auto_next_possible=""
    local auto_jitter="0"
    if [[ -f "$vpn_auto_status_file" ]]; then
      if command -v jq >/dev/null 2>&1; then
        auto_status="$(jq -r '.status // "unknown"' "$vpn_auto_status_file" 2>/dev/null || printf 'unknown')"
        auto_detail="$(jq -r '.detail // ""' "$vpn_auto_status_file" 2>/dev/null || printf '')"
        auto_consecutive="$(jq -r '.consecutive_low // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_country="$(jq -r '.last_country // ""' "$vpn_auto_status_file" 2>/dev/null || printf '')"
        auto_last_reconnect="$(jq -r '.last_reconnect // ""' "$vpn_auto_status_file" 2>/dev/null || printf '')"
        auto_cooldown="$(jq -r '.cooldown_until // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_retry_backoff="$(jq -r '.retry_backoff // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_retry_total="$(jq -r '.retry_total // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_next_decision="$(jq -r '.next_decision_at // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_last_low="$(jq -r '.last_low // ""' "$vpn_auto_status_file" 2>/dev/null || printf '')"
        auto_classification="$(jq -r '.classification // "monitoring"' "$vpn_auto_status_file" 2>/dev/null || printf 'monitoring')"
        auto_rotation_count="$(jq -r '.rotation_count_day // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_rotation_cap="$(jq -r '.rotation_cap // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
        auto_next_possible="$(jq -r '.next_possible_action // ""' "$vpn_auto_status_file" 2>/dev/null || printf '')"
        auto_jitter="$(jq -r '.jitter_applied // 0' "$vpn_auto_status_file" 2>/dev/null || printf '0')"
      else
        auto_status="$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf 'unknown')"
        auto_detail="$(sed -n 's/.*"detail"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '')"
        auto_consecutive="$(sed -n 's/.*"consecutive_low"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_country="$(sed -n 's/.*"last_country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '')"
        auto_last_reconnect="$(sed -n 's/.*"last_reconnect"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '')"
        auto_cooldown="$(sed -n 's/.*"cooldown_until"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_retry_backoff="$(sed -n 's/.*"retry_backoff"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_retry_total="$(sed -n 's/.*"retry_total"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_next_decision="$(sed -n 's/.*"next_decision_at"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_last_low="$(sed -n 's/.*"last_low"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '')"
        auto_classification="$(sed -n 's/.*"classification"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf 'monitoring')"
        auto_rotation_count="$(sed -n 's/.*"rotation_count_day"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_rotation_cap="$(sed -n 's/.*"rotation_cap"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
        auto_next_possible="$(sed -n 's/.*"next_possible_action"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '')"
        auto_jitter="$(sed -n 's/.*"jitter_applied"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$vpn_auto_status_file" | head -n1 || printf '0')"
      fi
      [[ -n "$auto_status" ]] || auto_status="unknown"
      [[ "$auto_consecutive" =~ ^[0-9]+$ ]] || auto_consecutive=0
      [[ "$auto_retry_backoff" =~ ^[0-9]+$ ]] || auto_retry_backoff=0
      [[ "$auto_retry_total" =~ ^[0-9]+$ ]] || auto_retry_total=0
      [[ "$auto_cooldown" =~ ^[0-9]+$ ]] || auto_cooldown=0
      [[ "$auto_next_decision" =~ ^[0-9]+$ ]] || auto_next_decision=0
      [[ "$auto_rotation_count" =~ ^[0-9]+$ ]] || auto_rotation_count=0
      [[ "$auto_rotation_cap" =~ ^[0-9]+$ ]] || auto_rotation_cap=0
      [[ "$auto_jitter" =~ ^[0-9]+$ ]] || auto_jitter=0
      if [[ "$auto_next_possible" == "null" ]]; then
        auto_next_possible=""
      fi
      local status_line="  Status: ${auto_status}"
      if [[ -n "$auto_detail" ]]; then
        status_line+=" (${auto_detail})"
      fi
      status_line+=" (classification=${auto_classification}; consecutive_low=${auto_consecutive}/${auto_required})"
      msg "$status_line"
      if [[ -n "$auto_last_reconnect" ]]; then
        local reconnect_line="  Last reconnect: ${auto_last_reconnect}"
        if [[ -n "$auto_country" ]]; then
          reconnect_line+=" (country: ${auto_country})"
        fi
        msg "$reconnect_line"
      fi
      if [[ -n "$auto_last_low" ]]; then
        msg "  Last low sample: ${auto_last_low}"
      fi
      local now_epoch
      now_epoch="$(date +%s)"
      if ((auto_cooldown > now_epoch)); then
        msg "  Cooldown until: $(summary_format_epoch "$auto_cooldown")"
      fi
      if ((auto_next_decision > 0)); then
        msg "  Next decision: $(summary_format_epoch "$auto_next_decision")"
      fi
      if [[ -n "$auto_next_possible" ]]; then
        msg "  Next possible action: ${auto_next_possible}"
      fi
      local rotation_line="  Rotation: ${auto_rotation_count}"
      if ((auto_rotation_cap > 0)); then
        rotation_line+="/${auto_rotation_cap} per day"
      else
        rotation_line+=" (uncapped)"
      fi
      msg "$rotation_line"
      msg "  Retry budget: ${auto_retry_total}/${VPN_MAX_RETRY_MINUTES:-20}m (backoff=${auto_retry_backoff}m)"
      if ((auto_jitter > 0)); then
        msg "  Last jitter applied: ${auto_jitter}s"
      fi
    else
      msg "  Status: (no status file yet)"
    fi
    local window_display="none"
    if [[ -n "${VPN_ALLOWED_HOURS_START:-}" && -n "${VPN_ALLOWED_HOURS_END:-}" ]]; then
      local start_fmt end_fmt
      start_fmt=$(printf '%02d' "${VPN_ALLOWED_HOURS_START:-0}" 2>/dev/null || printf '%02d' 0)
      end_fmt=$(printf '%02d' "${VPN_ALLOWED_HOURS_END:-0}" 2>/dev/null || printf '%02d' 0)
      window_display="${start_fmt}–${end_fmt} UTC"
    fi
    msg "  Threshold: ${VPN_SPEED_THRESHOLD_KBPS:-12} KB/s; Interval: ${VPN_CHECK_INTERVAL_MINUTES:-20}m"
    msg "  Allowed window: ${window_display}"
    msg "  Use arr.vpn.auto.status / arr.vpn.auto.history for diagnostics."
  elif [[ -f "$vpn_auto_status_file" || -f "$vpn_auto_state_file" ]]; then
    msg "VPN Auto-Reconnect: disabled (present but disabled)"
  fi

  if [[ "${ARR_PERMISSION_PROFILE}" == "collab" && -n "${COLLAB_PERMISSION_WARNINGS:-}" ]]; then
    warn "Collaborative profile notes:"
    while IFS= read -r collab_warning; do
      [[ -z "$collab_warning" ]] && continue
      warn "  - ${collab_warning}"
    done < <(printf '%s\n' "${COLLAB_PERMISSION_WARNINGS}")
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
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

    if [[ "${API_KEYS_SYNCED_PLACEHOLDERS:-0}" == "1" || "${secrets_have_placeholders}" == "1" ]]; then
      warn "Configarr secrets still contain placeholder API keys. Run ./arrstack.sh --sync-api-keys after Sonarr/Radarr/Prowlarr finish initial setup."
    fi
  fi

  if [[ "${SABNZBD_ENABLED:-0}" == "1" ]]; then
    local sab_helper_path="${ARR_STACK_DIR%/}/scripts/sab-helper.sh"
    if [[ ! -x "$sab_helper_path" ]]; then
      sab_helper_path="${SCRIPT_LIB_DIR}/sab-helper.sh"
    fi
    msg "---- SABnzbd ----"
    local sab_helper_scheme="${SABNZBD_HELPER_SCHEME:-http}"
    local sab_helper_host="${SABNZBD_HOST:-${LOCALHOST_IP:-localhost}}"
    if [[ -z "$sab_helper_host" || "$sab_helper_host" == "0.0.0.0" ]]; then
      sab_helper_host="${LOCALHOST_IP:-localhost}"
    fi
    local sab_host_auto="${ARR_SAB_HOST_AUTO:-0}"
    if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
      msg "VPN Routed: yes"
    else
      msg "VPN Routed: no"
    fi
    if [[ "$sab_host_auto" == "1" ]]; then
      msg "Host: ${sab_helper_host} (auto for VPN mode)"
    else
      msg "Host: ${sab_helper_host}"
      if [[ "${SABNZBD_USE_VPN:-0}" == "1" ]]; then
        local sab_host_lower="${sab_helper_host,,}"
        local sab_default_lower="${LOCALHOST_IP:-localhost}"
        sab_default_lower="${sab_default_lower,,}"
        if [[ "$sab_host_lower" == "$sab_default_lower" || "$sab_host_lower" == "127.0.0.1" || "$sab_host_lower" == "localhost" ]]; then
          warn "SABnzbd is routed through the VPN but SABNZBD_HOST=${sab_helper_host}; set SABNZBD_HOST to sabnzbd or another reachable host."
        fi
      fi
    fi
    if [[ "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
      msg "Host Port: ${SABNZBD_PORT}"
      if [[ "${EXPOSE_DIRECT_PORTS:-0}" != "1" ]]; then
        msg "LAN Exposure: disabled (EXPOSE_DIRECT_PORTS=0)"
      elif [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
        warn "SABnzbd exposed directly on the LAN without Caddy (ENABLE_CADDY=0)."
      fi
    else
      msg "Host Port: (not exposed – VPN mode)"
    fi
    local sab_helper_url="${sab_helper_scheme}://${sab_helper_host}:${SABNZBD_PORT}"
    msg "Helper Endpoint: ${sab_helper_url}"
    if [[ "${ENABLE_CADDY:-0}" == "1" && -n "${ARR_DOMAIN_SUFFIX_CLEAN:-}" ]]; then
      if [[ "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
        local sab_domain="sabnzbd.${ARR_DOMAIN_SUFFIX_CLEAN}"
        msg "Caddy Route: https://${sab_domain}"
      else
        msg "Caddy Route: not published (VPN mode)"
      fi
    fi
    if [[ -n "${SABNZBD_CATEGORY:-}" ]]; then
      msg "Default Category Override: ${SABNZBD_CATEGORY}"
    else
      msg "Default Category Override: (none)"
    fi

    local sab_version_display="(unknown)"
    if [[ -x "$sab_helper_path" ]]; then
      if sab_version_display="$($sab_helper_path version 2>/dev/null)"; then
        if [[ -z "$sab_version_display" ]]; then
          sab_version_display="(unknown)"
        fi
      else
        sab_version_display="(unknown)"
      fi
    else
      sab_version_display="(helper unavailable)"
    fi
    msg "Version: ${sab_version_display}"

    local sab_api_state="${ARR_SAB_API_KEY_STATE:-empty}"
    case "$sab_api_state" in
      set)
        case "${ARR_SAB_API_KEY_SOURCE:-}" in
          hydrated)
            msg "API Key: set (preserved from sabnzbd.ini)"
            ;;
          provided)
            msg "API Key: set (configured via environment)"
            ;;
          *)
            msg "API Key: set"
            ;;
        esac
        ;;
      placeholder)
        warn "SABnzbd API key still placeholder; finish setup in Settings → General."
        ;;
      empty)
        warn "SABnzbd API key not detected; set it in SABnzbd to enable helper uploads."
        ;;
    esac

    if [[ -x "$sab_helper_path" ]]; then
      local sab_status_output=""
      if sab_status_output=$("$sab_helper_path" status 2>/dev/null); then
        while IFS= read -r sab_line; do
          [[ -z "$sab_line" ]] && continue
          msg "$sab_line"
        done <<<"$sab_status_output"
      else
        msg "Status: unavailable"
      fi
    else
      msg "Status: helper missing"
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

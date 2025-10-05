# shellcheck shell=bash

if [[ -n "${SCRIPT_LIB_DIR:-}" && -f "${SCRIPT_LIB_DIR}/network.sh" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=scripts/network.sh
  . "${SCRIPT_LIB_DIR}/network.sh"
fi
# Invokes LAN DNS helper when Caddy/local DNS are enabled and host prerequisites met
configure_local_dns_entries() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🧭 Skipping local DNS host entry helper (ENABLE_CADDY=0)"
    return 0
  fi

  msg "🧭 Ensuring local DNS entries exist for Caddy hostnames"

  local helper_script="${REPO_ROOT}/scripts/setup-lan-dns.sh"

  if [[ "${LOCAL_DNS_STATE:-inactive}" != "active" ]]; then
    msg "  Local DNS container disabled (${LOCAL_DNS_STATE_REASON:-not enabled}); skipping host entries helper"
    return 0
  fi

  if [[ ! -f "$helper_script" ]]; then
    warn "Local DNS helper script ${helper_script} not found"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Local DNS helper script is not executable; fix permissions on ${helper_script}"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" ]]; then
    warn "LAN_IP is unset; skipping local DNS helper"
    return 0
  fi

  if [[ "${LAN_IP}" == "0.0.0.0" ]]; then
    warn "LAN_IP is 0.0.0.0; skipping local DNS helper"
    return 0
  fi

  if ! ip_assigned "${LAN_IP}"; then
    warn "LAN_IP ${LAN_IP} is not assigned on this host; skipping local DNS helper"
    return 0
  fi

  if ! "$helper_script" "$ARR_DOMAIN_SUFFIX_CLEAN" "${LAN_IP}"; then
    local exit_code=$?
    if ((exit_code == 3)); then
      warn "Local DNS helper refused to update hosts because LAN_IP is 0.0.0.0; provide a valid address and rerun."
    else
      warn "Local DNS helper was unable to update host mappings; rerun arrstack.sh with sudo to grant access"
    fi
    return 0
  fi

  msg "✅ Local DNS helper completed"
}

# Executes privileged host DNS takeover helper when explicitly requested
run_host_dns_setup() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "Skipping host DNS setup (--setup-host-dns) because ENABLE_CADDY=0"
    return 0
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" != "1" ]]; then
    msg "Skipping host DNS setup (--setup-host-dns) because ENABLE_LOCAL_DNS=0"
    return 0
  fi

  if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
    warn "Cannot run --setup-host-dns automatically: LAN_IP is ${LAN_IP:-<unset>}"
    warn "Set LAN_IP to a specific address and rerun arrstack.sh --setup-host-dns once available."
    return 0
  fi

  if ! ip_assigned "${LAN_IP}"; then
    warn "Cannot run --setup-host-dns automatically: LAN_IP ${LAN_IP} is not assigned on this host"
    warn "Verify the address with 'ip -4 addr show' or remove LAN_IP to auto-detect."
    return 0
  fi

  local helper_script="${REPO_ROOT}/scripts/host-dns-setup.sh"
  local -a helper_args=("$@")

  if [[ ! -f "$helper_script" ]]; then
    warn "Host DNS helper script not found at ${helper_script}; skipping --setup-host-dns"
    return 0
  fi

  if [[ ! -x "$helper_script" ]]; then
    warn "Host DNS helper script is not executable; fix permissions on ${helper_script} or rerun manually."
    return 0
  fi

  local need_root=0
  if [[ -f "/etc/resolv.conf" && ! -w "/etc/resolv.conf" ]]; then
    need_root=1
  fi

  msg "🔧 Running host DNS setup helper (--setup-host-dns)"

  local -a helper_env=(
    "LAN_IP=${LAN_IP}"
    "LAN_DOMAIN_SUFFIX=${LAN_DOMAIN_SUFFIX}"
    "UPSTREAM_DNS_SERVERS=${UPSTREAM_DNS_SERVERS}"
    "UPSTREAM_DNS_1=${UPSTREAM_DNS_1}"
    "UPSTREAM_DNS_2=${UPSTREAM_DNS_2}"
  )
  if [[ -n "${ARR_STACK_DIR:-}" ]]; then
    helper_env+=("ARR_STACK_DIR=${ARR_STACK_DIR}")
  fi

  if ((need_root)) && [[ "$(id -u)" != "0" ]]; then
    if command -v sudo >/dev/null 2>&1; then
      warn "DNS setup requires root privileges. Re-running with sudo..."
      if sudo env "${helper_env[@]}" "$helper_script" "${helper_args[@]}"; then
        msg "✅ Host DNS setup helper completed"
      else
        warn "Host DNS setup helper reported an error; review the output above or run scripts/host-dns-setup.sh manually."
      fi
      return 0
    fi
    die "DNS setup requires root privileges. Please run as root or install sudo."
  fi

  if env "${helper_env[@]}" "$helper_script" "${helper_args[@]}"; then
    msg "✅ Host DNS setup helper completed"
  else
    warn "Host DNS setup helper reported an error; review the output above or run scripts/host-dns-setup.sh manually."
  fi
}

notify_dns_dependents() {
  DNS_SETTINGS_CHANGED="${DNS_SETTINGS_CHANGED:-0}"

  if [[ "${DNS_SETTINGS_CHANGED}" != "1" ]]; then
    return 0
  fi

  msg "DNS settings changed, restarting dependent services..."
  local -a affected_services=()

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    affected_services+=(caddy)
  fi

  local service
  for service in "${affected_services[@]}"; do
    msg "  Restarting $service..."
    if ! restart_stack_service "$service"; then
      warn "Failed to restart $service"
    fi
  done

  DNS_SETTINGS_CHANGED=0
}

#!/usr/bin/env bash
# shellcheck shell=bash
# VPN backend: wg-quick (host-based WireGuard)
#
# This module provides a unified interface for managing ProtonVPN WireGuard connections
# on the host system using wg-quick. It implements the same function signatures as
# vpn-gluetun.sh to allow backend-agnostic VPN management.
#
# Functions provided:
#   vpn_up              - Bring up VPN connection
#   vpn_down            - Bring down VPN connection
#   vpn_rotate          - Rotate to a different server
#   vpn_get_forwarded_port - Get current ProtonVPN forwarded port
#
# Requirements:
#   - wireguard-tools (wg-quick command)
#   - ProtonVPN WireGuard configs in ${WG_CONFIG_DIR}/*.conf
#   - natpmpc (for NAT-PMP port forwarding)
#   - Running as root or with appropriate sudo permissions
#
# Configuration:
#   WG_CONFIG_DIR     - Directory containing ProtonVPN WireGuard configs (default: /etc/wireguard/proton)
#   WG_INTERFACE      - WireGuard interface name (default: proton0)
#   WG_PORT_FORWARD_STATE - File to store forwarded port (default: /run/protonvpn/forwarded_port)
#
# shellcheck disable=SC2250

if [[ -n "${_ARR_VPN_WG_QUICK_SOURCED:-}" ]]; then
  return 0
fi
_ARR_VPN_WG_QUICK_SOURCED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

# --- Configuration defaults ---
: "${WG_CONFIG_DIR:=/etc/wireguard/proton}"
: "${WG_INTERFACE:=proton0}"
: "${WG_PORT_FORWARD_STATE:=/run/protonvpn/forwarded_port}"
: "${WG_PORT_FORWARD_RETRY_COUNT:=10}"
: "${WG_PORT_FORWARD_RETRY_DELAY:=5}"
: "${WG_PORT_FORWARD_TIMEOUT:=60}"

# --- Internal state ---
__WG_CURRENT_CONFIG=""
__WG_CURRENT_GATEWAY=""

# --- Logging ---
_wg_log() {
  if declare -f msg >/dev/null 2>&1; then
    msg "[wg-quick] $*"
  else
    printf '[wg-quick] %s\n' "$*"
  fi
}

_wg_warn() {
  if declare -f warn >/dev/null 2>&1; then
    warn "[wg-quick] $*"
  else
    printf '[wg-quick] WARNING: %s\n' "$*" >&2
  fi
}

_wg_die() {
  if declare -f die >/dev/null 2>&1; then
    die "[wg-quick] $*"
  else
    printf '[wg-quick] ERROR: %s\n' "$*" >&2
    exit 1
  fi
}

# --- Dependency checks ---
_wg_require_commands() {
  local missing=()
  local cmd

  for cmd in wg wg-quick; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if ((${#missing[@]} > 0)); then
    _wg_die "Missing required commands: ${missing[*]}. Install wireguard-tools package."
  fi
}

_wg_check_permissions() {
  if [[ "${EUID}" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    _wg_die "Root privileges required. Run with sudo or configure passwordless sudo."
  fi
}

_wg_sudo_cmd() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

# --- Config management ---

# List available WireGuard configs
_wg_list_configs() {
  local config_dir="${WG_CONFIG_DIR}"
  
  if [[ ! -d "$config_dir" ]]; then
    return 1
  fi

  find "$config_dir" -maxdepth 1 -type f -name "*.conf" 2>/dev/null | sort
}

# Select a random config from available configs
_wg_select_random_config() {
  local -a configs
  
  mapfile -t configs < <(_wg_list_configs)
  
  if ((${#configs[@]} == 0)); then
    _wg_die "No WireGuard configs found in ${WG_CONFIG_DIR}"
  fi

  local idx=$((RANDOM % ${#configs[@]}))
  printf '%s' "${configs[$idx]}"
}

# Get the gateway IP from a WireGuard config
_wg_extract_gateway() {
  local config_path="$1"
  
  if [[ ! -f "$config_path" ]]; then
    return 1
  fi

  # Extract the Endpoint from the [Peer] section
  local endpoint
  endpoint=$(awk '/^\[Peer\]/,/^\[/ {if ($1 == "Endpoint") {sub(/.*= */, ""); sub(/:.*/, ""); print; exit}}' "$config_path")
  
  if [[ -z "$endpoint" ]]; then
    _wg_warn "Could not extract gateway from $config_path"
    return 1
  fi

  printf '%s' "$endpoint"
}

# --- Port forwarding (ProtonVPN NAT-PMP) ---

# Vendor note: This implementation is based on ProtonVPN's port forwarding protocol
# which uses NAT-PMP. The approach is well-documented in the WireGuard community
# and is used by Gluetun and other VPN clients.
#
# References:
#   - https://github.com/qdm12/gluetun/blob/master/internal/portforward/service/natpmp.go
#   - ProtonVPN port forwarding documentation
#   - NAT-PMP RFC 6886

_wg_init_port_forward_state() {
  local state_file="${WG_PORT_FORWARD_STATE}"
  local state_dir
  state_dir="$(dirname "$state_file")"

  if [[ ! -d "$state_dir" ]]; then
    _wg_sudo_cmd mkdir -p "$state_dir" || {
      _wg_warn "Failed to create port forward state directory: $state_dir"
      return 1
    }
  fi

  # Create empty state file if it doesn't exist
  if [[ ! -f "$state_file" ]]; then
    _wg_sudo_cmd touch "$state_file" || {
      _wg_warn "Failed to create port forward state file: $state_file"
      return 1
    }
  fi

  # Ensure readable by user
  _wg_sudo_cmd chmod 644 "$state_file" 2>/dev/null || true
}

# Request port forwarding from ProtonVPN gateway using NAT-PMP
_wg_request_port_forward() {
  local gateway="$1"
  local state_file="${WG_PORT_FORWARD_STATE}"
  
  if [[ -z "$gateway" ]]; then
    _wg_warn "No gateway specified for port forwarding"
    return 1
  fi

  # Check if natpmpc is available
  if ! command -v natpmpc >/dev/null 2>&1; then
    _wg_warn "natpmpc command not found. Install libnatpmp-utils or natpmpc package."
    _wg_warn "Port forwarding will not be available."
    return 1
  fi

  _wg_log "Requesting port forwarding from gateway $gateway..."

  local attempt=1
  local max_attempts="${WG_PORT_FORWARD_RETRY_COUNT}"
  local delay="${WG_PORT_FORWARD_RETRY_DELAY}"
  local port=""

  while ((attempt <= max_attempts)); do
    _wg_log "Port forward attempt ${attempt}/${max_attempts}..."

    # Request NAT-PMP port mapping
    # -a 1 0: request external port, 0 = dynamic allocation
    # -g: specify gateway
    local output
    if output=$(timeout "${WG_PORT_FORWARD_TIMEOUT}" natpmpc -a 1 0 tcp 60 -g "$gateway" 2>&1); then
      # Parse the output to extract the forwarded port
      # Expected format: "Mapped public port XXXXX protocol TCP to local port ..."
      if [[ "$output" =~ public\ port\ ([0-9]+) ]]; then
        port="${BASH_REMATCH[1]}"
        _wg_log "Successfully obtained forwarded port: $port"
        
        # Write port to state file
        printf '%s\n' "$port" | _wg_sudo_cmd tee "$state_file" >/dev/null
        _wg_sudo_cmd chmod 644 "$state_file" 2>/dev/null || true
        
        return 0
      fi
    fi

    _wg_warn "Port forward attempt ${attempt} failed: $output"
    
    if ((attempt < max_attempts)); then
      sleep "$delay"
    fi
    
    ((attempt++))
  done

  _wg_warn "Failed to obtain forwarded port after ${max_attempts} attempts"
  
  # Clear state file on failure
  printf '' | _wg_sudo_cmd tee "$state_file" >/dev/null
  
  return 1
}

# Start port forwarding refresh daemon
# ProtonVPN port forwards expire after 60 seconds and must be renewed
_wg_start_port_forward_daemon() {
  local gateway="$1"
  local state_file="${WG_PORT_FORWARD_STATE}"
  local refresh_interval=45  # Refresh every 45 seconds (before 60s expiry)

  if [[ -z "$gateway" ]]; then
    _wg_warn "No gateway specified for port forwarding daemon"
    return 1
  fi

  if ! command -v natpmpc >/dev/null 2>&1; then
    _wg_warn "natpmpc not available, skipping port forward daemon"
    return 1
  fi

  # Check if daemon is already running
  local pid_file="/var/run/wg-quick-pf-${WG_INTERFACE}.pid"
  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid=$(cat "$pid_file" 2>/dev/null)
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      _wg_log "Port forward daemon already running (PID: $old_pid)"
      return 0
    fi
  fi

  # Start daemon in background
  _wg_log "Starting port forward refresh daemon..."
  
  (
    # Daemon runs as a background process
    while true; do
      if ! natpmpc -a 1 0 tcp 60 -g "$gateway" >/dev/null 2>&1; then
        # If renewal fails, try to re-request
        if output=$(timeout "${WG_PORT_FORWARD_TIMEOUT}" natpmpc -a 1 0 tcp 60 -g "$gateway" 2>&1); then
          if [[ "$output" =~ public\ port\ ([0-9]+) ]]; then
            port="${BASH_REMATCH[1]}"
            printf '%s\n' "$port" | _wg_sudo_cmd tee "$state_file" >/dev/null 2>&1
            _wg_sudo_cmd chmod 644 "$state_file" 2>/dev/null || true
          fi
        fi
      fi
      sleep "$refresh_interval"
    done
  ) </dev/null >/dev/null 2>&1 &
  
  local daemon_pid=$!
  printf '%s\n' "$daemon_pid" | _wg_sudo_cmd tee "$pid_file" >/dev/null
  
  _wg_log "Port forward daemon started (PID: $daemon_pid)"
}

# Stop port forwarding daemon
_wg_stop_port_forward_daemon() {
  local pid_file="/var/run/wg-quick-pf-${WG_INTERFACE}.pid"
  
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi

  local pid
  pid=$(cat "$pid_file" 2>/dev/null)
  
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    _wg_log "Stopping port forward daemon (PID: $pid)..."
    _wg_sudo_cmd kill "$pid" 2>/dev/null || true
    
    # Wait for process to terminate
    local timeout=5
    while ((timeout > 0)) && kill -0 "$pid" 2>/dev/null; do
      sleep 1
      ((timeout--))
    done
    
    if kill -0 "$pid" 2>/dev/null; then
      _wg_sudo_cmd kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  
  _wg_sudo_cmd rm -f "$pid_file" 2>/dev/null || true
}

# --- Public interface functions ---

# Bring up VPN connection
# Selects a config (either specified or random) and brings up the interface
# shellcheck disable=SC2120
vpn_up() {
  local config_path="${1:-}"
  
  _wg_require_commands
  _wg_check_permissions
  
  # Check if interface is already up
  if _wg_sudo_cmd wg show "$WG_INTERFACE" >/dev/null 2>&1; then
    _wg_log "Interface $WG_INTERFACE is already up"
    
    # Ensure port forwarding is running
    if [[ -n "$__WG_CURRENT_GATEWAY" ]]; then
      _wg_start_port_forward_daemon "$__WG_CURRENT_GATEWAY" || true
    fi
    
    return 0
  fi

  # Select config if not specified
  if [[ -z "$config_path" ]]; then
    config_path=$(_wg_select_random_config)
  fi

  if [[ ! -f "$config_path" ]]; then
    _wg_die "Config file not found: $config_path"
  fi

  local config_name
  config_name="$(basename "$config_path" .conf)"
  
  _wg_log "Bringing up VPN with config: $config_name"

  # Create a temporary config for wg-quick with our interface name
  local temp_config="/tmp/wg-quick-${WG_INTERFACE}.conf"
  _wg_sudo_cmd cp "$config_path" "$temp_config"
  _wg_sudo_cmd chmod 600 "$temp_config"

  # Bring up the interface using wg-quick
  if ! _wg_sudo_cmd wg-quick up "$temp_config"; then
    _wg_sudo_cmd rm -f "$temp_config"
    _wg_die "Failed to bring up interface $WG_INTERFACE"
  fi

  # Rename interface if needed (wg-quick uses filename as interface name)
  local actual_iface
  actual_iface="$(basename "$temp_config" .conf)"
  if [[ "$actual_iface" != "$WG_INTERFACE" ]]; then
    _wg_sudo_cmd ip link set "$actual_iface" down 2>/dev/null || true
    _wg_sudo_cmd ip link set "$actual_iface" name "$WG_INTERFACE" 2>/dev/null || true
    _wg_sudo_cmd ip link set "$WG_INTERFACE" up 2>/dev/null || true
  fi

  _wg_sudo_cmd rm -f "$temp_config"

  # Store current config
  __WG_CURRENT_CONFIG="$config_path"
  
  # Extract gateway for port forwarding
  __WG_CURRENT_GATEWAY=$(_wg_extract_gateway "$config_path")
  
  _wg_log "VPN interface $WG_INTERFACE is up"

  # Initialize port forwarding
  _wg_init_port_forward_state
  
  # Request initial port forward
  if [[ -n "$__WG_CURRENT_GATEWAY" ]]; then
    if _wg_request_port_forward "$__WG_CURRENT_GATEWAY"; then
      # Start daemon to keep port forward alive
      _wg_start_port_forward_daemon "$__WG_CURRENT_GATEWAY" || true
    else
      _wg_warn "Port forwarding setup failed, but VPN is up"
    fi
  else
    _wg_warn "Could not determine gateway, port forwarding unavailable"
  fi

  return 0
}

# Bring down VPN connection
vpn_down() {
  _wg_require_commands
  _wg_check_permissions

  # Stop port forwarding daemon first
  _wg_stop_port_forward_daemon

  # Check if interface exists
  if ! _wg_sudo_cmd wg show "$WG_INTERFACE" >/dev/null 2>&1; then
    _wg_log "Interface $WG_INTERFACE is already down"
    return 0
  fi

  _wg_log "Bringing down VPN interface $WG_INTERFACE"

  # Bring down the interface
  if ! _wg_sudo_cmd wg-quick down "$WG_INTERFACE" 2>/dev/null; then
    # Fallback: manually remove interface
    _wg_sudo_cmd ip link delete "$WG_INTERFACE" 2>/dev/null || true
  fi

  # Clear state
  __WG_CURRENT_CONFIG=""
  __WG_CURRENT_GATEWAY=""
  
  # Clear port forward state
  if [[ -f "${WG_PORT_FORWARD_STATE}" ]]; then
    printf '' | _wg_sudo_cmd tee "${WG_PORT_FORWARD_STATE}" >/dev/null 2>/dev/null || true
  fi

  _wg_log "VPN interface $WG_INTERFACE is down"
  return 0
}

# Rotate to a different server
vpn_rotate() {
  _wg_require_commands
  _wg_check_permissions

  _wg_log "Rotating VPN server..."

  # Bring down current connection
  vpn_down || true

  # Small delay to ensure clean state
  sleep 2

  # Bring up with new random config
  # shellcheck disable=SC2119
  vpn_up

  _wg_log "VPN rotation complete"
  return 0
}

# Get current forwarded port
# Returns the port number on stdout, or empty if unavailable
vpn_get_forwarded_port() {
  local state_file="${WG_PORT_FORWARD_STATE}"
  
  if [[ ! -f "$state_file" ]]; then
    return 1
  fi

  local port
  port=$(tr -d '[:space:]' <"$state_file" 2>/dev/null)
  
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  printf '%s\n' "$port"
  return 0
}

# Check if VPN is up
vpn_is_up() {
  _wg_sudo_cmd wg show "$WG_INTERFACE" >/dev/null 2>&1
}

# Get VPN status information
vpn_status() {
  if ! vpn_is_up; then
    printf 'Status: down\n'
    return 1
  fi

  printf 'Status: up\n'
  printf 'Interface: %s\n' "$WG_INTERFACE"
  
  if [[ -n "$__WG_CURRENT_CONFIG" ]]; then
    printf 'Config: %s\n' "$(basename "$__WG_CURRENT_CONFIG")"
  fi

  local port
  if port=$(vpn_get_forwarded_port 2>/dev/null); then
    printf 'Forwarded port: %s\n' "$port"
  else
    printf 'Forwarded port: none\n'
  fi

  return 0
}

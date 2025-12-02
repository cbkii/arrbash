# shellcheck shell=bash

# Validates dotted-quad IPv4 per RFC ranges (0-255 per octet)
validate_ipv4() {
  local ip="$1"
  local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  [[ "$ip" =~ $regex ]]
}

# Detects RFC1918 IPv4 ranges after format validation
is_private_ipv4() {
  local ip="$1"

  if ! validate_ipv4 "$ip"; then
    return 1
  fi

  local IFS='.'
  read -r oct1 oct2 _ _ <<<"$ip"

  case "$oct1" in
    10)
      return 0
      ;;
    192)
      [[ "$oct2" == "168" ]] && return 0
      ;;
    172)
      if [[ "$oct2" =~ ^[0-9]+$ ]] && [ "$oct2" -ge 16 ] && [ "$oct2" -le 31 ]; then
        return 0
      fi
      ;;
  esac

  return 1
}

# Produces /24 CIDR for provided LAN IP, rejecting non-private inputs
lan_ipv4_subnet_cidr() {
  local ip="$1"

  if [[ -z "$ip" || "$ip" == "0.0.0.0" ]]; then
    return 1
  fi

  if ! is_private_ipv4 "$ip"; then
    return 1
  fi

  local IFS='.'
  read -r oct1 oct2 oct3 _ <<<"$ip"
  printf '%s.%s.%s.0/24' "$oct1" "$oct2" "$oct3"
}

# Produces /24 CIDR for provided LAN IP, rejecting non-private inputs
lan_ipv4_host_cidr() {
  local ip="$1"

  if [[ -z "$ip" || "$ip" == "0.0.0.0" ]]; then
    return 1
  fi

  if ! is_private_ipv4 "$ip"; then
    return 1
  fi

  lan_ipv4_subnet_cidr "$ip"
}

# Attempts to auto-detect host LAN IPv4 using default route heuristics
detect_lan_ip() {
  if ! have_command ip; then
    return 1
  fi

  local -a candidates=()
  local -a private_candidates=()

  local default_iface
  default_iface="$(ip route show default | awk '/default/ {print $5}' | head -n1)"

  if [[ -n "$default_iface" ]]; then
    local ip
    ip="$(ip -4 addr show dev "$default_iface" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)"
    [[ -n "$ip" ]] && candidates+=("$ip")
  fi

  while IFS= read -r ip; do
    [[ "$ip" =~ ^127\. ]] && continue
    candidates+=("$ip")
  done < <(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1)

  local candidate
  for candidate in "${candidates[@]}"; do
    if ! validate_ipv4 "$candidate"; then
      continue
    fi
    if is_private_ipv4 "$candidate"; then
      private_candidates+=("$candidate")
    fi
  done

  if ((${#private_candidates[@]} > 0)); then
    printf '%s' "${private_candidates[0]}"
    return 0
  fi

  for candidate in "${candidates[@]}"; do
    if validate_ipv4 "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  return 1
}

# Checks whether the host currently owns the provided IPv4 address
ip_assigned() {
  local target_ip="$1"
  if ! have_command ip; then
    return 1
  fi
  ip -4 addr show | grep -q "inet ${target_ip}/"
}

# Warns about missing Gluetun prerequisites before stack launch
check_network_requirements() {

  if ! have_command curl; then
    warn "curl not installed; install it so the stack can query the Gluetun control API"
  fi

  if ! have_command jq; then
    warn "jq not installed; helper scripts rely on it when parsing Gluetun responses"
  fi

  msg "Skipping legacy NAT-PMP probe; using Gluetun control API"
}

# Computes normalized qBittorrent WebUI auth whitelist with sensible defaults
# Takes optional existing whitelist as parameter to preserve user settings
# Only includes LAN CIDR when QBT_AUTH_WHITELIST_INCLUDE_LAN is explicitly enabled
# Returns normalized CSV
arr_compute_qbt_auth_whitelist() {
  local existing_whitelist="${1:-}"
  local lan_ip="${LAN_IP:-}"
  local localhost_ip="${LOCALHOST_IP:-127.0.0.1}"
  
  # Start with existing whitelist or sensible defaults
  local auth_whitelist="${existing_whitelist:-${localhost_ip}/32,::1/128}"
  
  # Only add LAN CIDR if explicitly enabled via QBT_AUTH_WHITELIST_INCLUDE_LAN
  if [[ "${QBT_AUTH_WHITELIST_INCLUDE_LAN:-0}" == "1" ]]; then
    local qb_lan_whitelist=""
    if qb_lan_whitelist="$(lan_ipv4_host_cidr "${lan_ip}" 2>/dev/null)" && [[ -n "$qb_lan_whitelist" ]]; then
      # Prepend LAN CIDR if not already present in the whitelist
      if [[ ",${auth_whitelist}," != *",${qb_lan_whitelist},"* ]]; then
        auth_whitelist="${qb_lan_whitelist},${auth_whitelist}"
      fi
    fi
  fi
  
  # Normalize and return
  if declare -f normalize_csv >/dev/null 2>&1; then
    normalize_csv "$auth_whitelist"
  else
    printf '%s' "$auth_whitelist"
  fi
}

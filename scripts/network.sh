# shellcheck shell=bash

validate_ipv4() {
  local ip="$1"
  local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  [[ "$ip" =~ $regex ]]
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

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

ip_assigned() {
  local target_ip="$1"
  if ! have_command ip; then
    return 1
  fi
  ip -4 addr show | grep -q "inet ${target_ip}/"
}

check_network_requirements() {
  msg "🔍 Checking Gluetun control prerequisites"

  if ! have_command curl; then
    warn "curl not installed; install it so the stack can query the Gluetun control API"
  fi

  if ! have_command jq; then
    warn "jq not installed; helper scripts rely on it when parsing Gluetun responses"
  fi

  msg "  Skipping legacy NAT-PMP probe; Gluetun readiness is now verified via /v1/openvpn/status once the container starts"
}

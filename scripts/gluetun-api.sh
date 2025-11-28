#!/usr/bin/env bash
# shellcheck shell=bash
# Library: Helpers for interacting with the Gluetun control API.
# Provides minimal wrappers to check tunnel status and ProtonVPN forwarded ports.
#
# Optimized for Gluetun v3.40+ (specifically tested with v3.40.3)
#
# Gluetun API Endpoint Reference (v3.40+):
#   - /v1/portforward            - Unified port forwarding (PRIMARY - works for both WireGuard and OpenVPN)
#   - /v1/openvpn/portforwarded  - Legacy OpenVPN (deprecated, will be removed in v4.0)
#   - /v1/wireguard/portforwarded - Legacy WireGuard (deprecated, will be removed in v4.0)
#   - /v1/openvpn/status         - OpenVPN tunnel status
#   - /v1/wireguard/status       - WireGuard tunnel status
#   - /v1/publicip/ip            - Public IP through VPN tunnel
#   - /healthcheck               - Container health status
#
# Important v3.40+ changes:
#   - API key authentication is REQUIRED via X-API-Key header
#   - VPN_PORT_FORWARDING_STATUS_FILE is deprecated (use API instead)
#   - /v1/portforward is the recommended unified endpoint
#
# shellcheck disable=SC1091,SC2250

if [[ -n "${_ARR_GLUETUN_API_SOURCED:-}" ]]; then
  return 0
fi
_ARR_GLUETUN_API_SOURCED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=../stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

if ! declare -f die >/dev/null 2>&1; then
  die() {
    printf '%s\n' "$*" >&2
    exit 1
  }
fi

# --- Configuration defaults ---
: "${GLUETUN_CONTROL_URL:=http://127.0.0.1:8000}"
: "${GLUETUN_API_KEY:=}"
: "${GLUETUN_API_TIMEOUT:=10}"
: "${GLUETUN_API_RETRY_COUNT:=3}"
: "${GLUETUN_API_RETRY_DELAY:=2}"
: "${GLUETUN_API_MAX_RETRY_DELAY:=8}"
# VPN_TYPE can be "openvpn" or "wireguard" - used for status endpoint selection
: "${VPN_TYPE:=openvpn}"
# Enable debug logging for API calls
: "${GLUETUN_API_DEBUG:=false}"

# --- Internal helpers ---
_gluetun_api_debug() {
  if [[ "${GLUETUN_API_DEBUG}" == "true" || "${GLUETUN_API_DEBUG}" == "1" ]]; then
    printf '[gluetun-api] DEBUG: %s\n' "$*" >&2
  fi
}

_gluetun_api_requires() {
  if ! command -v curl >/dev/null 2>&1; then
    die "curl is required to query the Gluetun control API"
  fi
  if ! command -v jq >/dev/null 2>&1; then
    die "jq is required to parse Gluetun control API responses"
  fi
}

# Check if API key is configured (required for Gluetun v3.40+)
_gluetun_api_check_auth() {
  if [[ -z "${GLUETUN_API_KEY}" ]]; then
    _gluetun_api_debug "Warning: GLUETUN_API_KEY is not set. Gluetun v3.40+ requires API key authentication."
    return 1
  fi
  return 0
}

# Make an API request with proper authentication and error handling
# Returns: response body on stdout, exit code 0 on success
_gluetun_api_request() {
  _gluetun_api_requires

  local path="$1"
  local url="${GLUETUN_CONTROL_URL%/}${path}"
  local -a args=(
    "curl"
    "-sS"                                        # Silent but show errors
    "--connect-timeout" "${GLUETUN_API_TIMEOUT}"
    "--max-time" "${GLUETUN_API_TIMEOUT}"
    "-w" "\n%{http_code}"                        # Append HTTP status code
    "${url}"
  )

  # API key authentication (required for Gluetun v3.40+)
  if [[ -n "${GLUETUN_API_KEY}" ]]; then
    args+=(-H "X-API-Key: ${GLUETUN_API_KEY}")
  fi

  local attempt=1
  local max_attempts="${GLUETUN_API_RETRY_COUNT}"
  local current_delay="${GLUETUN_API_RETRY_DELAY}"
  local max_delay="${GLUETUN_API_MAX_RETRY_DELAY}"

  while ((attempt <= max_attempts)); do
    _gluetun_api_debug "Request attempt ${attempt}/${max_attempts}: ${path}"
    
    local response=""
    local http_code=""
    local curl_exit=0
    
    response="$("${args[@]}" 2>/dev/null)" || curl_exit=$?
    
    if ((curl_exit == 0)) && [[ -n "$response" ]]; then
      # Extract HTTP status code from last line
      http_code="${response##*$'\n'}"
      response="${response%$'\n'"$http_code"}"
      
      _gluetun_api_debug "Response HTTP ${http_code} for ${path}"
      
      # Check for successful HTTP codes (200-299)
      if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        printf '%s' "$response"
        return 0
      fi
      
      # Handle specific error codes
      case "$http_code" in
        401|403)
          _gluetun_api_debug "Authentication failed for ${path}. Check GLUETUN_API_KEY."
          ;;
        404)
          _gluetun_api_debug "Endpoint not found: ${path}"
          ;;
        500|502|503)
          _gluetun_api_debug "Server error (${http_code}) for ${path}"
          ;;
      esac
    else
      _gluetun_api_debug "curl failed with exit code ${curl_exit} for ${path}"
    fi
    
    if ((attempt < max_attempts)); then
      if declare -f arr_retry >/dev/null 2>&1; then
        arr_retry "Gluetun API request to ${path} failed (attempt ${attempt}/${max_attempts}), retrying in ${current_delay}s..."
      fi
      sleep "${current_delay}"
      
      # Exponential backoff with cap
      current_delay=$((current_delay * 2))
      if ((current_delay > max_delay)); then
        current_delay="${max_delay}"
      fi
    fi
    ((attempt++))
  done

  _gluetun_api_debug "All ${max_attempts} attempts failed for ${path}"
  return 1
}

_gluetun_api_get_json() {
  local path="$1"
  _gluetun_api_request "$path"
}

# Health check using Gluetun's official healthcheck endpoint
# Returns 0 if healthy, 1 if unhealthy or unreachable
gluetun_api_healthcheck() {
  _gluetun_api_debug "Checking Gluetun health via /healthcheck"
  
  # Note: /healthcheck doesn't require API key in most configurations
  local body
  if body="$(_gluetun_api_get_json "/healthcheck" 2>/dev/null)"; then
    _gluetun_api_debug "Healthcheck passed"
    return 0
  fi
  
  _gluetun_api_debug "Healthcheck failed"
  return 1
}

# Returns the VPN tunnel status string ("running", "stopped", etc.).
# Tries the appropriate endpoint based on VPN_TYPE.
# For Gluetun v3.40+, both OpenVPN and WireGuard status endpoints work the same way.
gluetun_api_status() {
  local body
  local status
  local vpn_type_lower
  vpn_type_lower="$(printf '%s' "${VPN_TYPE:-openvpn}" | tr '[:upper:]' '[:lower:]')"
  
  local primary_endpoint="/v1/openvpn/status"
  local fallback_endpoint="/v1/wireguard/status"
  
  if [[ "$vpn_type_lower" == "wireguard" ]]; then
    primary_endpoint="/v1/wireguard/status"
    fallback_endpoint="/v1/openvpn/status"
  fi
  
  _gluetun_api_debug "Fetching VPN status (VPN_TYPE=${vpn_type_lower})"
  
  # Try primary endpoint based on VPN_TYPE
  if body="$(_gluetun_api_get_json "$primary_endpoint" 2>/dev/null)"; then
    _gluetun_api_debug "Response from ${primary_endpoint}: ${body}"
    status="$(printf '%s' "$body" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ -n "$status" && "$status" != "null" ]]; then
      printf '%s' "$status"
      return 0
    fi
  fi
  
  # Fallback to other endpoint
  _gluetun_api_debug "Trying fallback endpoint ${fallback_endpoint}"
  if body="$(_gluetun_api_get_json "$fallback_endpoint" 2>/dev/null)"; then
    _gluetun_api_debug "Response from ${fallback_endpoint}: ${body}"
    status="$(printf '%s' "$body" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ -n "$status" && "$status" != "null" ]]; then
      printf '%s' "$status"
      return 0
    fi
  fi
  
  _gluetun_api_debug "Failed to get VPN status from any endpoint"
  printf 'unknown'
  return 1
}

# Returns the forwarded port as an integer (0 if not available).
# Port is validated to be in valid range (1024-65535 for forwarded ports).
#
# For Gluetun v3.40+, we ONLY use /v1/portforward as it's the unified endpoint.
# Legacy endpoints (/v1/openvpn/portforwarded, /v1/wireguard/portforwarded) are
# deprecated and will be removed in v4.0.
#
# Response formats supported:
#   - {"port": 12345}           - Single port (most common)
#   - {"ports": [12345, 12346]} - Multiple ports (rare, returns first)
#   - {"port": 0}               - Port forwarding not yet negotiated
gluetun_api_forwarded_port() {
  local body
  local port

  _gluetun_api_debug "Fetching forwarded port from /v1/portforward"
  
  # Use the unified /v1/portforward endpoint (recommended for v3.40+)
  if body="$(_gluetun_api_get_json "/v1/portforward" 2>/dev/null)"; then
    _gluetun_api_debug "Response: ${body}"
    
    # Parse port from response - handle both {"port": N} and {"ports": [N]} formats
    port="$(printf '%s' "$body" | jq -r '.port // .ports[0] // 0' 2>/dev/null || printf '0')"
    
    # Validate port is in valid range
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535)); then
      _gluetun_api_debug "Valid forwarded port: ${port}"
      printf '%s' "$port"
      return 0
    elif [[ "$port" == "0" || "$port" == "null" || -z "$port" ]]; then
      _gluetun_api_debug "Port forwarding not yet negotiated (port=0)"
    else
      _gluetun_api_debug "Invalid port value: ${port}"
    fi
  else
    _gluetun_api_debug "Failed to query /v1/portforward endpoint"
  fi

  printf '0'
  return 1
}

# Returns the current public IP address as seen through the VPN
gluetun_api_public_ip() {
  local body
  
  _gluetun_api_debug "Fetching public IP via /v1/publicip/ip"
  
  if ! body="$(_gluetun_api_get_json "/v1/publicip/ip" 2>/dev/null)"; then
    _gluetun_api_debug "Failed to fetch public IP"
    printf ''
    return 1
  fi

  _gluetun_api_debug "Response: ${body}"
  
  local ip
  ip="$(printf '%s' "$body" | jq -r '.public_ip // .ip // empty' 2>/dev/null || true)"
  if [[ -n "$ip" && "$ip" != "null" ]]; then
    _gluetun_api_debug "Public IP: ${ip}"
    printf '%s' "$ip"
    return 0
  fi

  _gluetun_api_debug "No valid IP in response"
  printf ''
  return 1
}

# Wait until Gluetun reports status=running and optionally a forwarded port is present.
# Usage: gluetun_wait_until_ready <timeout_seconds> [require_port]
# Args:
#   timeout_seconds - Maximum time to wait (default: 120)
#   require_port    - If "true", also wait for forwarded port (default: true if VPN_PORT_FORWARDING=on)
# Returns 0 when ready, 1 on timeout.
gluetun_wait_until_ready() {
  local timeout="${1:-120}"
  local require_port="${2:-}"
  local start elapsed
  start="$(date +%s)"
  
  # Auto-detect if port forwarding is expected
  if [[ -z "$require_port" ]]; then
    local pf_setting="${VPN_PORT_FORWARDING:-off}"
    pf_setting="$(printf '%s' "$pf_setting" | tr '[:upper:]' '[:lower:]')"
    if [[ "$pf_setting" == "on" || "$pf_setting" == "true" || "$pf_setting" == "1" ]]; then
      require_port="true"
    else
      require_port="false"
    fi
  fi
  
  _gluetun_api_debug "Waiting for Gluetun ready (timeout=${timeout}s, require_port=${require_port})"

  while true; do
    local status
    status="$(gluetun_api_status 2>/dev/null || printf 'unknown')"
    
    if [[ "$status" == "running" ]]; then
      if [[ "$require_port" == "true" ]]; then
        local port
        port="$(gluetun_api_forwarded_port 2>/dev/null || printf '0')"
        if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
          _gluetun_api_debug "Gluetun ready: status=${status}, port=${port}"
          return 0
        fi
        _gluetun_api_debug "VPN running but port not yet available (port=${port})"
      else
        _gluetun_api_debug "Gluetun ready: status=${status}"
        return 0
      fi
    else
      _gluetun_api_debug "VPN not ready: status=${status}"
    fi

    local now
    now="$(date +%s)"
    elapsed=$((now - start))
    if ((elapsed >= timeout)); then
      _gluetun_api_debug "Timeout after ${elapsed}s waiting for Gluetun"
      return 1
    fi
    sleep 3
  done
}

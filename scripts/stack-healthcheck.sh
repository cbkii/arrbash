#!/usr/bin/env bash
# shellcheck shell=bash
# Health check script for container monitoring and observability
# shellcheck disable=SC1091

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

if [[ -f "${REPO_ROOT}/scripts/gluetun-api.sh" ]]; then
  # shellcheck source=scripts/gluetun-api.sh
  . "${REPO_ROOT}/scripts/gluetun-api.sh"
fi

if [[ -f "${REPO_ROOT}/scripts/qbt-api.sh" ]]; then
  # shellcheck source=scripts/qbt-api.sh
  . "${REPO_ROOT}/scripts/qbt-api.sh"
fi

# Configuration
: "${STACK:=arr}"
: "${HEALTHCHECK_TIMEOUT:=10}"
: "${HEALTHCHECK_OUTPUT_FORMAT:=text}"

if ! declare -f msg >/dev/null 2>&1; then
  msg() {
    printf '[INFO] %s\n' "$*"
  }
fi

if ! declare -f warn >/dev/null 2>&1; then
  warn() {
    printf '[WARN] %s\n' "$*" >&2
  }
fi

_health_status="healthy"
_health_checks_total=0
_health_checks_passed=0
_health_checks_failed=0
_health_details=()

_record_health_check() {
  local service="$1"
  local status="$2"
  local message="$3"
  
  ((_health_checks_total++))
  
  if [[ "$status" == "pass" ]]; then
    ((_health_checks_passed++))
    _health_details+=("${service}|pass|${message}")
  else
    ((_health_checks_failed++))
    _health_details+=("${service}|fail|${message}")
    _health_status="unhealthy"
  fi
}

# Check Docker container health
_check_container_health() {
  local container_name="$1"
  
  if ! command -v docker >/dev/null 2>&1; then
    _record_health_check "$container_name" "fail" "Docker command not available"
    return 1
  fi
  
  local container_status
  container_status=$(docker inspect --format='{{.State.Status}}' "$container_name" 2>/dev/null || echo "not_found")
  
  case "$container_status" in
    running)
      local health_status
      health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "none")
      
      if [[ "$health_status" == "healthy" ]]; then
        _record_health_check "$container_name" "pass" "Container running and healthy"
        return 0
      elif [[ "$health_status" == "none" ]]; then
        _record_health_check "$container_name" "pass" "Container running (no health check defined)"
        return 0
      else
        _record_health_check "$container_name" "fail" "Container running but health status: $health_status"
        return 1
      fi
      ;;
    not_found)
      _record_health_check "$container_name" "fail" "Container not found"
      return 1
      ;;
    *)
      _record_health_check "$container_name" "fail" "Container status: $container_status"
      return 1
      ;;
  esac
}

# Check Gluetun VPN connectivity
_check_gluetun_vpn() {
  local gluetun_status
  gluetun_status=$(gluetun_api_status 2>/dev/null || echo "unknown")
  
  if [[ "$gluetun_status" == "running" ]]; then
    _record_health_check "gluetun-vpn" "pass" "VPN tunnel status: running"
    return 0
  else
    _record_health_check "gluetun-vpn" "fail" "VPN tunnel status: $gluetun_status"
    return 1
  fi
}

# Check Gluetun port forwarding
_check_gluetun_port_forwarding() {
  local forwarded_port
  forwarded_port=$(gluetun_api_forwarded_port 2>/dev/null || echo "0")
  
  if [[ "$forwarded_port" =~ ^[1-9][0-9]*$ ]]; then
    _record_health_check "gluetun-port-forwarding" "pass" "Forwarded port: $forwarded_port"
    return 0
  else
    _record_health_check "gluetun-port-forwarding" "fail" "No forwarded port available"
    return 1
  fi
}

# Check qBittorrent API
_check_qbittorrent_api() {
  if qbt_api_healthcheck 2>/dev/null; then
    _record_health_check "qbittorrent-api" "pass" "API responding"
    return 0
  else
    _record_health_check "qbittorrent-api" "fail" "API not responding"
    return 1
  fi
}

# Check HTTP endpoint
_check_http_endpoint() {
  local service_name="$1"
  local url="$2"
  
  if curl -fsS --connect-timeout 3 --max-time "${HEALTHCHECK_TIMEOUT}" "$url" >/dev/null 2>&1; then
    _record_health_check "$service_name" "pass" "HTTP endpoint accessible"
    return 0
  else
    _record_health_check "$service_name" "fail" "HTTP endpoint not accessible"
    return 1
  fi
}

# Output results in text format
_output_text() {
  echo "=========================================="
  echo "Health Check Report"
  echo "=========================================="
  echo "Overall Status: ${_health_status}"
  echo "Checks: ${_health_checks_passed}/${_health_checks_total} passed"
  echo "=========================================="
  echo
  
  for detail in "${_health_details[@]}"; do
    IFS='|' read -r service status message <<< "$detail"
    local icon="✓"
    if [[ "$status" == "fail" ]]; then
      icon="✗"
    fi
    printf '%s %-30s %s\n' "$icon" "$service" "$message"
  done
  
  echo
  if [[ "$_health_status" == "healthy" ]]; then
    echo "Result: All health checks passed"
    return 0
  else
    echo "Result: Some health checks failed"
    return 1
  fi
}

# Output results in JSON format
_output_json() {
  local timestamp
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')
  
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$timestamp"
  printf '  "status": "%s",\n' "$_health_status"
  printf '  "checks_total": %d,\n' "$_health_checks_total"
  printf '  "checks_passed": %d,\n' "$_health_checks_passed"
  printf '  "checks_failed": %d,\n' "$_health_checks_failed"
  printf '  "details": [\n'
  
  local first=1
  for detail in "${_health_details[@]}"; do
    IFS='|' read -r service status message <<< "$detail"
    
    if ((first == 0)); then
      printf ',\n'
    fi
    first=0
    
    printf '    {\n'
    printf '      "service": "%s",\n' "$service"
    printf '      "status": "%s",\n' "$status"
    printf '      "message": "%s"\n' "$message"
    printf '    }'
  done
  
  printf '\n  ]\n'
  printf '}\n'
  
  if [[ "$_health_status" == "healthy" ]]; then
    return 0
  else
    return 1
  fi
}

# Main health check routine
main() {
  local check_containers=1
  local check_vpn=1
  local check_api=1
  local check_services=1
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --format)
        shift
        HEALTHCHECK_OUTPUT_FORMAT="$1"
        shift
        ;;
      --containers-only)
        check_vpn=0
        check_api=0
        check_services=0
        shift
        ;;
      --vpn-only)
        check_containers=0
        check_api=0
        check_services=0
        shift
        ;;
      --api-only)
        check_containers=0
        check_vpn=0
        check_services=0
        shift
        ;;
      --help|-h)
        cat <<'USAGE'
Usage: stack-healthcheck.sh [OPTIONS]

Performs health checks on containers and services.

Options:
  --format FORMAT         Output format (text or json, default: text)
  --containers-only       Only check container status
  --vpn-only              Only check VPN connectivity
  --api-only              Only check API endpoints
  --help, -h              Show this help message

Exit codes:
  0 - All health checks passed
  1 - One or more health checks failed
USAGE
        return 0
        ;;
      *)
        warn "Unknown option: $1"
        return 1
        ;;
    esac
  done
  
  # Perform health checks
  if ((check_containers)); then
    _check_container_health "${STACK}-gluetun" 2>/dev/null || true
    _check_container_health "${STACK}-qbittorrent" 2>/dev/null || true
    _check_container_health "${STACK}-sonarr" 2>/dev/null || true
    _check_container_health "${STACK}-radarr" 2>/dev/null || true
    _check_container_health "${STACK}-prowlarr" 2>/dev/null || true
  fi
  
  if ((check_vpn)); then
    _check_gluetun_vpn 2>/dev/null || true
    # Only check port forwarding if VPN is configured for it
    if [[ "${VPN_PORT_FORWARDING:-off}" != "off" ]]; then
      _check_gluetun_port_forwarding 2>/dev/null || true
    fi
  fi
  
  if ((check_api)); then
    _check_qbittorrent_api 2>/dev/null || true
  fi
  
  if ((check_services)); then
    # Check web endpoints if configured
    if [[ -n "${LAN_IP:-}" ]]; then
      [[ -n "${QBT_PORT:-}" ]] && _check_http_endpoint "qbittorrent-web" "http://${LAN_IP}:${QBT_PORT}" 2>/dev/null || true
      [[ -n "${SONARR_PORT:-}" ]] && _check_http_endpoint "sonarr-web" "http://${LAN_IP}:${SONARR_PORT}" 2>/dev/null || true
      [[ -n "${RADARR_PORT:-}" ]] && _check_http_endpoint "radarr-web" "http://${LAN_IP}:${RADARR_PORT}" 2>/dev/null || true
    fi
  fi
  
  # Output results
  case "$HEALTHCHECK_OUTPUT_FORMAT" in
    json)
      _output_json
      ;;
    text|*)
      _output_text
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

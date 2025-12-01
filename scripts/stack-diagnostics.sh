#!/usr/bin/env bash
# shellcheck shell=bash
# Startup diagnostics: validates dependencies, configuration, and API connectivity
# shellcheck disable=SC1091

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# Graceful shutdown handling
_diagnostics_cleanup() {
  local rc="${1:-$?}"
  # Cleanup any temporary resources if needed
  return "$rc"
}

_diagnostics_signal_handler() {
  local signal="$1"
  printf '\n[INFO] Received %s signal, cleaning up...\n' "$signal" >&2
  _diagnostics_cleanup 130
  exit 130
}

trap '_diagnostics_signal_handler INT' INT
trap '_diagnostics_signal_handler TERM' TERM
trap '_diagnostics_cleanup' EXIT

if [[ -f "${REPO_ROOT}/scripts/stack-common.sh" ]]; then
  # shellcheck source=scripts/stack-common.sh
  . "${REPO_ROOT}/scripts/stack-common.sh"
fi

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

if ! declare -f die >/dev/null 2>&1; then
  die() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
  }
fi

# Track diagnostics results
_diagnostics_passed=0
_diagnostics_failed=0
_diagnostics_warnings=0

_diag_pass() {
  ((_diagnostics_passed++))
  msg "✓ $*"
}

_diag_fail() {
  ((_diagnostics_failed++))
  warn "✗ $*"
}

_diag_warn() {
  ((_diagnostics_warnings++))
  warn "⚠ $*"
}

# Check if a command exists
_check_command() {
  local cmd="$1"
  local description="${2:-$cmd}"

  if command -v "$cmd" >/dev/null 2>&1; then
    _diag_pass "Command available: $description"
    return 0
  else
    _diag_fail "Missing required command: $description"
    return 1
  fi
}

# Validate port number
_validate_port() {
  local port="$1"
  local name="$2"

  if [[ -z "$port" ]]; then
    _diag_warn "Port not set: $name"
    return 1
  fi

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    _diag_fail "Invalid port format: $name=$port (must be numeric)"
    return 1
  fi

  if ((port < 1 || port > 65535)); then
    _diag_fail "Port out of range: $name=$port (must be 1-65535)"
    return 1
  fi

  _diag_pass "Valid port: $name=$port"
  return 0
}

# Validate directory path
_validate_directory() {
  local path="$1"
  local name="$2"
  local must_exist="${3:-0}"

  if [[ -z "$path" ]]; then
    _diag_warn "Directory path not set: $name"
    return 1
  fi

  if [[ ! "$path" =~ ^/ ]]; then
    _diag_warn "Directory path is not absolute: $name=$path"
  fi

  if ((must_exist)); then
    if [[ -d "$path" ]]; then
      _diag_pass "Directory exists: $name=$path"
      return 0
    else
      _diag_fail "Directory does not exist: $name=$path"
      return 1
    fi
  else
    _diag_pass "Directory path configured: $name=$path"
    return 0
  fi
}

# Validate JSON content
_validate_json() {
  local content="$1"
  local description="$2"

  if ! command -v jq >/dev/null 2>&1; then
    _diag_warn "Cannot validate JSON (jq not available): $description"
    return 1
  fi

  if printf '%s' "$content" | jq empty 2>/dev/null; then
    _diag_pass "Valid JSON: $description"
    return 0
  else
    _diag_fail "Invalid JSON: $description"
    return 1
  fi
}

# Check dependency commands
check_dependencies() {
  msg "Checking system dependencies..."

  _check_command "bash" "Bash shell" || true
  _check_command "docker" "Docker" || true
  _check_command "curl" "curl (HTTP client)" || true
  _check_command "jq" "jq (JSON processor)" || true
  _check_command "openssl" "openssl (cryptography)" || true
  _check_command "git" "git (version control)" || true
  _check_command "python3" "python3 (PBKDF2 password hashing)" || true

  # Check Docker Compose (plugin or standalone)
  if docker compose version >/dev/null 2>&1; then
    _diag_pass "Command available: Docker Compose (plugin)"
  elif command -v docker-compose >/dev/null 2>&1; then
    _diag_pass "Command available: Docker Compose (standalone)"
  else
    _diag_fail "Missing required command: Docker Compose"
  fi
}

# Check configuration variables
check_configuration() {
  msg "Checking configuration variables..."

  # Check ports
  _validate_port "${GLUETUN_CONTROL_PORT:-}" "GLUETUN_CONTROL_PORT" || true
  _validate_port "${QBT_PORT:-}" "QBT_PORT" || true
  _validate_port "${QBT_INT_PORT:-}" "QBT_INT_PORT" || true
  _validate_port "${SONARR_INT_PORT:-}" "SONARR_INT_PORT" || true
  _validate_port "${RADARR_INT_PORT:-}" "RADARR_INT_PORT" || true
  _validate_port "${PROWLARR_INT_PORT:-}" "PROWLARR_INT_PORT" || true

  # Check directories
  _validate_directory "${ARR_DATA_ROOT:-}" "ARR_DATA_ROOT" 0 || true
  _validate_directory "${ARR_DOCKER_DIR:-}" "ARR_DOCKER_DIR" 0 || true
  _validate_directory "${DOWNLOADS_DIR:-}" "DOWNLOADS_DIR" 0 || true
  _validate_directory "${COMPLETED_DIR:-}" "COMPLETED_DIR" 0 || true
  _validate_directory "${MEDIA_DIR:-}" "MEDIA_DIR" 0 || true

  # Check critical variables
  if [[ -z "${STACK:-}" ]]; then
    _diag_warn "STACK variable not set"
  else
    _diag_pass "STACK variable set: ${STACK}"
  fi

  if [[ -z "${LAN_IP:-}" ]]; then
    _diag_warn "LAN_IP not set - services may not be accessible"
  else
    _diag_pass "LAN_IP configured: ${LAN_IP}"
  fi
}

# Check API connectivity
check_api_connectivity() {
  msg "Checking API connectivity..."

  # Check Gluetun API
  if [[ -n "${GLUETUN_CONTROL_URL:-}" || -n "${GLUETUN_CONTROL_PORT:-}" ]]; then
    local gluetun_url="${GLUETUN_CONTROL_URL:-http://127.0.0.1:${GLUETUN_CONTROL_PORT:-8000}}"

    if curl -fsS --connect-timeout 3 --max-time 5 "${gluetun_url}/v1/publicip/ip" >/dev/null 2>&1; then
      _diag_pass "Gluetun API is accessible: ${gluetun_url}"
    else
      _diag_warn "Gluetun API not accessible (may not be running): ${gluetun_url}"
    fi
  else
    _diag_warn "Gluetun API endpoint not configured"
  fi

  # Check qBittorrent API
  if [[ -n "${QBT_HOST:-}" && -n "${QBT_PORT:-}" ]]; then
    local qbt_url="http://${QBT_HOST}:${QBT_PORT}"

    if curl -fsS --connect-timeout 3 --max-time 5 "${qbt_url}/api/v2/app/webapiVersion" >/dev/null 2>&1; then
      _diag_pass "qBittorrent API is accessible: ${qbt_url}"
    else
      _diag_warn "qBittorrent API not accessible (may not be running): ${qbt_url}"
    fi
  else
    _diag_warn "qBittorrent API endpoint not configured"
  fi
}

# Check Docker daemon
check_docker_daemon() {
  msg "Checking Docker daemon..."

  if docker info >/dev/null 2>&1; then
    _diag_pass "Docker daemon is running"
    return 0
  else
    _diag_fail "Docker daemon is not running or not accessible"
    return 1
  fi
}

# Check Docker containers
check_docker_containers() {
  msg "Checking Docker containers..."

  if ! docker info >/dev/null 2>&1; then
    _diag_warn "Skipping container checks (Docker not accessible)"
    return 1
  fi

  local stack_name="${STACK:-arr}"

  # Check if containers exist
  if docker ps -a --filter "name=${stack_name}" --format "{{.Names}}" 2>/dev/null | grep -q .; then
    _diag_pass "Found containers with stack name: ${stack_name}"

    # Check running containers
    local running_count
    running_count=$(docker ps --filter "name=${stack_name}" --format "{{.Names}}" 2>/dev/null | wc -l || echo 0)

    if ((running_count > 0)); then
      _diag_pass "Running containers: ${running_count}"
    else
      _diag_warn "No running containers found for stack: ${stack_name}"
    fi
  else
    _diag_warn "No containers found for stack: ${stack_name} (may not be deployed yet)"
  fi
}

# Print summary
print_summary() {
  echo
  echo "=========================================="
  echo "Diagnostics Summary"
  echo "=========================================="
  echo "✓ Passed:   ${_diagnostics_passed}"
  echo "⚠ Warnings: ${_diagnostics_warnings}"
  echo "✗ Failed:   ${_diagnostics_failed}"
  echo "=========================================="

  if ((_diagnostics_failed > 0)); then
    echo
    warn "Some critical checks failed. Please review the errors above."
    warn "Actionable guidance:"
    warn "- Install missing dependencies with: sudo apt install docker.io curl jq openssl git"
    warn "- Ensure Docker daemon is running: sudo systemctl start docker"
    warn "- Check configuration in .env or userr.conf files"
    warn "- Verify API endpoints are accessible if services are expected to be running"
    return 1
  elif ((_diagnostics_warnings > 0)); then
    echo
    _diag_warn "Some checks produced warnings. Review above for details."
    return 0
  else
    echo
    msg "All diagnostics passed successfully!"
    return 0
  fi
}

# Main diagnostics routine
main() {
  local skip_api=0
  local skip_docker=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-api)
        skip_api=1
        shift
        ;;
      --skip-docker)
        skip_docker=1
        shift
        ;;
      --help | -h)
        cat <<'USAGE'
Usage: stack-diagnostics.sh [OPTIONS]

Validates system dependencies, configuration, and API connectivity.

Options:
  --skip-api      Skip API connectivity checks
  --skip-docker   Skip Docker-related checks
  --help, -h      Show this help message

Exit codes:
  0 - All checks passed (warnings allowed)
  1 - One or more critical checks failed
USAGE
        return 0
        ;;
      *)
        warn "Unknown option: $1"
        return 1
        ;;
    esac
  done

  check_dependencies
  check_configuration

  if ((skip_docker == 0)); then
    check_docker_daemon
    check_docker_containers
  fi

  if ((skip_api == 0)); then
    check_api_connectivity
  fi

  print_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

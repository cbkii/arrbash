# shellcheck shell=bash
# Configuration consolidation and validation
# Provides centralized configuration loading with clear precedence
# Precedence: CLI flags > exported environment > userr.conf > defaults

if [[ -n "${_ARR_CONFIG_CONSOLIDATE_SOURCED:-}" ]]; then
  return 0
fi
_ARR_CONFIG_CONSOLIDATE_SOURCED=1

# Source validation helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/stack-validation.sh" ]]; then
  # shellcheck source=scripts/stack-validation.sh
  . "${SCRIPT_DIR}/stack-validation.sh"
fi

# Load and validate configuration with clear precedence
# Returns: 0 if all validations pass, 1 if any critical validation fails
arr_load_and_validate_config() {
  local validation_errors=0
  
  # Validate critical ports if set
  if [[ -n "${GLUETUN_CONTROL_PORT:-}" ]]; then
    if ! arr_validate_port "$GLUETUN_CONTROL_PORT" "GLUETUN_CONTROL_PORT"; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${QBT_PORT:-}" ]]; then
    if ! arr_validate_port "$QBT_PORT" "QBT_PORT"; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${QBT_INT_PORT:-}" ]]; then
    if ! arr_validate_port "$QBT_INT_PORT" "QBT_INT_PORT"; then
      ((validation_errors++))
    fi
  fi
  
  # Validate IP addresses if set
  if [[ -n "${LAN_IP:-}" ]]; then
    if ! arr_validate_ip "$LAN_IP" "LAN_IP"; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${LOCALHOST_IP:-}" ]]; then
    if ! arr_validate_ip "$LOCALHOST_IP" "LOCALHOST_IP"; then
      ((validation_errors++))
    fi
  fi
  
  # Validate URLs if set
  if [[ -n "${GLUETUN_CONTROL_URL:-}" ]]; then
    if ! arr_validate_url "$GLUETUN_CONTROL_URL" "GLUETUN_CONTROL_URL"; then
      ((validation_errors++))
    fi
  fi
  
  # Validate boolean settings
  if [[ -n "${SPLIT_VPN:-}" ]]; then
    if ! arr_validate_boolean "$SPLIT_VPN" "SPLIT_VPN"; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${EXPOSE_DIRECT_PORTS:-}" ]]; then
    if ! arr_validate_boolean "$EXPOSE_DIRECT_PORTS" "EXPOSE_DIRECT_PORTS"; then
      ((validation_errors++))
    fi
  fi
  
  # Validate retry/timeout settings
  if [[ -n "${GLUETUN_API_RETRY_COUNT:-}" ]]; then
    if ! arr_validate_positive_integer "$GLUETUN_API_RETRY_COUNT" "GLUETUN_API_RETRY_COUNT" 1 10; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${GLUETUN_API_RETRY_DELAY:-}" ]]; then
    if ! arr_validate_positive_integer "$GLUETUN_API_RETRY_DELAY" "GLUETUN_API_RETRY_DELAY" 1 60; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${QBT_API_RETRY_COUNT:-}" ]]; then
    if ! arr_validate_positive_integer "$QBT_API_RETRY_COUNT" "QBT_API_RETRY_COUNT" 1 10; then
      ((validation_errors++))
    fi
  fi
  
  if [[ -n "${QBT_API_RETRY_DELAY:-}" ]]; then
    if ! arr_validate_positive_integer "$QBT_API_RETRY_DELAY" "QBT_API_RETRY_DELAY" 1 60; then
      ((validation_errors++))
    fi
  fi
  
  if ((validation_errors > 0)); then
    if declare -f arr_error >/dev/null 2>&1; then
      arr_error "Configuration validation failed with ${validation_errors} error(s)"
      arr_action "Review the errors above and correct the configuration values"
    fi
    return 1
  fi
  
  if declare -f arr_info >/dev/null 2>&1 && [[ "${ARR_TRACE:-0}" == "1" ]]; then
    arr_info "Configuration validation passed"
  fi
  
  return 0
}

# Print configuration summary showing precedence
arr_print_config_summary() {
  if declare -f arr_info >/dev/null 2>&1; then
    arr_info "=== Configuration Summary ==="
    arr_info "Precedence: CLI flags > environment > userr.conf > defaults"
    arr_info ""
    arr_info "Network Configuration:"
    arr_info "  LAN_IP: ${LAN_IP:-<not set>}"
    arr_info "  SPLIT_VPN: ${SPLIT_VPN:-0}"
    arr_info ""
    arr_info "Gluetun Configuration:"
    arr_info "  GLUETUN_CONTROL_URL: ${GLUETUN_CONTROL_URL:-<default>}"
    arr_info "  GLUETUN_CONTROL_PORT: ${GLUETUN_CONTROL_PORT:-8000}"
    arr_info "  GLUETUN_API_RETRY_COUNT: ${GLUETUN_API_RETRY_COUNT:-3}"
    arr_info "  GLUETUN_API_RETRY_DELAY: ${GLUETUN_API_RETRY_DELAY:-2}"
    arr_info ""
    arr_info "qBittorrent Configuration:"
    arr_info "  QBT_HOST: ${QBT_HOST:-127.0.0.1}"
    arr_info "  QBT_PORT: ${QBT_PORT:-<not set>}"
    arr_info "  QBT_INT_PORT: ${QBT_INT_PORT:-8082}"
    arr_info "  QBT_API_RETRY_COUNT: ${QBT_API_RETRY_COUNT:-3}"
    arr_info "  QBT_API_RETRY_DELAY: ${QBT_API_RETRY_DELAY:-2}"
    arr_info ""
    arr_info "VPN Port Forwarding:"
    arr_info "  VPN_PORT_FORWARDING: ${VPN_PORT_FORWARDING:-off}"
    arr_info "  CONTROLLER_REQUIRE_PF: ${CONTROLLER_REQUIRE_PF:-false}"
    arr_info ""
  else
    printf '=== Configuration Summary ===\n'
    printf 'Precedence: CLI flags > environment > userr.conf > defaults\n'
    printf '\n'
    printf 'Network Configuration:\n'
    printf '  LAN_IP: %s\n' "${LAN_IP:-<not set>}"
    printf '  SPLIT_VPN: %s\n' "${SPLIT_VPN:-0}"
    printf '\n'
  fi
}

# Set default values for retry configuration
arr_set_retry_defaults() {
  : "${GLUETUN_API_RETRY_COUNT:=3}"
  : "${GLUETUN_API_RETRY_DELAY:=2}"
  : "${GLUETUN_API_TIMEOUT:=8}"
  : "${QBT_API_RETRY_COUNT:=3}"
  : "${QBT_API_RETRY_DELAY:=2}"
  : "${QBT_API_TIMEOUT:=10}"
  
  export GLUETUN_API_RETRY_COUNT GLUETUN_API_RETRY_DELAY GLUETUN_API_TIMEOUT
  export QBT_API_RETRY_COUNT QBT_API_RETRY_DELAY QBT_API_TIMEOUT
}

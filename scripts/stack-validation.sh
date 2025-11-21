# shellcheck shell=bash
# Input validation helpers for ports, JSON content, and configuration values
# shellcheck disable=SC2250
#
# NOTE: This library is designed to work standalone without requiring stack-common.sh
# It checks for the new error handling functions (arr_error, arr_warn, etc.) but falls
# back to the legacy warn() function and manual prefixes if not available. This ensures
# compatibility in scripts that haven't sourced stack-common.sh yet.

if [[ -n "${_ARR_VALIDATION_SOURCED:-}" ]]; then
  return 0
fi
_ARR_VALIDATION_SOURCED=1

# Validate port number with detailed error messages
# Usage: arr_validate_port <port> <variable_name>
# Returns: 0 if valid, 1 if invalid
arr_validate_port() {
  local port="$1"
  local var_name="${2:-PORT}"
  
  if [[ -z "$port" ]]; then
    if declare -f arr_error >/dev/null 2>&1; then
      arr_error "${var_name}: Port value is empty or not set"
    else
      printf '[ERROR] %s: Port value is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    if declare -f arr_error >/dev/null 2>&1; then
      arr_error "${var_name}: Port must be a positive integer, got: ${port}"
      arr_action "Please set ${var_name} to a valid port number (1-65535)"
    else
      printf '[ERROR] %s: Port must be a positive integer, got: %s\n' "$var_name" "$port" >&2
      printf '[ACTION] Please set %s to a valid port number (1-65535)\n' "$var_name" >&2
    fi
    return 1
  fi
  
  if ((port < 1 || port > 65535)); then
    if declare -f arr_error >/dev/null 2>&1; then
      arr_error "${var_name}: Port ${port} is out of valid range (1-65535)"
      arr_action "Please set ${var_name} to a port between 1 and 65535"
    else
      printf '[ERROR] %s: Port %s is out of valid range (1-65535)\n' "$var_name" "$port" >&2
      printf '[ACTION] Please set %s to a port between 1 and 65535\n' "$var_name" >&2
    fi
    return 1
  fi
  
  # Check for privileged ports (informational)
  if ((port < 1024)); then
    if declare -f arr_info >/dev/null 2>&1 && [[ "${ARR_TRACE:-0}" == "1" ]]; then
      arr_info "${var_name}: Port ${port} is a privileged port (requires root or CAP_NET_BIND_SERVICE)"
    fi
  fi
  
  return 0
}

# Validate JSON content with detailed error messages
# Usage: arr_validate_json <json_string> <description>
# Returns: 0 if valid, 1 if invalid
arr_validate_json() {
  local json_content="$1"
  local description="${2:-JSON content}"
  
  if [[ -z "$json_content" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${description}: JSON content is empty"
    else
      printf '[ERROR] %s: JSON content is empty\n' "$description" >&2
    fi
    return 1
  fi
  
  if ! command -v jq >/dev/null 2>&1; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[WARN] ${description}: Cannot validate JSON (jq not available)"
    else
      printf '[WARN] %s: Cannot validate JSON (jq not available)\n' "$description" >&2
    fi
    return 0  # Cannot validate without jq, assume valid
  fi
  
  local error_output
  if error_output=$(printf '%s' "$json_content" | jq empty 2>&1); then
    return 0
  else
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${description}: Invalid JSON format"
      warn "[DETAIL] ${error_output}"
      warn "[ACTION] Check JSON syntax and ensure proper escaping of special characters"
    else
      printf '[ERROR] %s: Invalid JSON format\n' "$description" >&2
      printf '[DETAIL] %s\n' "$error_output" >&2
      printf '[ACTION] Check JSON syntax and ensure proper escaping of special characters\n' >&2
    fi
    return 1
  fi
}

# Validate IP address format
# Usage: arr_validate_ip <ip_address> <variable_name>
# Returns: 0 if valid, 1 if invalid
arr_validate_ip() {
  local ip="$1"
  local var_name="${2:-IP}"
  
  if [[ -z "$ip" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: IP address is empty or not set"
    else
      printf '[ERROR] %s: IP address is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  # IPv4 validation
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local -a octets
    IFS='.' read -r -a octets <<< "$ip"
    
    for octet in "${octets[@]}"; do
      if ((octet < 0 || octet > 255)); then
        if declare -f warn >/dev/null 2>&1; then
          warn "[ERROR] ${var_name}: Invalid IPv4 address: ${ip} (octet out of range: ${octet})"
          warn "[ACTION] Each octet must be between 0 and 255"
        else
          printf '[ERROR] %s: Invalid IPv4 address: %s (octet out of range: %s)\n' "$var_name" "$ip" "$octet" >&2
          printf '[ACTION] Each octet must be between 0 and 255\n' >&2
        fi
        return 1
      fi
    done
    return 0
  fi
  
  # IPv6 basic validation (simplified)
  if [[ "$ip" =~ : ]]; then
    # Basic IPv6 check - just ensure it has colons and valid hex characters
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
      return 0
    fi
  fi
  
  if declare -f warn >/dev/null 2>&1; then
    warn "[ERROR] ${var_name}: Invalid IP address format: ${ip}"
    warn "[ACTION] Provide a valid IPv4 (e.g., 192.168.1.100) or IPv6 address"
  else
    printf '[ERROR] %s: Invalid IP address format: %s\n' "$var_name" "$ip" >&2
    printf '[ACTION] Provide a valid IPv4 (e.g., 192.168.1.100) or IPv6 address\n' >&2
  fi
  return 1
}

# Validate URL format
# Usage: arr_validate_url <url> <variable_name>
# Returns: 0 if valid, 1 if invalid
arr_validate_url() {
  local url="$1"
  local var_name="${2:-URL}"
  
  if [[ -z "$url" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: URL is empty or not set"
    else
      printf '[ERROR] %s: URL is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  if [[ ! "$url" =~ ^https?:// ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: URL must start with http:// or https://, got: ${url}"
      warn "[ACTION] Provide a complete URL including protocol"
    else
      printf '[ERROR] %s: URL must start with http:// or https://, got: %s\n' "$var_name" "$url" >&2
      printf '[ACTION] Provide a complete URL including protocol\n' >&2
    fi
    return 1
  fi
  
  return 0
}

# Validate directory path
# Usage: arr_validate_directory <path> <variable_name> [must_exist]
# Returns: 0 if valid, 1 if invalid
arr_validate_directory() {
  local path="$1"
  local var_name="${2:-DIRECTORY}"
  local must_exist="${3:-0}"
  
  if [[ -z "$path" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Directory path is empty or not set"
    else
      printf '[ERROR] %s: Directory path is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  if [[ ! "$path" =~ ^/ ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[WARN] ${var_name}: Directory path is not absolute: ${path}"
      warn "[ACTION] Consider using an absolute path for clarity"
    else
      printf '[WARN] %s: Directory path is not absolute: %s\n' "$var_name" "$path" >&2
      printf '[ACTION] Consider using an absolute path for clarity\n' >&2
    fi
  fi
  
  if [[ "$must_exist" == "1" && ! -d "$path" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Directory does not exist: ${path}"
      warn "[ACTION] Create the directory with: mkdir -p '${path}'"
    else
      printf '[ERROR] %s: Directory does not exist: %s\n' "$var_name" "$path" >&2
      printf '[ACTION] Create the directory with: mkdir -p '\''%s'\''\n' "$path" >&2
    fi
    return 1
  fi
  
  return 0
}

# Validate boolean value
# Usage: arr_validate_boolean <value> <variable_name>
# Returns: 0 if valid, 1 if invalid
arr_validate_boolean() {
  local value="$1"
  local var_name="${2:-BOOLEAN}"
  
  if [[ -z "$value" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Boolean value is empty or not set"
    else
      printf '[ERROR] %s: Boolean value is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  case "$value" in
    0|1|true|false|TRUE|FALSE|yes|no|YES|NO|on|off|ON|OFF)
      return 0
      ;;
    *)
      if declare -f warn >/dev/null 2>&1; then
        warn "[ERROR] ${var_name}: Invalid boolean value: ${value}"
        warn "[ACTION] Use one of: 0, 1, true, false, yes, no, on, off"
      else
        printf '[ERROR] %s: Invalid boolean value: %s\n' "$var_name" "$value" >&2
        printf '[ACTION] Use one of: 0, 1, true, false, yes, no, on, off\n' >&2
      fi
      return 1
      ;;
  esac
}

# Validate positive integer
# Usage: arr_validate_positive_integer <value> <variable_name> [min] [max]
# Returns: 0 if valid, 1 if invalid
arr_validate_positive_integer() {
  local value="$1"
  local var_name="${2:-INTEGER}"
  local min="${3:-1}"
  local max="${4:-}"
  
  if [[ -z "$value" ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Value is empty or not set"
    else
      printf '[ERROR] %s: Value is empty or not set\n' "$var_name" >&2
    fi
    return 1
  fi
  
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Must be a positive integer, got: ${value}"
      warn "[ACTION] Provide a numeric value without decimals or negative signs"
    else
      printf '[ERROR] %s: Must be a positive integer, got: %s\n' "$var_name" "$value" >&2
      printf '[ACTION] Provide a numeric value without decimals or negative signs\n' >&2
    fi
    return 1
  fi
  
  if [[ -n "$min" ]] && ((value < min)); then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Value ${value} is below minimum ${min}"
      warn "[ACTION] Provide a value >= ${min}"
    else
      printf '[ERROR] %s: Value %s is below minimum %s\n' "$var_name" "$value" "$min" >&2
      printf '[ACTION] Provide a value >= %s\n' "$min" >&2
    fi
    return 1
  fi
  
  if [[ -n "$max" ]] && ((value > max)); then
    if declare -f warn >/dev/null 2>&1; then
      warn "[ERROR] ${var_name}: Value ${value} exceeds maximum ${max}"
      warn "[ACTION] Provide a value <= ${max}"
    else
      printf '[ERROR] %s: Value %s exceeds maximum %s\n' "$var_name" "$value" "$max" >&2
      printf '[ACTION] Provide a value <= %s\n' "$max" >&2
    fi
    return 1
  fi
  
  return 0
}

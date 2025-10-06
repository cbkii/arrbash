#!/usr/bin/env bash
# shellcheck shell=bash
# Common helpers for interacting with the Gluetun control server.

: "${PF_MAX_TOTAL_WAIT:=60}"
: "${PF_POLL_INTERVAL:=5}"
: "${PF_CYCLE_AFTER:=30}"
: "${PF_ASYNC_ENABLE:=1}"
: "${PF_ASYNC_INITIAL_QUICK_WAIT:=10}"
: "${PF_ASYNC_TOTAL_BUDGET:=240}"
: "${PF_ASYNC_POLL_INTERVAL:=5}"
: "${PF_ASYNC_CYCLE_INTERVAL:=40}"
: "${PF_ASYNC_MAX_CYCLES:=3}"
: "${PF_ASYNC_STATE_FILE:=pf-state.json}"
: "${PF_ASYNC_LOG_FILE:=port-forwarding.log}"
: "${GLUETUN_PF_STRICT:=0}"
: "${PF_ENABLE_CYCLE:=1}"

# GLUETUN_PF_STRICT
#   0 (default): Port forwarding timeout is soft (status=timeout-soft) and does not
#                cause a non-zero exit for the async worker.
#   1:           Port forwarding timeout reported as hard (status=timeout) and worker
#                exits with non-zero status for external supervisors to detect.
# PF_ENABLE_CYCLE
#   1 (default): Allow automatic OpenVPN cycle attempts while waiting on PF assignment.
#   0:           Skip cycle attempts (useful for advanced diagnostics or to avoid re-connect storms).

# Determines if the current Gluetun image version mandates role-based auth config
gluetun_version_requires_auth_config() {
  local image="${GLUETUN_IMAGE:-}"

  if [[ -z "$image" ]]; then
    return 1
  fi

  local tag="${image##*:}"

  # Extract semantic version components from a variety of tag formats
  if [[ "$tag" =~ ^v?([0-9]+)\.([0-9]+) ]]; then
    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"

    if [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
      if ((major > 3 || (major == 3 && minor >= 40))); then
        return 0
      fi
      return 1
    fi
  fi

  if [[ "$tag" == "latest" || "$tag" == "edge" || "$tag" == "testing" || "$image" == "qmcgaw/gluetun" ]]; then
    return 0
  fi

  # Unknown versions are treated as requiring auth for safety
  return 0
}

# Resolves the Gluetun data directory regardless of stack invocation context
_pf_gluetun_root() {
  if declare -f arr_gluetun_dir >/dev/null 2>&1; then
    arr_gluetun_dir
    return
  fi

  local base="${ARR_DOCKER_DIR:-}"
  if [[ -z "$base" ]]; then
    if [[ -n "${ARR_STACK_DIR:-}" ]]; then
      base="${ARR_STACK_DIR%/}/docker-data"
    else
      base="${ARR_DATA_ROOT%/}/docker-data"
    fi
  fi
  printf '%s/gluetun' "${base%/}"
}

# Returns absolute path to the async port-forward state file
pf_state_path() {
  local state_file="${PF_ASYNC_STATE_FILE:-pf-state.json}"
  printf '%s/%s' "$(_pf_gluetun_root)" "$state_file"
}

# Provides the lockfile path used to serialize state writes
pf_state_lock_file() {
  printf '%s.lock' "$(pf_state_path)"
}

# Computes logfile destination for port-forward worker logging
pf_log_path() {
  local log_file="${PF_ASYNC_LOG_FILE:-port-forwarding.log}"
  printf '%s/%s' "$(_pf_gluetun_root)" "$log_file"
}

# Tracks the async worker PID for lifecycle management
pf_worker_pid_path() {
  printf '%s/%s' "$(_pf_gluetun_root)" "pf-worker.pid"
}

# Ensures parent directory exists with secure permissions before writing worker files
_pf_ensure_parent_dir() {
  local target="$1"
  local dir
  dir="$(dirname -- "$target")"
  if declare -f ensure_data_dir_mode >/dev/null 2>&1; then
    ensure_data_dir_mode "$dir"
  else
    mkdir -p "$dir" 2>/dev/null || true
    chmod 700 "$dir" 2>/dev/null || true
  fi
}

# Escapes text for JSON payloads without requiring jq
_pf_escape_json_string() {
  local value="$1"

  # Escape characters that would break JSON string encoding while staying
  # dependency-free. The explicit quoting keeps shellcheck aware that we're
  # intentionally working with literal backslashes.
  local backspace
  backspace=$(printf '\010')
  local formfeed
  formfeed=$(printf '\014')
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//${backspace}/\\b}"
  value="${value//$'\t'/\\t}"
  value="${value//${formfeed}/\\f}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"

  printf '%s' "$value"
}

# Normalizes numeric inputs to integers (fallback 0) for JSON/state storage
_pf_normalize_int() {
  local value="$1"
  if [[ "$value" =~ ^-?[0-9]+$ ]]; then
    printf '%s' "$value"
  else
    printf '0'
  fi
}

# Appends timestamped log lines to the Gluetun PF log while enforcing permissions
pf_log() {
  local message="$*"
  local timestamp
  timestamp="$(date '+%Y-%m-%dT%H:%M:%S')"
  local formatted="[${timestamp}] [pf] ${message}"
  local log_path
  log_path="$(pf_log_path)"
  _pf_ensure_parent_dir "$log_path"
  printf '%s\n' "$formatted" >>"$log_path" 2>/dev/null || true
  if declare -f ensure_nonsecret_file_mode >/dev/null 2>&1; then
    ensure_nonsecret_file_mode "$log_path"
  elif [[ -n "${NONSECRET_FILE_MODE:-}" ]]; then
    chmod "${NONSECRET_FILE_MODE}" "$log_path" 2>/dev/null || true
  else
    chmod 600 "$log_path" 2>/dev/null || true
  fi
}

# Persists the most recent forwarded port so other tools can read it
pf_store_forwarded_port() {
  local port="$1"
  local sanitized
  sanitized="$(_pf_normalize_int "$port")"
  local path
  path="$(_pf_gluetun_root)/forwarded_port"
  _pf_ensure_parent_dir "$path"
  printf '%s\n' "$sanitized" >"$path" 2>/dev/null || true
  if declare -f ensure_secret_file_mode >/dev/null 2>&1; then
    ensure_secret_file_mode "$path"
  else
    chmod 600 "$path" 2>/dev/null || true
  fi
}

# Serializes port-forward worker state (attempts, status, timestamps) to disk
write_pf_state() {
  local port
  port="$(_pf_normalize_int "${1:-0}")"
  local status="${2:-pending}"
  local attempts
  attempts="$(_pf_normalize_int "${3:-0}")"
  local cycles
  cycles="$(_pf_normalize_int "${4:-0}")"
  local message="${5:-}"
  local last_success_input="${6:-}"
  local last_checked
  last_checked="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local state_file
  state_file="$(pf_state_path)"

  local last_success_json=""
  local invalid_last_success=0
  if [[ -n "$last_success_input" ]]; then
    strict_re='^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$'
    extended_re='^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]([.][0-9][0-9]?[0-9]?[0-9]?[0-9]?[0-9]?)?(Z|[+-][0-9][0-9]:[0-9][0-9])$'
    if [[ $last_success_input =~ $strict_re || $last_success_input =~ $extended_re ]]; then
      last_success_json="$last_success_input"
    else
      invalid_last_success=1
    fi
  fi

  if ((invalid_last_success)) && [[ -z "${PF_INVALID_LAST_SUCCESS_LOGGED:-}" ]]; then
    # Guarded warning ensures we only log once per run when timestamps are invalid.
    pf_log "Ignoring invalid last_success timestamp input"
    PF_INVALID_LAST_SUCCESS_LOGGED=1
  fi

  local json=""
  if command -v jq >/dev/null 2>&1; then
    # _pf_normalize_int guarantees numeric --argjson values remain digit strings.
    json="$(
      jq -nc \
        --argjson port "$port" \
        --arg status "$status" \
        --argjson attempts "$attempts" \
        --argjson cycles "$cycles" \
        --arg message "$message" \
        --arg last_checked "$last_checked" \
        --arg last_success "$last_success_json" \
        '{"port":$port,"status":$status,"attempts":$attempts,"cycles":$cycles,"last_checked":$last_checked,"last_success":($last_success == "" ? null : $last_success),"message":$message}'
    )"
    local jq_status=$?
    if ((jq_status != 0)); then
      json=""
      if [[ -z "${PF_JQ_SERIALIZE_FAILURE_LOGGED:-}" ]]; then
        # Log once so operators can discover jq issues without flooding logs.
        pf_log "Failed to serialize PF state with jq; using fallback encoder"
        PF_JQ_SERIALIZE_FAILURE_LOGGED=1
      fi
    fi
  fi

  if [[ -z "$json" ]]; then
    # Fallback builder avoids complex JSON; intended for simple string/number fields only.
    local escaped_status escaped_message escaped_last_checked escaped_last_success
    escaped_status="$(_pf_escape_json_string "$status")"
    escaped_message="$(_pf_escape_json_string "$message")"
    escaped_last_checked="$(_pf_escape_json_string "$last_checked")"
    if [[ -n "$last_success_json" ]]; then
      escaped_last_success="\"$(_pf_escape_json_string "$last_success_json")\""
    else
      escaped_last_success="null"
    fi
    json=$(printf '{"port":%s,"status":"%s","attempts":%s,"cycles":%s,"last_checked":"%s","last_success":%s,"message":"%s"}' \
      "$port" "$escaped_status" "$attempts" "$cycles" "$escaped_last_checked" "$escaped_last_success" "$escaped_message")
  fi

  _pf_ensure_parent_dir "$state_file"
  printf '%s\n' "$json" >"$state_file" 2>/dev/null || true # ignore failures: non-fatal state persistence
  chmod 600 "$state_file" 2>/dev/null || true              # ignore failures: best-effort permission fix

  if [[ "$port" -gt 0 ]]; then
    PF_ENSURED_PORT="$port"
  else
    PF_ENSURED_PORT="${PF_ENSURED_PORT:-0}"
  fi
  PF_ENSURE_STATUS_MESSAGE="$status${message:+ - ${message}}"
}

# Writes PF state under a simple lock to avoid clobbered concurrent updates
pf_write_with_lock() {
  local lock_file
  lock_file="$(pf_state_lock_file)"
  _pf_ensure_parent_dir "$lock_file"

  local lock_fd
  exec {lock_fd}>"$lock_file"
  flock -x "$lock_fd"

  write_pf_state "$@"

  flock -u "$lock_fd"
  exec {lock_fd}>&-
}

# Fetches forwarded port from Gluetun API while tolerating transient failures
safe_fetch_port() {
  local raw
  raw="$(fetch_forwarded_port 2>/dev/null || printf '0')"
  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    printf '%s' "$raw"
  else
    printf '0'
  fi
}

# Removes worker pid/state artifacts when async worker exits
pf_worker_cleanup() {
  local pid_file="${PF_ASYNC_WORKER_PID_FILE:-}"
  if [[ -n "$pid_file" && -f "$pid_file" ]]; then
    local recorded_pid
    recorded_pid="$(cat "$pid_file" 2>/dev/null || printf '')"
    if [[ "$recorded_pid" == "$$" ]]; then
      rm -f "$pid_file" 2>/dev/null || true
    fi
  fi
}

# Validates async worker timing knobs before use to prevent tight loops
pf_async_validate_intervals() {
  local quick="${PF_ASYNC_INITIAL_QUICK_WAIT:-10}"
  local budget="${PF_ASYNC_TOTAL_BUDGET:-240}"
  local poll="${PF_ASYNC_POLL_INTERVAL:-5}"
  local cycle="${PF_ASYNC_CYCLE_INTERVAL:-40}"
  local cycles="${PF_ASYNC_MAX_CYCLES:-3}"

  [[ "$quick" =~ ^[0-9]+$ ]] || quick=10
  [[ "$budget" =~ ^[0-9]+$ ]] || budget=240
  [[ "$poll" =~ ^[0-9]+$ ]] || poll=5
  [[ "$cycle" =~ ^[0-9]+$ ]] || cycle=40
  [[ "$cycles" =~ ^[0-9]+$ ]] || cycles=3

  ((quick < 0)) && quick=0
  ((budget <= 0)) && budget=1
  ((poll <= 0)) && poll=1
  ((cycle < 0)) && cycle=0

  printf '%s %s %s %s %s' "$quick" "$budget" "$poll" "$cycle" "$cycles"
}

# Long-running worker polling Gluetun for forwarded ports with optional cycling
async_port_forward_worker() {
  local oneshot=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --oneshot)
        oneshot=1
        shift
        ;;
      --help)
        printf 'Usage: async_port_forward_worker [--oneshot]\n'
        return 0
        ;;
      --)
        shift
        break
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ "${VPN_SERVICE_PROVIDER:-}" != "protonvpn" || "${VPN_PORT_FORWARDING:-on}" != "on" ]]; then
    pf_write_with_lock 0 "disabled" 0 0 "Port forwarding disabled for provider ${VPN_SERVICE_PROVIDER:-unknown}" ""
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    pf_log "curl unavailable; cannot manage Proton port forwarding"
    pf_write_with_lock 0 "failed" 0 0 "curl unavailable" ""
    return 1
  fi

  local quick_wait total_budget poll_interval cycle_interval max_cycles
  IFS=' ' read -r quick_wait total_budget poll_interval cycle_interval max_cycles < <(pf_async_validate_intervals)

  if ((oneshot)); then
    pf_log "Running one-shot ProtonVPN port forwarding sync"
    if ((max_cycles > 1)); then
      max_cycles=1
    fi
  fi

  local start_time current_time elapsed=0 attempts=0 cycles=0
  start_time=$(date +%s)
  local last_success=""

  pf_log "Worker started (budget=${total_budget}s quick=${quick_wait}s cycles=${max_cycles})"
  pf_write_with_lock 0 "pending" 0 0 "worker started" "${last_success}"
  pf_store_forwarded_port 0

  local initial_port
  initial_port="$(safe_fetch_port)"
  if [[ "$initial_port" != "0" ]]; then
    last_success="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    pf_log "Detected existing forwarded port ${initial_port}"
    pf_write_with_lock "$initial_port" "acquired" 0 0 "forwarded port already assigned" "$last_success"
    pf_store_forwarded_port "$initial_port"
    return 0
  fi

  trap 'pf_worker_cleanup' EXIT

  local quick_deadline=$((start_time + quick_wait))
  local budget_deadline=$((start_time + total_budget))
  local next_cycle_time=$((start_time + cycle_interval))

  while ((current_time = $(date +%s), current_time <= budget_deadline)); do
    local port
    port="$(safe_fetch_port)"
    attempts=$((attempts + 1))
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    if [[ "$port" != "0" ]]; then
      last_success="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      pf_log "Forwarded port acquired: ${port} (attempts=${attempts} cycles=${cycles} elapsed=${elapsed}s)"
      pf_write_with_lock "$port" "acquired" "$attempts" "$cycles" "forwarded port acquired" "$last_success"
      pf_store_forwarded_port "$port"
      return 0
    fi

    pf_write_with_lock 0 "pending" "$attempts" "$cycles" "waiting for assignment" "$last_success"

    if ((PF_ENABLE_CYCLE == 1)) && ((current_time >= quick_deadline)) && ((cycle_interval > 0)) && ((cycles < max_cycles)) && ((current_time >= next_cycle_time)); then
      cycles=$((cycles + 1))
      pf_log "Cycling OpenVPN (cycle ${cycles}/${max_cycles})"
      if ! gluetun_cycle_openvpn; then
        pf_log "Failed to cycle OpenVPN via control API"
      fi
      pf_write_with_lock 0 "pending" "$attempts" "$cycles" "cycled OpenVPN" "$last_success"
      next_cycle_time=$((current_time + cycle_interval))
    fi

    sleep "$poll_interval"
  done

  local timeout_message="timeout after ${total_budget}s (attempts=${attempts} cycles=${cycles})"
  if ((GLUETUN_PF_STRICT == 1)); then
    pf_log "${timeout_message} (strict)"
    pf_write_with_lock 0 "timeout" "$attempts" "$cycles" "$timeout_message" "$last_success"
    return 1
  fi
  pf_log "${timeout_message} (soft)"
  pf_write_with_lock 0 "timeout-soft" "$attempts" "$cycles" "$timeout_message" "$last_success"
  return 0
}

# Detects whether a previously recorded worker PID is still active
pf_worker_pid_alive() {
  local pid_file
  pid_file="$(pf_worker_pid_path)"
  if [[ ! -f "$pid_file" ]]; then
    return 1
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || printf '')"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    local cmdline=""
    if declare -f read_proc_cmdline >/dev/null 2>&1; then
      cmdline="$(read_proc_cmdline "$pid" 2>/dev/null || true)"
    elif [[ -r "/proc/${pid}/cmdline" ]]; then
      cmdline="$(tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null || true)"
    fi
    if [[ -z "$cmdline" ]] && declare -f read_proc_comm >/dev/null 2>&1; then
      cmdline="$(read_proc_comm "$pid" 2>/dev/null || true)"
    fi
    if [[ "$cmdline" == *"async_port_forward_worker"* ]]; then
      return 0
    fi
  fi
  rm -f "$pid_file" 2>/dev/null || true
  return 1
}

# Launches the async port-forward worker when enabled, ensuring singleton behavior
start_async_pf_if_enabled() {
  local -a worker_args=("$@")
  if [[ "${PF_ASYNC_ENABLE:-1}" != "1" ]]; then
    pf_write_with_lock 0 "disabled" 0 0 "Async worker disabled via PF_ASYNC_ENABLE" ""
    pf_store_forwarded_port 0
    return 0
  fi

  if [[ "${VPN_SERVICE_PROVIDER:-}" != "protonvpn" || "${VPN_PORT_FORWARDING:-on}" != "on" ]]; then
    pf_write_with_lock 0 "disabled" 0 0 "Port forwarding disabled for provider ${VPN_SERVICE_PROVIDER:-unknown}" ""
    pf_store_forwarded_port 0
    return 0
  fi

  if pf_worker_pid_alive; then
    local existing_pid
    existing_pid="$(cat "$(pf_worker_pid_path)" 2>/dev/null || printf '')"
    pf_log "Worker already running (pid ${existing_pid})"
    return 0
  fi

  local pid_file
  pid_file="$(pf_worker_pid_path)"
  _pf_ensure_parent_dir "$pid_file"

  PF_ASYNC_WORKER_PID_FILE="$pid_file" async_port_forward_worker "${worker_args[@]}" &
  local pid=$!
  printf '%s\n' "$pid" >"$pid_file" 2>/dev/null || true
  chmod 600 "$pid_file" 2>/dev/null || true
  pf_log "Worker launched in background (pid ${pid})"
}

# Builds base URL for Gluetun control API from LAN/localhost settings
_gluetun_control_base() {
  local port host
  port="${GLUETUN_CONTROL_PORT:-8000}"
  host="${LOCALHOST_IP:-127.0.0.1}"
  if [[ $host == *:* && $host != [* ]]; then
    printf 'http://[%s]:%s' "$host" "$port"
  else
    printf 'http://%s:%s' "$host" "$port"
  fi
}

# Performs authenticated GET against Gluetun control API with jq-compatible output
gluetun_control_get() {
  local path url
  path="$1"
  url="$(_gluetun_control_base)${path}"

  if ! command -v curl >/dev/null 2>&1; then
    if [[ -z "${GLUETUN_CURL_WARNED:-}" ]]; then
      if declare -f warn >/dev/null 2>&1; then
        warn "[gluetun] curl not available; unable to query control API at ${url}"
      fi
      GLUETUN_CURL_WARNED=1
    fi
    return 1
  fi

  local -a curl_args=(-fsS --max-time 8)
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    curl_args+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
  fi

  curl "${curl_args[@]}" "$url" 2>/dev/null
}

# Extracts a string property from Gluetun JSON response using jq or fallback parser
_gluetun_extract_json_string() {
  local payload="$1"
  local key="$2"
  local value=""

  if command -v jq >/dev/null 2>&1; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi

  if [[ -z "$value" ]]; then
    if [[ "$payload" == *'\\"'* ]]; then
      # Fallback parser cannot safely handle escaped quotes; return empty string.
      value=""
    else
      # sed fallback is a best-effort extraction for flat JSON structures only.
      value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"\\]*\\)\".*/\\1/p" | head -n1)"
    fi
  fi

  printf '%s' "$value"
}

# Extracts numeric property from Gluetun JSON response, handling jq absence
_gluetun_extract_json_number() {
  local payload="$1"
  local key="$2"
  local value=""

  if command -v jq >/dev/null 2>&1; then
    value="$(printf '%s' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null || printf '')"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
  fi

  if [[ -z "$value" ]]; then
    if [[ "$payload" == *'\\"'* ]]; then
      # Fallback parser cannot safely handle escaped quotes; return empty result.
      value=""
    else
      # sed fallback is a best-effort extraction for flat JSON structures only.
      value="$(printf '%s\n' "$payload" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\\1/p" | head -n1)"
    fi
  fi

  printf '%s' "$value"
}

# Returns full JSON payload describing current public IP metadata
gluetun_public_ip_details() {
  local payload="$1"

  GLUETUN_PUBLIC_IP=""
  GLUETUN_PUBLIC_IP_CITY=""
  GLUETUN_PUBLIC_IP_REGION=""
  GLUETUN_PUBLIC_IP_COUNTRY=""
  GLUETUN_PUBLIC_IP_HOSTNAME=""
  GLUETUN_PUBLIC_IP_ORGANIZATION=""
  GLUETUN_PUBLIC_IP_TIMEZONE=""

  if [[ -z "$payload" ]]; then
    return 1
  fi

  GLUETUN_PUBLIC_IP="$(_gluetun_extract_json_string "$payload" "public_ip")"
  GLUETUN_PUBLIC_IP_CITY="$(_gluetun_extract_json_string "$payload" "city")"
  GLUETUN_PUBLIC_IP_REGION="$(_gluetun_extract_json_string "$payload" "region")"
  GLUETUN_PUBLIC_IP_COUNTRY="$(_gluetun_extract_json_string "$payload" "country")"
  GLUETUN_PUBLIC_IP_HOSTNAME="$(_gluetun_extract_json_string "$payload" "hostname")"
  GLUETUN_PUBLIC_IP_ORGANIZATION="$(_gluetun_extract_json_string "$payload" "organization")"
  GLUETUN_PUBLIC_IP_TIMEZONE="$(_gluetun_extract_json_string "$payload" "timezone")"

  [[ -n "$GLUETUN_PUBLIC_IP" ]]
}

# Formats public IP location/country summary for status output
gluetun_public_ip_location() {
  local -a parts=()

  if [[ -n "${GLUETUN_PUBLIC_IP_CITY:-}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_CITY")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_REGION:-}" && "${GLUETUN_PUBLIC_IP_REGION}" != "${GLUETUN_PUBLIC_IP_CITY}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_REGION")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_COUNTRY:-}" ]]; then
    parts+=("$GLUETUN_PUBLIC_IP_COUNTRY")
  fi

  if ((${#parts[@]} == 0)); then
    return 1
  fi

  (
    IFS=', '
    printf '%s' "${parts[*]}"
  )
}

# Combines IP and location data into a concise status string
gluetun_public_ip_summary() {
  local payload="$1"

  if ! gluetun_public_ip_details "$payload"; then
    return 1
  fi

  local summary="$GLUETUN_PUBLIC_IP"
  local location
  location="$(gluetun_public_ip_location 2>/dev/null || printf '')"

  local -a detail_segments=()
  if [[ -n "$location" ]]; then
    detail_segments+=("$location")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_HOSTNAME:-}" ]]; then
    detail_segments+=("host ${GLUETUN_PUBLIC_IP_HOSTNAME}")
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_TIMEZONE:-}" ]]; then
    detail_segments+=("tz ${GLUETUN_PUBLIC_IP_TIMEZONE}")
  fi

  if ((${#detail_segments[@]} > 0)); then
    local details_formatted
    details_formatted=$(
      IFS='; '
      printf '%s' "${detail_segments[*]}"
    )
    summary+=" (${details_formatted})"
  fi

  if [[ -n "${GLUETUN_PUBLIC_IP_ORGANIZATION:-}" ]]; then
    summary+=" via ${GLUETUN_PUBLIC_IP_ORGANIZATION}"
  fi

  printf '%s' "$summary"
}

# Fetches port-forward status payload for downstream summarizers
gluetun_port_forward_details() {
  local payload="$1"

  GLUETUN_PORT_FORWARD_PORT=""
  GLUETUN_PORT_FORWARD_STATUS=""
  GLUETUN_PORT_FORWARD_MESSAGE=""
  GLUETUN_PORT_FORWARD_EXPIRES_AT=""

  if [[ -z "$payload" ]]; then
    return 1
  fi

  local port
  port="$(_gluetun_extract_json_number "$payload" "port")"
  if [[ -z "$port" ]]; then
    port="$(_gluetun_extract_json_number "$payload" "PublicPort")"
  fi
  GLUETUN_PORT_FORWARD_PORT="$port"

  GLUETUN_PORT_FORWARD_STATUS="$(_gluetun_extract_json_string "$payload" "status")"
  if [[ -z "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
    GLUETUN_PORT_FORWARD_STATUS="$(_gluetun_extract_json_string "$payload" "Status")"
  fi

  GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "message")"
  if [[ -z "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "error")"
  fi
  if [[ -z "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    GLUETUN_PORT_FORWARD_MESSAGE="$(_gluetun_extract_json_string "$payload" "error_message")"
  fi

  GLUETUN_PORT_FORWARD_EXPIRES_AT="$(_gluetun_extract_json_string "$payload" "expires_at")"
  if [[ -z "$GLUETUN_PORT_FORWARD_EXPIRES_AT" ]]; then
    GLUETUN_PORT_FORWARD_EXPIRES_AT="$(_gluetun_extract_json_string "$payload" "ExpiresAt")"
  fi

  if [[ -n "$GLUETUN_PORT_FORWARD_PORT" || -n "$GLUETUN_PORT_FORWARD_STATUS" || -n "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
    return 0
  fi

  return 1
}

# Summarizes port-forward status with warnings for placeholder or strict failures
gluetun_port_forward_summary() {
  local payload="$1"

  if ! gluetun_port_forward_details "$payload"; then
    return 1
  fi

  local summary=""

  if [[ -n "$GLUETUN_PORT_FORWARD_PORT" && "$GLUETUN_PORT_FORWARD_PORT" != "0" ]]; then
    summary="$GLUETUN_PORT_FORWARD_PORT"
    local -a extras=()
    if [[ -n "$GLUETUN_PORT_FORWARD_EXPIRES_AT" ]]; then
      extras+=("expires ${GLUETUN_PORT_FORWARD_EXPIRES_AT}")
    fi
    if [[ -n "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
      case "$GLUETUN_PORT_FORWARD_STATUS" in
        '' | ok | OK | active | Active | open | OPEN) ;;
        *)
          extras+=("status ${GLUETUN_PORT_FORWARD_STATUS}")
          ;;
      esac
    fi
    if ((${#extras[@]} > 0)); then
      local extras_str
      extras_str=$(
        IFS='; '
        printf '%s' "${extras[*]}"
      )
      summary+=" (${extras_str})"
    fi
  else
    summary="not available"
    local -a extras=()
    if [[ -n "$GLUETUN_PORT_FORWARD_STATUS" ]]; then
      extras+=("status ${GLUETUN_PORT_FORWARD_STATUS}")
    fi
    if [[ -n "$GLUETUN_PORT_FORWARD_MESSAGE" ]]; then
      extras+=("$GLUETUN_PORT_FORWARD_MESSAGE")
    fi
    if ((${#extras[@]} > 0)); then
      local extras_str
      extras_str=$(
        IFS='; '
        printf '%s' "${extras[*]}"
      )
      summary+=" (${extras_str})"
    fi
  fi

  printf '%s' "$summary"
}

# Retrieves and caches the current forwarded port, updating state side effects
fetch_forwarded_port() {
  local response

  if response=$(gluetun_control_get "/v1/openvpn/portforwarded" 2>/dev/null); then
    if gluetun_port_forward_details "$response" && [[ -n "$GLUETUN_PORT_FORWARD_PORT" ]]; then
      printf '%s' "$GLUETUN_PORT_FORWARD_PORT"
      return 0
    fi
  fi

  printf '0'
}

# Fetches current public IP string (without metadata) from Gluetun API
fetch_public_ip() {
  local response

  if response=$(gluetun_control_get "/v1/publicip/ip" 2>/dev/null); then
    if gluetun_public_ip_details "$response" && [[ -n "$GLUETUN_PUBLIC_IP" ]]; then
      printf '%s' "$GLUETUN_PUBLIC_IP"
      return 0
    fi
  fi

  printf ''
}

# Sends OpenVPN status change requests to Gluetun control API
gluetun_update_openvpn_status() {
  local desired="$1"

  if [[ -z "$desired" ]]; then
    return 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi

  local api_base
  api_base="$(_gluetun_control_base)"

  local -a curl_args=(-fsS --max-time 8 -X PUT -H 'Content-Type: application/json')
  if [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    curl_args+=(-H "X-Api-Key: ${GLUETUN_API_KEY}")
  fi

  curl "${curl_args[@]}" --data "{\"status\":\"${desired}\"}" "${api_base}/v1/openvpn/status" >/dev/null 2>&1
}

# Requests Gluetun to reconnect OpenVPN; used for PF recovery loops
gluetun_cycle_openvpn() {
  if ! gluetun_update_openvpn_status "stopped"; then
    return 1
  fi

  sleep 2

  if ! gluetun_update_openvpn_status "running"; then
    return 1
  fi

  sleep 5

  return 0
}

# DEPRECATED: Legacy Proton PF ensure loop; prefer async_port_forward_worker()
# shellcheck disable=SC2034  # exported for callers to read ensure results
ensure_proton_port_forwarding_ready() {
  PF_ENSURED_PORT="0"
  PF_ENSURE_STATUS_MESSAGE=""

  if [[ "${VPN_SERVICE_PROVIDER:-}" != "protonvpn" ]]; then
    return 0
  fi

  if [[ "${VPN_PORT_FORWARDING:-on}" != "on" ]]; then
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    PF_ENSURE_STATUS_MESSAGE="curl unavailable"
    warn "[pf] curl is required to manage Proton port forwarding; skipping ensure loop"
    return 1
  fi

  local max_wait="${PF_MAX_TOTAL_WAIT:-60}"
  local poll_interval="${PF_POLL_INTERVAL:-5}"
  local cycle_after="${PF_CYCLE_AFTER:-30}"

  if [[ ! "$max_wait" =~ ^[0-9]+$ ]]; then
    max_wait=60
  fi

  if [[ ! "$poll_interval" =~ ^[0-9]+$ ]]; then
    poll_interval=5
  fi

  if [[ ! "$cycle_after" =~ ^[0-9]+$ ]]; then
    cycle_after=30
  fi

  if ((poll_interval <= 0)); then
    poll_interval=1
  fi

  if ((max_wait <= 0)); then
    PF_ENSURE_STATUS_MESSAGE="skipped (PF_MAX_TOTAL_WAIT=0)"
    warn "[pf] Skipping Proton port forwarding wait (PF_MAX_TOTAL_WAIT=0)"
    return 1
  fi

  msg "[pf] Waiting for Proton port forwarding (budget ${max_wait}s)..."

  local start_time
  start_time=$(date +%s)
  local cycled=0

  while :; do
    local port
    port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
    if [[ "$port" =~ ^[0-9]+$ && "$port" != "0" ]]; then
      msg "[pf] Forwarded port acquired: $port"
      PF_ENSURED_PORT="$port"
      PF_ENSURE_STATUS_MESSAGE="acquired port ${port}"
      return 0
    fi

    local now
    now=$(date +%s)
    local elapsed=$((now - start_time))

    if ((elapsed >= max_wait)); then
      PF_ENSURE_STATUS_MESSAGE="timed out after ${elapsed}s"
      PF_ENSURED_PORT="0"
      warn "[pf] Port forwarding not ready after ${elapsed}s"
      return 1
    fi

    if ((cycle_after > 0 && cycled == 0 && elapsed >= cycle_after)); then
      msg "[pf] Cycling OpenVPN once to retry Proton port forwarding..."
      if ! gluetun_cycle_openvpn; then
        warn "[pf] Failed to cycle OpenVPN via Gluetun control API"
      fi
      cycled=1
    fi

    sleep "$poll_interval"
  done
}

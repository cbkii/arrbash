#!/usr/bin/env bash
# shellcheck disable=SC2128,SC2178
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARR_STACK_DIR="${ARR_STACK_DIR:-${REPO_ROOT}}"

# shellcheck source=scripts/stack-common.sh
. "${REPO_ROOT}/scripts/stack-common.sh"
# shellcheck source=scripts/qbt-api.sh
. "${REPO_ROOT}/scripts/qbt-api.sh"

# Prints daemon usage/help text
print_usage() {
  cat <<'USAGE'
Usage: qbt-tracker-updater-daemon.sh [--once]
  --once    Run a single tracker update and exit
USAGE
}

# Loads configuration from userr.conf if available
load_tracker_config() {
  local userconf_path
  userconf_path="$(arr_userconf_path 2>/dev/null || printf '')"
  
  if [[ -f "$userconf_path" ]]; then
    # shellcheck source=/dev/null
    . "$userconf_path" 2>/dev/null || true
  fi
  
  # Set defaults if not already configured
  : "${QBT_TRACKER_UPDATE_ENABLED:=0}"
  : "${QBT_TRACKER_UPDATE_INTERVAL_HOURS:=48}"
  : "${QBT_TRACKER_UPDATE_RETRY_HOURS:=12}"
  : "${QBT_TRACKER_UPDATE_URL:=https://cf.trackerslist.com/all.txt}"
  
  export QBT_TRACKER_UPDATE_ENABLED
  export QBT_TRACKER_UPDATE_INTERVAL_HOURS
  export QBT_TRACKER_UPDATE_RETRY_HOURS
  export QBT_TRACKER_UPDATE_URL
}

# Downloads tracker list from configured URL
download_tracker_list() {
  local url="$1"
  local temp_file="$2"
  
  if ! command -v curl >/dev/null 2>&1; then
    arr_error "curl is required to download tracker lists"
    return 1
  fi
  
  if ! curl -fsSL --max-time 30 --connect-timeout 10 "$url" -o "$temp_file" 2>/dev/null; then
    arr_error "Failed to download tracker list from ${url}"
    return 1
  fi
  
  # Validate we got something
  if [[ ! -s "$temp_file" ]]; then
    arr_error "Downloaded tracker list is empty"
    return 1
  fi
  
  return 0
}

# Cleans and validates tracker list
clean_tracker_list() {
  local input_file="$1"
  local output_file="$2"
  
  # Remove blank lines, trim whitespace, filter for valid tracker URLs
  grep -v '^[[:space:]]*$' "$input_file" 2>/dev/null | \
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
    grep -E '^(http|https|udp|wss?)://' > "$output_file" 2>/dev/null || true
  
  if [[ ! -s "$output_file" ]]; then
    arr_error "No valid trackers found after cleaning"
    return 1
  fi
  
  return 0
}

# Updates qBittorrent tracker list
update_qbt_trackers() {
  local new_trackers="$1"
  
  arr_info "Fetching current tracker list from qBittorrent..."
  local current_trackers
  if ! current_trackers="$(qbt_get_additional_trackers 2>/dev/null)"; then
    arr_error "Failed to get current tracker list from qBittorrent"
    return 1
  fi
  
  # Check if update is needed
  if [[ "$current_trackers" == "$new_trackers" ]]; then
    arr_info "Tracker list is already up to date"
    return 0
  fi
  
  arr_info "Updating qBittorrent tracker list..."
  if ! qbt_set_additional_trackers "$new_trackers"; then
    arr_error "Failed to update qBittorrent tracker list"
    return 1
  fi
  
  arr_info "Successfully updated qBittorrent tracker list"
  return 0
}

# Executes a single tracker update cycle
run_once() {
  load_tracker_config
  
  if [[ "${QBT_TRACKER_UPDATE_ENABLED}" != "1" ]]; then
    arr_info "Tracker updater disabled (QBT_TRACKER_UPDATE_ENABLED=${QBT_TRACKER_UPDATE_ENABLED})"
    return 1
  fi
  
  local url="${QBT_TRACKER_UPDATE_URL}"
  arr_info "Downloading tracker list from ${url}..."
  
  local temp_download temp_clean
  temp_download="$(arr_mktemp_file "tracker-download.XXXXXX" 600)" || {
    arr_error "Failed to create temporary file"
    return 1
  }
  temp_clean="$(arr_mktemp_file "tracker-clean.XXXXXX" 600)" || {
    arr_cleanup_temp_path "$temp_download"
    arr_error "Failed to create temporary file"
    return 1
  }
  
  local result=0
  if ! download_tracker_list "$url" "$temp_download"; then
    result=1
  elif ! clean_tracker_list "$temp_download" "$temp_clean"; then
    result=1
  else
    local tracker_content
    tracker_content="$(cat "$temp_clean")"
    
    if ! update_qbt_trackers "$tracker_content"; then
      result=1
    fi
  fi
  
  arr_cleanup_temp_path "$temp_download"
  arr_cleanup_temp_path "$temp_clean"
  
  return "$result"
}

# Event loop handling CLI flags and periodic execution with retry logic
main() {
  local once=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --once)
        once=1
        shift
        ;;
      --help | -h)
        print_usage
        return 0
        ;;
      *)
        print_usage >&2
        return 1
        ;;
    esac
  done

  if ((once)); then
    run_once
    return $?
  fi

  load_tracker_config
  
  if [[ "${QBT_TRACKER_UPDATE_ENABLED}" != "1" ]]; then
    arr_info "Tracker updater daemon disabled (QBT_TRACKER_UPDATE_ENABLED=${QBT_TRACKER_UPDATE_ENABLED})"
    return 0
  fi

  arr_info "qBittorrent tracker updater daemon starting"
  
  local interval_hours="${QBT_TRACKER_UPDATE_INTERVAL_HOURS}"
  local retry_hours="${QBT_TRACKER_UPDATE_RETRY_HOURS}"
  
  # Validate intervals
  if ! [[ "$interval_hours" =~ ^[0-9]+$ ]] || ((interval_hours <= 0)); then
    arr_warn "Invalid QBT_TRACKER_UPDATE_INTERVAL_HOURS=${interval_hours}, using default 48"
    interval_hours=48
  fi
  if ! [[ "$retry_hours" =~ ^[0-9]+$ ]] || ((retry_hours <= 0)); then
    arr_warn "Invalid QBT_TRACKER_UPDATE_RETRY_HOURS=${retry_hours}, using default 12"
    retry_hours=12
  fi
  
  local interval_seconds=$((interval_hours * 3600))
  local retry_seconds=$((retry_hours * 3600))
  
  arr_info "Update interval: ${interval_hours}h, retry interval: ${retry_hours}h"
  
  local -i loop_count=0
  local -i max_loops=0
  if [[ -n "${QBT_TRACKER_UPDATE_MAX_LOOPS:-}" && "${QBT_TRACKER_UPDATE_MAX_LOOPS}" =~ ^[0-9]+$ ]]; then
    max_loops="${QBT_TRACKER_UPDATE_MAX_LOOPS}"
  fi
  
  while true; do
    if ((max_loops > 0 && loop_count >= max_loops)); then
      arr_info "Tracker updater daemon stopping after ${loop_count} iteration(s)"
      break
    fi
    loop_count+=1
    
    # Reload config on each iteration
    load_tracker_config
    
    if [[ "${QBT_TRACKER_UPDATE_ENABLED}" != "1" ]]; then
      arr_info "Tracker updater disabled during runtime, exiting"
      break
    fi
    
    local next_sleep="$interval_seconds"
    
    if run_once; then
      arr_info "Tracker update successful, sleeping ${interval_hours}h until next update"
      next_sleep="$interval_seconds"
    else
      arr_warn "Tracker update failed, will retry in ${retry_hours}h"
      next_sleep="$retry_seconds"
    fi
    
    # Sleep in small chunks to allow for early termination
    local -i slept=0
    local -i sleep_chunk=60  # Check every minute
    while ((slept < next_sleep)); do
      local -i remaining=$((next_sleep - slept))
      local -i chunk="$sleep_chunk"
      if ((remaining < chunk)); then
        chunk="$remaining"
      fi
      if ((chunk > 0)); then
        sleep "$chunk"
      fi
      slept=$((slept + chunk))
    done
  done
  
  arr_info "qBittorrent tracker updater daemon stopped"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

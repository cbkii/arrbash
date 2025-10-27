# shellcheck shell=bash
# Purpose: Handle manual override flags for the VPN watchdog.
# Inputs: ARR_STACK_DIR, helper functions from stack-common.sh.
# Outputs: Exposes helpers queried by the watchdog loop (pause, kill, wake, force-once).
#
# Historical issue: earlier revisions attempted to track complex qBittorrent activity
# inside this module. The refactor keeps only filesystem-based overrides so the logic
# works in both bash and zsh without relying on unsupported builtins.

if [[ -n "${__VPN_AUTO_SIGNALS_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_SIGNALS_LOADED=1

vpn_auto_override_path() {
  local suffix="$1"
  local base="${ARR_STACK_DIR:-${REPO_ROOT:-$(pwd)}}"
  printf '%s/.vpn-auto-reconnect-%s' "${base%/}" "$suffix"
}

vpn_auto_reconnect_wake_file() {
  vpn_auto_override_path 'wake'
}

vpn_auto_reconnect_wake_requested() {
  local file
  file="$(vpn_auto_reconnect_wake_file)"
  [[ -f "$file" ]]
}

vpn_auto_reconnect_consume_wake() {
  local file
  file="$(vpn_auto_reconnect_wake_file)"
  if [[ -f "$file" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}

vpn_auto_reconnect_manual_pause_active() {
  local file
  file="$(vpn_auto_override_path pause)"
  [[ -f "$file" ]]
}

vpn_auto_reconnect_kill_active() {
  local file
  file="$(vpn_auto_override_path 'kill-24h')"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  local mtime
  mtime="$(stat -c '%Y' "$file" 2>/dev/null || printf '0')"
  if [[ ! "$mtime" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  local now
  now="$(vpn_auto_now_epoch)"
  if ((now - mtime > 86400)); then
    rm -f "$file" 2>/dev/null || true
    return 1
  fi
  return 0
}

vpn_auto_reconnect_force_once_requested() {
  local file
  file="$(vpn_auto_override_path once)"
  [[ -f "$file" ]]
}

vpn_auto_reconnect_consume_force_once_flag() {
  local file
  file="$(vpn_auto_override_path once)"
  if [[ -f "$file" ]]; then
    rm -f "$file" 2>/dev/null || true
  fi
}


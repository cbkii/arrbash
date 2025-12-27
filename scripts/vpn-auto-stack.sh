# shellcheck shell=bash
# Purpose: Aggregate VPN auto-reconnect helpers spanning state management, configuration, signals, metrics, and control.
# Inputs: Expects scripts/stack-common.sh to be sourced first and relies on ARR_* variables populated by the stack.
# Outputs: Exposes vpn_auto_reconnect_process_once and supporting helpers for daemons and installers.
# Exit codes: None directly; sourced modules may exit/die during their operations.

if [[ -n "${__VPN_AUTO_STACK_LOADED:-}" ]]; then
  return 0
fi
__VPN_AUTO_STACK_LOADED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/vpn-auto-state.sh
. "${SCRIPT_DIR}/vpn-auto-state.sh"
# shellcheck source=scripts/vpn-auto-config.sh
. "${SCRIPT_DIR}/vpn-auto-config.sh"

# Load appropriate VPN backend based on VPN_BACKEND setting
: "${VPN_BACKEND:=wg-quick}"

case "${VPN_BACKEND,,}" in
  wg-quick | wireguard)
    # shellcheck source=scripts/vpn-wg-quick.sh
    . "${SCRIPT_DIR}/vpn-wg-quick.sh"
    ;;
  gluetun | docker)
    # shellcheck source=scripts/vpn-gluetun.sh
    . "${SCRIPT_DIR}/vpn-gluetun.sh"
    ;;
  *)
    if declare -f die >/dev/null 2>&1; then
      die "Unknown VPN_BACKEND: ${VPN_BACKEND}. Must be 'wg-quick' or 'gluetun'."
    else
      printf 'ERROR: Unknown VPN_BACKEND: %s. Must be '\''wg-quick'\'' or '\''gluetun'\''.\n' "${VPN_BACKEND}" >&2
      exit 1
    fi
    ;;
esac

# shellcheck shell=bash
# Purpose: Aggregate VPN auto-reconnect helpers spanning state management, configuration, and Gluetun integration.
# Inputs: Expects scripts/stack-common.sh to be sourced first and relies on ARR_* variables populated by the stack.
# Outputs: Exposes vpn_auto_reconnect_process_once and supporting helpers for daemons and installers through sourced modules.
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
# shellcheck source=scripts/vpn-gluetun.sh
. "${SCRIPT_DIR}/vpn-gluetun.sh"

# shellcheck shell=bash
# Purpose: Aggregate service lifecycle helpers spanning VueTorrent, runtime state, validation, and stack startup.
# Inputs: Relies on ARR_* configuration variables and expects scripts/common.sh to be sourced first.
# Outputs: Provides install_vuetorrent, validate_generated_paths, start_stack, and supporting helpers.
# Exit codes: None directly; sourced modules may exit or die during their own operations.

if [[ -n "${__SERVICE_STACK_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_STACK_LOADED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/service-vuetorrent.sh
. "${SCRIPT_DIR}/service-vuetorrent.sh"
# shellcheck source=scripts/service-runtime.sh
. "${SCRIPT_DIR}/service-runtime.sh"
# shellcheck source=scripts/service-validate.sh
. "${SCRIPT_DIR}/service-validate.sh"
# shellcheck source=scripts/service-lifecycle.sh
. "${SCRIPT_DIR}/service-lifecycle.sh"

# shellcheck shell=bash
# Purpose: Aggregate compose-related helpers spanning environment prep, directory setup, and asset generation.
# Inputs: Relies on ARR_* configuration variables and expects scripts/stack-common.sh to be sourced beforehand.
# Outputs: Exposes functions like generate_api_key, prepare_env_context, write_compose, and write_qbt_config.
# Exit codes: None directly; sourced modules may die or return non-zero during their own operations.

if [[ -n "${__COMPOSE_STACK_LOADED:-}" ]]; then
  return 0
fi
__COMPOSE_STACK_LOADED=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/stack-secrets.sh
. "${SCRIPT_DIR}/stack-secrets.sh"
# shellcheck source=scripts/env-runtime.sh
. "${SCRIPT_DIR}/env-runtime.sh"
# shellcheck source=scripts/stack-setup-directories.sh
. "${SCRIPT_DIR}/stack-setup-directories.sh"
# shellcheck source=scripts/stack-compose-runtime.sh
. "${SCRIPT_DIR}/stack-compose-runtime.sh"
# shellcheck source=scripts/gen-config-assets.sh
. "${SCRIPT_DIR}/gen-config-assets.sh"

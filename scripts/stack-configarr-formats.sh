# shellcheck shell=bash
# shellcheck disable=SC2034
# Purpose: Provide ConfigArr custom format IDs with optional overrides from user configuration.
# This helper is intended to be sourced by scripts that need to reference ConfigArr custom format IDs.

if [[ -n "${__CONFIGARR_CUSTOM_FORMAT_IDS_SH:-}" ]]; then
  return 0
fi
__CONFIGARR_CUSTOM_FORMAT_IDS_SH=1

# Defaults sourced from https://trash-guides.info/ for convenience.
declare -ar CONFIGARR_CF_IDS_LQ_DEFAULT=(
  "9c11cd3f07101cdba90a2d81cf0e56b4"
  "90a6f9a284dff5103f6346090e6280c8"
)

declare -ar CONFIGARR_CF_IDS_LQ_TITLE_DEFAULT=(
  "e2315f990da2e2cbfc9fa5b7a6fcfe48"
  "e204b80c87be9497a8a6eaff48f72905"
)

declare -ar CONFIGARR_CF_IDS_UPSCALED_DEFAULT=(
  "23297a736ca77c0fc8e70f8edd7ee56c"
  "bfd8eb01832d646a0a89c4deb46f8564"
)

declare -ar CONFIGARR_CF_IDS_LANGUAGE_DEFAULT=(
  "69aa1e159f97d860440b04cd6d590c4f"
  "0dc8aec3bd1c47cd6c40c46ecd27e846"
)

declare -ar CONFIGARR_CF_IDS_MULTI_DEFAULT=(
  "7ba05c6e0e14e793538174c679126996"
  "4b900e171accbfb172729b63323ea8ca"
)

declare -ar CONFIGARR_CF_IDS_X265_DEFAULT=(
  "47435ece6b99a0b477caf360e79ba0bb"
  "dc98083864ea246d05a42df0d05f81cc"
)

_configarr_cf_ids_resolve() {
  local override_var="$1"
  local default_name="$2"
  local target_name="$3"

  local -n target_ref="$target_name"
  local -n default_ref="$default_name"

  if declare -p "$override_var" >/dev/null 2>&1; then
    local declaration
    declaration="$(declare -p "$override_var" 2>/dev/null || printf '')"
    case "$declaration" in
      declare\ -a*)
        local -n override_ref="$override_var"
        target_ref=("${override_ref[@]}")
        return 0
        ;;
    esac
  fi

  local override_value="${!override_var-}"
  if [[ -n "${override_value:-}" ]]; then
    read -r -a target_ref <<<"$override_value"
    return 0
  fi

  target_ref=("${default_ref[@]}")
}

configarr_load_custom_format_ids() {
  local lq_var="${1:-CF_IDS_LQ}"
  local lq_title_var="${2:-CF_IDS_LQ_TITLE}"
  local upscaled_var="${3:-CF_IDS_UPSCALED}"
  local language_var="${4:-CF_IDS_LANGUAGE}"
  local multi_var="${5:-CF_IDS_MULTI}"
  local x265_var="${6:-CF_IDS_X265}"

  _configarr_cf_ids_resolve "ARR_CF_IDS_LQ" "CONFIGARR_CF_IDS_LQ_DEFAULT" "$lq_var"
  _configarr_cf_ids_resolve "ARR_CF_IDS_LQ_TITLE" "CONFIGARR_CF_IDS_LQ_TITLE_DEFAULT" "$lq_title_var"
  _configarr_cf_ids_resolve "ARR_CF_IDS_UPSCALED" "CONFIGARR_CF_IDS_UPSCALED_DEFAULT" "$upscaled_var"
  _configarr_cf_ids_resolve "ARR_CF_IDS_LANGUAGE" "CONFIGARR_CF_IDS_LANGUAGE_DEFAULT" "$language_var"
  _configarr_cf_ids_resolve "ARR_CF_IDS_MULTI" "CONFIGARR_CF_IDS_MULTI_DEFAULT" "$multi_var"
  _configarr_cf_ids_resolve "ARR_CF_IDS_X265" "CONFIGARR_CF_IDS_X265_DEFAULT" "$x265_var"
}

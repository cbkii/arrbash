# shellcheck shell=bash

# Return a canonical representation of a path while tolerating missing targets.
# Prefers realpath -e, falls back to readlink -f, and echoes the raw input when
# canonicalisation utilities are unavailable or fail.
arr_canonical_path() {
  local path="$1"

  if command -v realpath >/dev/null 2>&1; then
    if realpath -e -- "${path}" 2>/dev/null; then
      return 0
    fi
  fi

  if command -v readlink >/dev/null 2>&1; then
    if readlink -f -- "${path}" 2>/dev/null; then
      return 0
    fi
  fi

  printf '%s\n' "${path}"
}

# Returns the default user configuration path derived from ARRCONF_DIR, falling
# back to ARR_DATA_ROOT when the config directory is unset.
arr_default_userconf_path() {
  local conf_dir="${ARRCONF_DIR:-${ARR_DATA_ROOT:-}}"

  if [[ -z "${conf_dir:-}" ]]; then
    return 1
  fi

  conf_dir="${conf_dir%/}"
  printf '%s/userr.conf\n' "$conf_dir"
}

# Locate the first userr.conf override under ARR_DATA_ROOT (depth 4) and fall
# back to the repo parent tree, excluding the repository itself when REPO_ROOT
# is known. Returns the canonical absolute path on success.
arr_find_userconf_override() {
  local target="userr.conf"
  local repo_root="${REPO_ROOT:-}"
  local parent=""
  local first=""

  if [[ -n "${ARR_DATA_ROOT:-}" ]]; then
    local search_root=""
    if search_root="$(cd -- "${ARR_DATA_ROOT}" 2>/dev/null && pwd -P)"; then
      first="$(find -L "${search_root}" -maxdepth 4 -type f -name "${target}" -print -quit 2>/dev/null)" || true
      if [[ -n "${first}" ]]; then
        arr_canonical_path "${first}"
        return 0
      fi
    fi
  fi

  if [[ -n "${repo_root}" ]]; then
    repo_root="$(cd -- "${repo_root}" 2>/dev/null && pwd -P)" || repo_root=""
  fi

  if [[ -n "${repo_root}" ]]; then
    parent="$(cd -- "${repo_root}/.." 2>/dev/null && pwd -P)" || parent=""
  else
    parent="$(cd -- ".." 2>/dev/null && pwd -P)" || parent=""
  fi

  [[ -d "${parent}" ]] || return 1

  if [[ -n "${repo_root}" ]]; then
    first="$(find -L "${parent}" -maxdepth 4 -path "${repo_root}" -prune -o -type f -name "${target}" -print -quit 2>/dev/null)" || true
  else
    first="$(find -L "${parent}" -maxdepth 4 -type f -name "${target}" -print -quit 2>/dev/null)" || true
  fi

  [[ -n "${first}" ]] || return 1

  arr_canonical_path "${first}"
}

# Resolve the effective userr.conf path, preferring an explicit ARR_USERCONF_PATH
# when set, otherwise falling back to the first sibling override and finally the
# default under ARRCONF_DIR (falls back to ARR_DATA_ROOT when unset). Sets the provided variable
# names to the canonical path, discovered override, and source label.
arr_resolve_userconf_paths() {
  local __path_var="$1"
  local __override_var="${2-}"
  local __source_var="${3-}"

  local candidate="${ARR_USERCONF_PATH:-}"
  local source="default"
  local override=""

  if [[ -n "${candidate}" ]]; then
    source="explicit"
  else
    if override="$(arr_find_userconf_override 2>/dev/null || true)" && [[ -n "${override}" ]]; then
      candidate="${override}"
      source="override"
    else
      if ! candidate="$(arr_default_userconf_path 2>/dev/null)"; then
        candidate="userr.conf"
      fi
      source="default"
      override=""
    fi
  fi

  local canon_candidate
  canon_candidate="$(arr_canonical_path "${candidate}")"

  if [[ "${source}" == "override" ]]; then
    override="${canon_candidate}"
  else
    override=""
  fi

  printf -v "${__path_var}" '%s' "${canon_candidate}"

  if [[ -n "${__override_var}" ]]; then
    printf -v "${__override_var}" '%s' "${override}"
  fi

  if [[ -n "${__source_var}" ]]; then
    printf -v "${__source_var}" '%s' "${source}"
  fi
}

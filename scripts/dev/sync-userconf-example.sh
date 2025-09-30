#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT="${REPO_ROOT}/arrconf/userr.conf.example"
MODE="write"

if [[ ${1:-} == "--check" ]]; then
  MODE="check"
fi

# shellcheck disable=SC1091
# shellcheck source=../../arrconf/userr.conf.defaults.sh
. "${REPO_ROOT}/arrconf/userr.conf.defaults.sh"

COMMON_LIB="${REPO_ROOT}/scripts/common.sh"
if [[ -f "$COMMON_LIB" ]]; then
  # shellcheck disable=SC1091
  # shellcheck source=../../scripts/common.sh
  . "$COMMON_LIB"
else
  echo "scripts/common.sh is required for temporary file helpers" >&2
  exit 4
fi

if ! command -v envsubst >/dev/null 2>&1; then
  echo "envsubst is required to render ${OUTPUT}. Install gettext." >&2
  exit 2
fi

if ! declare -f arrstack_render_userconf_template >/dev/null 2>&1; then
  echo "arrstack_render_userconf_template is missing from arrconf/userr.conf.defaults.sh" >&2
  exit 3
fi

arrstack_export_userconf_template_vars
spec="$(arrstack_userconf_envsubst_spec)"

render() {
  arrstack_render_userconf_template | envsubst "$spec"
}

if [[ "$MODE" == "check" ]]; then
  if ! tmp="$(arrstack_mktemp_file "${OUTPUT##*/}.XXXXXX" 600)"; then
    echo "Failed to create temporary file while checking ${OUTPUT}" >&2
    exit 4
  fi
  trap 'rm -f "$tmp"' EXIT
  render >"$tmp"
  if ! cmp -s "$tmp" "$OUTPUT"; then
    echo "${OUTPUT#"${REPO_ROOT}"/} is out of sync with arrconf/userr.conf.defaults.sh. Run scripts/dev/sync-userconf-example.sh." >&2
    diff -u "$OUTPUT" "$tmp" || true
    exit 3
  fi
  rm -f "$tmp"
  trap - EXIT
else
  render >"$OUTPUT"
  chmod 644 "$OUTPUT" 2>/dev/null || true
fi

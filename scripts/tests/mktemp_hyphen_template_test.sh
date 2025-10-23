#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

# Simulate top-level installer trap environment so mktemp helpers avoid
# registering subshell-specific cleanup handlers that would immediately
# delete the generated paths.
ARR_MAIN_TRAP_INSTALLED=1

workdir="$(mktemp -d "${TMPDIR:-/tmp}/arrbash-mktemp-test.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

(
  cd "$workdir"

  file_path="$(arr_mktemp_file "-leading-file.XXXXXX")"
  [[ "$file_path" == /* ]]
  [[ -f "$file_path" ]]
  arr_cleanup_temp_path "$file_path"
  [[ ! -e "$file_path" ]]

  dir_path="$(arr_mktemp_dir "-leading-dir.XXXXXX")"
  [[ "$dir_path" == /* ]]
  [[ -d "$dir_path" ]]
  arr_cleanup_temp_path "$dir_path"
  [[ ! -d "$dir_path" ]]
)

echo "mktemp_hyphen_template_test: ok"

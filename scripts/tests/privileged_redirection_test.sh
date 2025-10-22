#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=scripts/common.sh
. "${REPO_ROOT}/scripts/common.sh"

tmp="$(arr_mktemp_file "/tmp/demo.env.XXXXXX")"
arr_run_sensitive_command sh -c 'printf bar >"$1"' sh "$tmp"
if ! grep -q '^bar$' "$tmp"; then
  arr_cleanup_temp_path "$tmp"
  echo "expected bar in temp file" >&2
  exit 1
fi
arr_cleanup_temp_path "$tmp"
echo "privileged_redirection_test: ok"

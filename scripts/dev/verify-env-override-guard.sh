#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat <<'USERR' > "${TMP_DIR}/userr.conf"
#!/usr/bin/env bash
ENABLE_CADDY=0
USERR

export ARRSTACK_NO_MAIN=1
export ARR_BASE="${TMP_DIR}"
export ARR_USERCONF_PATH="${TMP_DIR}/userr.conf"
export ENABLE_CADDY=1

# shellcheck source=../../arrstack.sh disable=SC1091
. "${REPO_ROOT}/arrstack.sh"

if [[ "${ENABLE_CADDY:-}" != "1" ]]; then
  printf 'Environment override lost; expected ENABLE_CADDY=1 but found %s\n' "${ENABLE_CADDY:-<unset>}" >&2
  exit 1
fi

printf 'Environment override preserved: ENABLE_CADDY=%s\n' "${ENABLE_CADDY}"

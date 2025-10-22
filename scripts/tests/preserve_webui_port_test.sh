#!/usr/bin/env bash
set -euo pipefail

single_match="$(printf 'WebUI\\Port=1234\n' | grep -E '^WebUI(\\|\\\\)Port=' | cut -d= -f2)"
[[ "${single_match}" == "1234" ]]

double_match="$(printf 'WebUI\\\\Port=5678\n' | grep -E '^WebUI(\\|\\\\)Port=' | cut -d= -f2)"
[[ "${double_match}" == "5678" ]]

echo "preserve_webui_port_test: ok"

# shellcheck shell=bash
# Purpose: Provide secret management helpers for credential generation and hashing.
# Inputs: Uses CADDY_IMAGE, ARR_ENV_FILE, ARR_DOCKER_DIR, FORCE_ROTATE_API_KEY, GLUETUN_API_KEY.
# Outputs: Prints hashed credentials and updates GLUETUN_API_KEY variable in-place.
# Exit codes: Functions return non-zero when prerequisites are missing or invalid.
if [[ -n "${__CONFIG_SECRETS_LOADED:-}" ]]; then
  return 0
fi
__CONFIG_SECRETS_LOADED=1

# Generates a bcrypt hash for Caddy credentials, preferring local openssl before docker fallback
caddy_bcrypt() {
  local plaintext="${1-}"

  if [[ -z "$plaintext" ]]; then
    return 1
  fi

  local hash_output=""

  if command -v openssl >/dev/null 2>&1; then
    hash_output="$(
      printf '%s\n' "$plaintext" \
        | openssl passwd -bcrypt -stdin 2>/dev/null
    )" || true

    if [[ -n "$hash_output" ]]; then
      printf '%s\n' "$hash_output"
      return 0
    fi
  fi

  local -a docker_hash_cmd=(
    docker run --rm
    --cpus=1
    --memory=256m
    --network=none
    "${CADDY_IMAGE}"
    caddy hash-password
    --algorithm bcrypt
    --plaintext
    "$plaintext"
  )

  local docker_hash_output=""
  if command -v timeout >/dev/null 2>&1; then
    docker_hash_output="$(timeout --preserve-status 10 "${docker_hash_cmd[@]}" 2>/dev/null || true)"
  else
    docker_hash_output="$("${docker_hash_cmd[@]}" 2>/dev/null || true)"
  fi

  if [[ -n "$docker_hash_output" ]]; then
    printf '%s\n' "$docker_hash_output"
    return 0
  fi

  return 1
}

# Produces an alphanumeric token using the strongest available entropy source
safe_random_alnum() {
  local len="${1:-64}"
  if [[ ! "$len" =~ ^[0-9]+$ || "$len" -le 0 ]]; then
    len=64
  fi
  local output=""
  local chunk=""
  local need=0
  while ((${#output} < len)); do
    need=$((len - ${#output}))
    if command -v openssl >/dev/null 2>&1; then
      chunk="$(openssl rand -base64 $((need * 2)) 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$need")"
    elif [[ -r /dev/urandom ]]; then
      chunk="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$need")"
    else
      chunk="$(printf '%s' "$RANDOM$RANDOM$RANDOM" | tr -dc 'A-Za-z0-9' | head -c "$need")"
    fi
    if [[ -z "$chunk" ]]; then
      continue
    fi
    output+="$chunk"
  done
  printf '%s\n' "${output:0:len}"
}

# Ensures GLUETUN_API_KEY exists, rotating auth config when forced or missing
generate_api_key() {
  step "🔐 Generating API key"

  if [[ -f "$ARR_ENV_FILE" ]] && [[ "$FORCE_ROTATE_API_KEY" != "1" ]]; then
    local existing
    existing="$(get_env_kv "GLUETUN_API_KEY" "$ARR_ENV_FILE" || true)"
    if [[ -n "$existing" ]]; then
      GLUETUN_API_KEY="$existing"
      export GLUETUN_API_KEY
      msg "Using existing API key"
      return
    fi
  fi

  GLUETUN_API_KEY="$(safe_random_alnum 64)"
  export GLUETUN_API_KEY
  msg "Generated new API key"

  if gluetun_version_requires_auth_config 2>/dev/null; then
    local auth_config="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
    if [[ -f "$auth_config" ]]; then
      rm -f "$auth_config"
      msg "Removed existing auth config for key rotation"
    fi
  fi
}

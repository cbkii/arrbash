# shellcheck shell=bash
# Purpose: Generate runtime asset files for services (Gluetun, Caddy, qBittorrent, Configarr, helpers).
# Inputs: Requires ARR_DOCKER_DIR, STACK, service toggles (ENABLE_CADDY, SABNZBD_ENABLED), and credential variables.
# Outputs: Writes scripts/config assets on disk and updates environment variables when regenerating credentials.
# Exit codes: Functions return non-zero when file writes fail or validations detect invalid configurations.
if [[ -n "${__CONFIG_ASSETS_LOADED:-}" ]]; then
  return 0
fi
__CONFIG_ASSETS_LOADED=1

write_gluetun_control_assets() {
  msg "[pf] Preparing Gluetun control assets"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"
  local hooks_dir="${gluetun_root}/hooks"

  ensure_data_dir_mode "$gluetun_root"
  ensure_dir_mode "$hooks_dir" "$DATA_DIR_MODE"

  local auth_dir="${gluetun_root}/auth"
  local auth_config="${auth_dir}/config.toml"
  ensure_dir_mode "$auth_dir" "$DATA_DIR_MODE"

  # Only write role-based auth for Gluetun >=3.40 to avoid confusing older builds
  if gluetun_version_requires_auth_config 2>/dev/null && [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    local sanitized_key
    sanitized_key=${GLUETUN_API_KEY//$'\r'/}
    if [[ "$sanitized_key" == *$'\n'* ]]; then
      sanitized_key=${sanitized_key//$'\n'/}
      warn "[pf] Stripped newline characters from GLUETUN_API_KEY before writing auth config"
    fi
    sanitized_key=${sanitized_key//\\/\\\\}
    sanitized_key="$(printf '%s' "$sanitized_key" | sed 's/"/\\"/g')"

    local auth_payload
    auth_payload=$(
      cat <<EOF
[[roles]]
name = "${STACK}"
auth = "apikey"
apikey = "${sanitized_key}"
routes = [
  # Port forwarding endpoints
  "GET /v1/openvpn/portforwarded",

  # VPN status and control
  "GET /v1/openvpn/status",
  "PUT /v1/openvpn/status",

  # Public IP information
  "GET /v1/publicip/ip"
]
EOF
    )

    local auth_action=""
    if [[ ! -f "$auth_config" ]]; then
      auth_action="created"
    else
      local current_config
      current_config="$(cat "$auth_config" 2>/dev/null || printf '')"
      if [[ "$current_config" != "$auth_payload" ]]; then
        auth_action="updated"
      fi
    fi

    if [[ -n "$auth_action" ]]; then
      atomic_write "$auth_config" "$auth_payload" "$SECRET_FILE_MODE"
      msg "  Gluetun auth config ${auth_action} at ${auth_config}"
    fi
  else
    if gluetun_version_requires_auth_config 2>/dev/null; then
      warn "[pf] GLUETUN_API_KEY is empty; skipping Gluetun auth config generation (Gluetun 3.40+ requires an API key for control routes)"
    fi
  fi

  cat >"${hooks_dir}/update-qbt-port.sh" <<'HOOK'
#!/bin/sh
set -eu

log() {
    printf '[%s] [update-qbt-port] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" >&2
}

if ! command -v curl >/dev/null 2>&1; then
    log "curl not available inside Gluetun; skipping port update"
    exit 0
fi

PORT_SPEC="${1:-}"
PORT_VALUE="${PORT_SPEC%%,*}"
PORT_VALUE="${PORT_VALUE%%:*}"

case "$PORT_VALUE" in
    ''|*[!0-9]*)
        log "Ignoring non-numeric port payload: ${PORT_SPEC}"
        exit 0
        ;;
esac

QBITTORRENT_ADDR="${QBITTORRENT_ADDR:-http://${LOCALHOST_IP:-localhost}:${QBT_INT_PORT:-8082}}"
PAYLOAD=$(printf 'json={"listen_port":%s,"random_port":false}' "$PORT_VALUE")

COOKIE_FILE=""
cleanup_cookie() {
    if [ -n "$COOKIE_FILE" ]; then
        rm -f "$COOKIE_FILE" 2>/dev/null || true
        COOKIE_FILE=""
    fi
}
trap cleanup_cookie EXIT

attempt_update() {
    UPDATE_METHOD=""

    if curl -fsS --max-time 8 \
        --data "$PAYLOAD" \
        "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
        UPDATE_METHOD="direct"
        return 0
    fi

    if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
        COOKIE_FILE="$(mktemp "${TMPDIR:-/tmp}/update-qbt-cookie.XXXXXX")" || {
            log "Failed to create temporary cookie file"
            return 1
        }
        if curl -fsS --max-time 5 -c "$COOKIE_FILE" \
            --data-urlencode "username=${QBT_USER}" \
            --data-urlencode "password=${QBT_PASS}" \
            "${QBITTORRENT_ADDR%/}/api/v2/auth/login" >/dev/null 2>&1; then
            if curl -fsS --max-time 8 -b "$COOKIE_FILE" \
                --data "$PAYLOAD" \
                "${QBITTORRENT_ADDR%/}/api/v2/app/setPreferences" >/dev/null 2>&1; then
                UPDATE_METHOD="authenticated"
                cleanup_cookie
                return 0
            fi
            log "Authenticated but failed to apply port update"
        else
            log "qBittorrent authentication failed"
        fi
        cleanup_cookie
    else
        if [ "${ATTEMPT:-0}" = "1" ]; then
            log "Skipping authenticated update: QBT_USER/QBT_PASS not provided"
        fi
    fi

    return 1
}

MAX_ATTEMPTS=3
ATTEMPT=0
UPDATE_METHOD=""

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))

    if attempt_update; then
        if [ "$UPDATE_METHOD" = "authenticated" ]; then
            log "Updated qBittorrent listen port to ${PORT_VALUE} after authentication (attempt ${ATTEMPT})"
        else
            log "Updated qBittorrent listen port to ${PORT_VALUE} (attempt ${ATTEMPT})"
        fi
        exit 0
    fi

    if [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; then
        log "Attempt ${ATTEMPT} failed, retrying..."
        sleep 2
    fi
done

log "Failed to update port after ${MAX_ATTEMPTS} attempts"
exit 1
HOOK

  ensure_file_mode "${hooks_dir}/update-qbt-port.sh" 700
}

# Ensures Caddy basic auth credentials exist, regenerating bcrypt/hash artifacts as needed
ensure_caddy_auth() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🔐 Skipping Caddy Basic Auth setup (ENABLE_CADDY=0)"
    return 0
  fi

  step "🔐 Ensuring Caddy Basic Auth"

  hydrate_caddy_auth_from_env_file

  local sanitized_user
  sanitized_user="$(sanitize_user "${CADDY_BASIC_AUTH_USER}")"
  if [[ "$sanitized_user" != "$CADDY_BASIC_AUTH_USER" ]]; then
    CADDY_BASIC_AUTH_USER="$sanitized_user"
    persist_env_var "CADDY_BASIC_AUTH_USER" "$CADDY_BASIC_AUTH_USER"
    msg "  Caddy user sanitized -> ${CADDY_BASIC_AUTH_USER}"
  fi

  local current_hash
  current_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH:-}")"
  CADDY_BASIC_AUTH_HASH="$current_hash"

  local need_regen=0
  if [[ "${FORCE_REGEN_CADDY_AUTH:-0}" == "1" ]]; then
    need_regen=1
  elif [[ -z "$current_hash" ]] || ! valid_bcrypt "$current_hash"; then
    need_regen=1
  fi

  local cred_dir="${ARR_DOCKER_DIR}/caddy"
  local cred_file="${cred_dir}/credentials"

  if [[ "$need_regen" == "1" ]]; then
    local plaintext
    plaintext="$(gen_safe_password 20)"

    local hash_output
    hash_output="$(caddy_bcrypt "$plaintext" || true)"
    local new_hash
    new_hash="$(printf '%s\n' "$hash_output" | awk '/^\$2[aby]\$/{hash=$0} END {if (hash) print hash}')"

    if [[ -z "$new_hash" ]] || ! valid_bcrypt "$new_hash"; then
      die "Failed to generate Caddy bcrypt hash (docker or ${CADDY_IMAGE} unavailable?)"
    fi

    CADDY_BASIC_AUTH_HASH="$new_hash"
    persist_env_var "CADDY_BASIC_AUTH_HASH" "$CADDY_BASIC_AUTH_HASH"

    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    (
      umask 0077
      {
        printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
        printf 'password=%s\n' "$plaintext"
      } >"$cred_file"
    )
    chmod 600 "$cred_file" 2>/dev/null || true

    local passmask
    passmask="$(obfuscate_sensitive "$plaintext" 2 2)"
    msg "  Generated new Caddy credentials -> user: ${CADDY_BASIC_AUTH_USER}, pass: ${passmask}"
    msg "  Full credentials saved to: ${cred_file}"
  else
    ensure_dir "$cred_dir"
    chmod 700 "$cred_dir" 2>/dev/null || true
    local existing_plain=""
    if [[ -f "$cred_file" ]]; then
      existing_plain="$(grep '^password=' "$cred_file" | head -n1 | cut -d= -f2- || true)"
    fi
    if [[ -n "$existing_plain" ]]; then
      (
        umask 0077
        {
          printf 'username=%s\n' "$CADDY_BASIC_AUTH_USER"
          printf 'password=%s\n' "$existing_plain"
        } >"$cred_file"
      )
      chmod 600 "$cred_file" 2>/dev/null || true
    else
      warn "Caddy credentials file missing plaintext password; use --rotate-caddy-auth to recreate it."
    fi
    msg "  Existing Caddy bcrypt hash is valid ✓"
  fi
}

# Publishes Caddy's internal CA to a readable location for LAN distribution
sync_caddy_ca_public_copy() {
  local wait_attempts=1
  local quiet=0

  while (($#)); do
    case "$1" in
      --wait)
        wait_attempts=10
        ;;
      --quiet)
        quiet=1
        ;;
    esac
    shift
  done

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local ca_source="${caddy_root}/data/pki/authorities/local/root.crt"
  local ca_pub_dir="${caddy_root}/ca-pub"
  local ca_dest="${ca_pub_dir}/root.crt"

  ensure_dir "$ca_pub_dir"
  chmod "$DATA_DIR_MODE" "$ca_pub_dir" 2>/dev/null || true

  local attempt
  for ((attempt = 1; attempt <= wait_attempts; attempt++)); do
    if [[ -f "$ca_source" ]]; then
      if [[ -f "$ca_dest" ]] && cmp -s "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        return 0
      fi

      if cp -f "$ca_source" "$ca_dest" 2>/dev/null; then
        chmod 644 "$ca_dest" 2>/dev/null || true
        msg "  Published Caddy root certificate to ${ca_dest}"
        return 0
      fi

      warn "Failed to copy Caddy root certificate to ${ca_dest}"
      return 1
    fi

    if ((attempt < wait_attempts)); then
      sleep 2
    fi
  done

  if ((quiet == 0)); then
    warn "Caddy root certificate not found at ${ca_source}; it will be copied after Caddy issues it."
  fi

  return 1
}

# Generates Caddyfile and copies CA assets when proxying is enabled
write_caddy_assets() {
  if [[ "${ENABLE_CADDY:-0}" != "1" ]]; then
    msg "🌐 Skipping Caddy configuration (ENABLE_CADDY=0)"
    return 0
  fi

  step "🌐 Writing Caddy reverse proxy config"

  local caddy_root="${ARR_DOCKER_DIR}/caddy"
  local data_dir="${caddy_root}/data"
  local config_dir="${caddy_root}/config"
  local caddyfile="${caddy_root}/Caddyfile"
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  ensure_dir "$caddy_root"
  ensure_dir "$data_dir"
  ensure_dir "$config_dir"
  chmod "$DATA_DIR_MODE" "$caddy_root" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$data_dir" 2>/dev/null || true
  chmod "$DATA_DIR_MODE" "$config_dir" 2>/dev/null || true

  # Normalize LAN CIDRs into single-space separators
  local lan_cidrs
  lan_cidrs="$(printf '%s' "${CADDY_LAN_CIDRS}" | tr ',\t\r\n' '    ')"
  lan_cidrs="$(printf '%s\n' "$lan_cidrs" | xargs 2>/dev/null || printf '')"
  if [[ -z "$lan_cidrs" ]]; then
    lan_cidrs="${LOCALHOST_IP}/32"
  fi

  local caddy_auth_hash
  caddy_auth_hash="$(unescape_env_value_from_compose "${CADDY_BASIC_AUTH_HASH}")"

  if ! is_bcrypt_hash "$caddy_auth_hash"; then
    warn "CADDY_BASIC_AUTH_HASH does not appear to be a valid bcrypt string; use --rotate-caddy-auth to regenerate."
  fi

  # Prefer normalized suffix from .env; fall back to computed value
  local domain_suffix="${ARR_DOMAIN_SUFFIX_CLEAN}"

  local default_upstream_host="${LOCALHOST_IP:-localhost}"
  if [[ -z "$default_upstream_host" || "$default_upstream_host" == "0.0.0.0" ]]; then
    default_upstream_host="localhost"
  fi

  local -a services=(
    "qbittorrent|${QBT_INT_PORT}|${default_upstream_host}"
    "sonarr|${SONARR_PORT}|${default_upstream_host}"
    "radarr|${RADARR_PORT}|${default_upstream_host}"
    "prowlarr|${PROWLARR_PORT}|${default_upstream_host}"
    "bazarr|${BAZARR_PORT}|${default_upstream_host}"
    "flaresolverr|${FLARR_PORT}|${default_upstream_host}"
  )

  if [[ "${SABNZBD_ENABLED:-0}" == "1" && "${SABNZBD_USE_VPN:-0}" != "1" ]]; then
    local sab_proxy_port="${SABNZBD_PORT}"
    local sab_upstream_host="${SABNZBD_HOST:-$default_upstream_host}"
    if [[ -z "$sab_upstream_host" || "$sab_upstream_host" == "0.0.0.0" ]]; then
      sab_upstream_host="$default_upstream_host"
    fi
    if [[ -n "$sab_proxy_port" && "$sab_proxy_port" =~ ^[0-9]+$ ]]; then
      services+=("sabnzbd|${sab_proxy_port}|${sab_upstream_host}")
    fi
  fi

  local caddyfile_content
  caddyfile_content="$({
    printf '%s\n' "# Auto-generated by ${STACK}.sh"
    printf '# Adjust LAN CIDRs or add TLS settings via %s overrides.\n\n' "$userconf_path"
    printf '{\n'
    printf '  admin off\n'
    printf '}\n\n'

    # Plain HTTP health endpoint for container healthcheck
    printf 'http://ca.%s {\n' "$domain_suffix"
    printf '    root * /ca-pub\n'
    printf '    file_server\n'
    printf '    # Serve the public root over HTTP to avoid bootstrap loops\n'
    printf '    @ca_cert {\n'
    printf '        path /root.crt\n'
    printf '    }\n'
    printf '    handle @ca_cert {\n'
    printf '        header Content-Type "application/pkix-cert"\n'
    printf '        header Content-Disposition "attachment; filename=\"%s-root.cer\""\n' "$STACK"
    printf '    }\n'
    printf '}\n\n'

    local entry name port upstream_host host
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      host="${name}.${domain_suffix}"
      printf '%s {\n' "$host"
      printf '    tls internal\n'
      printf '    @lan remote_ip %s\n' "$lan_cidrs"
      printf '    handle @lan {\n'
      printf '        reverse_proxy %s:%s\n' "$upstream_host" "$port"
      printf '    }\n'
      printf '    handle {\n'
      printf '        basic_auth * {\n'
      printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
      printf '        }\n'
      printf '        reverse_proxy %s:%s\n' "$upstream_host" "$port"
      printf '    }\n'
      printf '}\n\n'
    done

    printf ':%s, :%s {\n' "$CADDY_HTTP_PORT" "$CADDY_HTTPS_PORT"
    printf '    encode zstd gzip\n'
    printf '    @lan remote_ip %s\n' "$lan_cidrs"
    printf '    route /healthz {\n'
    printf '        respond "ok" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle @lan {\n'
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://%s:%s\n' "$upstream_host" "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    handle {\n'
    printf '        basic_auth * {\n'
    printf '            %s %s\n' "$CADDY_BASIC_AUTH_USER" "$caddy_auth_hash"
    printf '        }\n'
    for entry in "${services[@]}"; do
      IFS='|' read -r name port upstream_host <<<"$entry"
      if [[ -z "$upstream_host" ]]; then
        upstream_host="$default_upstream_host"
      fi
      printf '        handle_path /apps/%s/* {\n' "$name"
      printf '            reverse_proxy http://%s:%s\n' "$upstream_host" "$port"
      printf '        }\n'
    done
    printf '        respond "ARR Stack Running" 200\n'
    printf '    }\n'
    printf '\n'
    printf '    tls internal\n'
    printf '}\n\n'
  })"

  atomic_write "$caddyfile" "$caddyfile_content" "$NONSECRET_FILE_MODE"

  sync_caddy_ca_public_copy --quiet || true

  if ! grep -Fq "${CADDY_BASIC_AUTH_USER}" "$caddyfile"; then
    warn "Caddyfile is missing the configured Basic Auth user; verify CADDY_BASIC_AUTH_USER"
  fi

  # shellcheck disable=SC2016  # intentional literal $ in regex
  if ! grep -qE '\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}' "$caddyfile"; then
    warn "Caddyfile bcrypt string may be invalid; hash regeneration fixes this (use --rotate-caddy-auth)."
  fi
}

# Copies the shared Gluetun helper script into the stack workspace
sync_gluetun_library() {
  step "📚 Syncing Gluetun helper library"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/gluetun.sh" "$ARR_STACK_DIR/scripts/gluetun.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/gluetun.sh" 755
}

# Syncs VPN auto-reconnect scripts with executable permissions into the stack
sync_vpn_auto_reconnect_assets() {
  step "📡 Syncing VPN auto-reconnect helpers"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  local helper
  for helper in \
    vpn-auto-stack.sh \
    vpn-auto-state.sh \
    vpn-auto-config.sh \
    vpn-auto-signals.sh \
    vpn-auto-metrics.sh \
    vpn-auto-control.sh
  do
    cp "${REPO_ROOT}/scripts/${helper}" "$ARR_STACK_DIR/scripts/${helper}"
    ensure_file_mode "$ARR_STACK_DIR/scripts/${helper}" 755
  done

  cp "${REPO_ROOT}/scripts/vpn-auto-reconnect-daemon.sh" "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh" 755
}

# Installs SABnzbd helper into the stack scripts directory
write_sab_helper_script() {
  step "🧰 Writing SABnzbd helper script"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/sab-helper.sh" "$ARR_STACK_DIR/scripts/sab-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/sab-helper.sh" 755

  msg "  SABnzbd helper: ${ARR_STACK_DIR}/scripts/sab-helper.sh"
}

# Installs qBittorrent helper shim into the stack scripts directory
write_qbt_helper_script() {
  step "🧰 Writing qBittorrent helper script"

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/qbt-helper.sh" 755

  rm -f "$ARR_STACK_DIR/scripts/qbt-webui.sh"

  msg "  qBittorrent helper (also init hook): ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

# Reconciles qBittorrent configuration defaults while preserving user customizations
write_qbt_config() {
  step "🧩 Writing qBittorrent config"
  local config_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local runtime_dir="${config_dir}/qBittorrent"
  local conf_file="${runtime_dir}/qBittorrent.conf"

  ensure_dir "$config_dir"
  ensure_dir "$runtime_dir"
  local default_auth_whitelist="${LOCALHOST_IP}/32,::1/128"
  local qb_lan_whitelist=""
  if qb_lan_whitelist="$(lan_ipv4_subnet_cidr "${LAN_IP:-}" 2>/dev/null)" && [[ -n "$qb_lan_whitelist" ]]; then
    default_auth_whitelist+=,${qb_lan_whitelist}
  fi

  local auth_whitelist
  auth_whitelist="$(normalize_csv "${QBT_AUTH_WHITELIST:-$default_auth_whitelist}")"
  QBT_AUTH_WHITELIST="$auth_whitelist"
  msg "  Stored WebUI auth whitelist entries: ${auth_whitelist}"

  local vt_root="${VUETORRENT_ROOT:-/config/vuetorrent}"
  local vt_alt_value="true"
  if [[ "${VUETORRENT_ALT_ENABLED:-1}" -eq 0 ]]; then
    vt_alt_value="false"
  fi

  local default_conf
  default_conf="$(
    cat <<EOF
[AutoRun]
enabled=false

[BitTorrent]
Session\AddTorrentStopped=false
Session\DefaultSavePath=/completed/
Session\TempPath=/downloads/incomplete/
Session\TempPathEnabled=true

[Meta]
MigrationVersion=8

[Network]
PortForwardingEnabled=false

[Preferences]
General\UseRandomPort=false
Connection\UPnP=false
Connection\UseNAT-PMP=false
WebUI\UseUPnP=false
Downloads\SavePath=/completed/
Downloads\TempPath=/downloads/incomplete/
Downloads\TempPathEnabled=true
WebUI\Address=${QBT_BIND_ADDR}
WebUI\AlternativeUIEnabled=${vt_alt_value}
WebUI\RootFolder=${vt_root}
WebUI\Port=${QBT_INT_PORT}
WebUI\Username=${QBT_USER}
WebUI\LocalHostAuth=true
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\AuthSubnetWhitelist=${auth_whitelist}
WebUI\CSRFProtection=false
WebUI\ClickjackingProtection=true
WebUI\HostHeaderValidation=false
WebUI\HTTPS\Enabled=false
WebUI\ServerDomains=*
EOF
  )"

  local source_content="$default_conf"
  if [[ -f "$conf_file" ]]; then
    local existing_content=""
    if existing_content="$(arr_read_sensitive_file "$conf_file" || true)"; then
      source_content="$existing_content"
    else
      warn "  Unable to read ${conf_file}; falling back to defaults"
    fi
  fi

  local managed_spec
  local -a managed_lines=(
    "WebUI\\Address=${QBT_BIND_ADDR}"
    "WebUI\\Port=${QBT_INT_PORT}"
    "WebUI\\AlternativeUIEnabled=${vt_alt_value}"
    "WebUI\\RootFolder=${vt_root}"
    "WebUI\\ServerDomains=*"
    "WebUI\\LocalHostAuth=true"
    "WebUI\\AuthSubnetWhitelistEnabled=true"
    "WebUI\\CSRFProtection=false"
    "WebUI\\ClickjackingProtection=true"
    "WebUI\\HostHeaderValidation=false"
    "WebUI\\AuthSubnetWhitelist=${auth_whitelist}"
  )
  managed_spec="$(printf '%s\n' "${managed_lines[@]}")"
  managed_spec="${managed_spec%$'\n'}"

  local managed_spec_for_awk
  # Escape backslashes so awk -v does not treat sequences like \A as escapes
  managed_spec_for_awk="${managed_spec//\\/\\\\}"

  local updated_content
  updated_content="$(
    printf '%s' "$source_content" \
      | awk -v managed="$managed_spec_for_awk" '
        BEGIN {
          FS = "=";
          OFS = "=";
          order_count = 0;
          count = split(managed, arr, "\n");
          for (i = 1; i <= count; i++) {
            if (arr[i] == "") {
              continue;
            }
            split(arr[i], kv, "=");
            key = kv[1];
            value = substr(arr[i], length(key) + 2);
            replacements[key] = value;
            order[++order_count] = key;
          }
        }
        {
          line = $0;
          if (index(line, "=") == 0) {
            print line;
            next;
          }
          split(line, kv, "=");
          key = kv[1];
          if (key in replacements) {
            print key, replacements[key];
            seen[key] = 1;
          } else {
            print line;
          }
        }
        END {
          for (i = 1; i <= order_count; i++) {
            key = order[i];
            if (!(key in seen)) {
              print key, replacements[key];
            }
          }
        }
      '
  )"

  atomic_write "$conf_file" "$updated_content" "$SECRET_FILE_MODE"
}

ensure_qbt_webui_config_ready() {
  local config_root="${ARR_DOCKER_DIR}/qbittorrent"
  local canonical_conf="${config_root}/qBittorrent/qBittorrent.conf"
  local legacy_conf="${config_root}/qBittorrent.conf"

  if [[ -f "$canonical_conf" ]]; then
    if [[ -f "$legacy_conf" ]]; then
      warn "Removing legacy qBittorrent.conf at ${legacy_conf}"
      if ! arr_run_sensitive_command rm -f "$legacy_conf"; then
        warn "Could not remove legacy qBittorrent.conf at ${legacy_conf}"
      fi
    fi
    return 0
  fi

  if [[ -f "$legacy_conf" ]]; then
    warn "Legacy qBittorrent.conf detected at ${legacy_conf}; move it to ${canonical_conf}."
  fi

  die "Missing qBittorrent WebUI config at ${canonical_conf}. Create the file before starting qbittorrent."
}

ensure_qbt_config() {
  msg "Ensuring qBittorrent configuration is applied"

  # Sleep to allow qBittorrent to restart safely; configurable via QBT_CONFIG_SLEEP (default: 5 seconds)
  sleep "${QBT_CONFIG_SLEEP:-5}"

  if ! docker inspect qbittorrent --format '{{.State.Running}}' 2>/dev/null | grep -q "true"; then
    warn "qBittorrent container not running, skipping config sync"
  fi

  sync_qbt_password_from_logs || true

  docker stop qbittorrent >/dev/null 2>&1 || true
  sleep "${QBT_CONFIG_SLEEP:-5}"

  write_qbt_config

  docker start qbittorrent >/dev/null 2>&1 || true

  return 0
}

# Materializes Configarr config/secrets with sanitized policy values when enabled
write_configarr_assets() {
  if [[ "${ENABLE_CONFIGARR:-0}" != "1" ]]; then
    msg "🧾 Skipping Configarr assets (ENABLE_CONFIGARR=0)"
    return 0
  fi

  step "🧾 Preparing Configarr assets"

  local configarr_root="${ARR_DOCKER_DIR}/configarr"
  local runtime_config="${configarr_root}/config.yml"
  local runtime_secrets="${configarr_root}/secrets.yml"
  local runtime_cfs="${configarr_root}/cfs"
  local -A configarr_policy=()

  ensure_dir_mode "$configarr_root" "$DATA_DIR_MODE"
  ensure_dir_mode "$runtime_cfs" "$DATA_DIR_MODE"

  local sanitized_video_min_res=""
  local sanitized_video_max_res=""
  local episode_max_mbmin=""
  local episode_min_mbmin=""
  local episode_pref_mbmin=""
  local episode_cap_mb=""
  local sanitized_ep_max_gb=""
  local sanitized_ep_min_mb=""
  local sanitized_runtime_min=""
  local sanitized_season_max_gb=""
  local sanitized_mbmin_decimals=""

  if have_command python3; then
    local py_output=""
    if py_output=$(
      python3 <<'PY'
import math
import os


def trim_float(value: float, precision: int = 2) -> str:
    if math.isclose(value, round(value)):
        return str(int(round(value)))
    fmt = "{:." + str(precision) + "f}"
    text = fmt.format(value)
    return text.rstrip("0").rstrip(".")


def sanitize_resolution(name: str, default: str, allowed: list[str], warnings: list[str]) -> str:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    lowered = raw.lower()
    for candidate in allowed:
        if candidate.lower() == lowered:
            return candidate
    warnings.append(f"{name}='{raw}' not supported; using {default}")
    return default


def parse_float(name: str, default: float, warnings: list[str], minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name, "")
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        warnings.append(f"{name}='{raw}' is not numeric; using {default}")
        return default
    if minimum is not None and value < minimum:
        warnings.append(f"{name}={raw} below minimum {minimum}; clamping")
        value = minimum
    if maximum is not None and value > maximum:
        warnings.append(f"{name}={raw} above maximum {maximum}; clamping")
        value = maximum
    return value


warnings: list[str] = []
allowed_res = ["480p", "576p", "720p", "1080p", "2160p"]
res_index = {res: idx for idx, res in enumerate(allowed_res)}

min_res = sanitize_resolution("ARR_VIDEO_MIN_RES", "720p", allowed_res, warnings)
max_res = sanitize_resolution("ARR_VIDEO_MAX_RES", "1080p", allowed_res, warnings)

if res_index[min_res] > res_index[max_res]:
    warnings.append(
        f"ARR_VIDEO_MIN_RES='{min_res}' and ARR_VIDEO_MAX_RES='{max_res}' conflict; using 720p–1080p"
    )
    min_res = "720p"
    max_res = "1080p"

max_gb = parse_float("ARR_EP_MAX_GB", 5.0, warnings, minimum=1.0, maximum=20.0)
min_mb = parse_float("ARR_EP_MIN_MB", 250.0, warnings, minimum=1.0)
runtime = parse_float("ARR_TV_RUNTIME_MIN", 45.0, warnings, minimum=1.0)
season_cap = parse_float("ARR_SEASON_MAX_GB", 30.0, warnings, minimum=1.0)

dec_raw = os.environ.get("ARR_MBMIN_DECIMALS", "1") or "1"
try:
    decimals = int(dec_raw)
except ValueError:
    warnings.append(f"ARR_MBMIN_DECIMALS='{dec_raw}' invalid; using 1")
    decimals = 1

if decimals < 0:
    warnings.append("ARR_MBMIN_DECIMALS below 0; clamping to 0")
    decimals = 0
elif decimals > 3:
    warnings.append("ARR_MBMIN_DECIMALS above 3; clamping to 3")
    decimals = 3

max_total_mb = max_gb * 1024.0

if min_mb >= max_total_mb:
    warnings.append(
        f"ARR_EP_MIN_MB={min_mb} must be smaller than ARR_EP_MAX_GB*1024={max_total_mb}; reducing"
    )
    min_mb = min(250.0, max_total_mb * 0.5)
    if min_mb <= 0:
        min_mb = max_total_mb * 0.25

episode_max_mbmin = max_total_mb / runtime
episode_min_mbmin = min_mb / runtime

if episode_max_mbmin < 20.0:
    warnings.append(
        f"Derived episode max {episode_max_mbmin:.2f} MB/min is too small; using 60"
    )
    episode_max_mbmin = 60.0

if episode_min_mbmin >= episode_max_mbmin:
    episode_min_mbmin = max(episode_max_mbmin * 0.5, 1.0)

episode_pref_mbmin = (episode_min_mbmin + episode_max_mbmin) / 2.0

fmt = "{:." + str(decimals) + "f}"

print(f"sanitized_video_min_res={min_res}")
print(f"sanitized_video_max_res={max_res}")
print(f"episode_max_mbmin={fmt.format(episode_max_mbmin)}")
print(f"episode_min_mbmin={fmt.format(episode_min_mbmin)}")
print(f"episode_pref_mbmin={fmt.format(episode_pref_mbmin)}")
print(f"episode_cap_mb={int(round(max_total_mb))}")
print(f"sanitized_ep_max_gb={trim_float(max_gb)}")
print(f"sanitized_ep_min_mb={trim_float(min_mb, 1)}")
print(f"sanitized_runtime_min={trim_float(runtime, 1)}")
print(f"sanitized_season_max_gb={trim_float(season_cap, 1)}")
print(f"sanitized_mbmin_decimals={decimals}")

for warning in warnings:
    print("warn::" + warning)
PY
    ); then
      while IFS= read -r line; do
        case "$line" in
          warn::*)
            warn "Configarr: ${line#warn::}"
            ;;
          sanitized_video_min_res=*)
            sanitized_video_min_res="${line#*=}"
            ;;
          sanitized_video_max_res=*)
            sanitized_video_max_res="${line#*=}"
            ;;
          episode_max_mbmin=*)
            episode_max_mbmin="${line#*=}"
            ;;
          episode_min_mbmin=*)
            episode_min_mbmin="${line#*=}"
            ;;
          episode_pref_mbmin=*)
            episode_pref_mbmin="${line#*=}"
            ;;
          episode_cap_mb=*)
            episode_cap_mb="${line#*=}"
            ;;
          sanitized_ep_max_gb=*)
            sanitized_ep_max_gb="${line#*=}"
            ;;
          sanitized_ep_min_mb=*)
            sanitized_ep_min_mb="${line#*=}"
            ;;
          sanitized_runtime_min=*)
            sanitized_runtime_min="${line#*=}"
            ;;
          sanitized_season_max_gb=*)
            sanitized_season_max_gb="${line#*=}"
            ;;
          sanitized_mbmin_decimals=*)
            sanitized_mbmin_decimals="${line#*=}"
            ;;
        esac
      done <<<"$py_output"
    else
      warn "Configarr: failed to evaluate policy heuristics via python3; using defaults"
    fi
  else
    warn "Configarr: python3 unavailable; using default policy heuristics"
  fi

  : "${sanitized_video_min_res:=720p}"
  : "${sanitized_video_max_res:=1080p}"
  : "${episode_max_mbmin:=113.8}"
  : "${episode_min_mbmin:=5.6}"
  : "${episode_pref_mbmin:=59.7}"
  : "${episode_cap_mb:=5120}"
  : "${sanitized_ep_max_gb:=5}"
  : "${sanitized_ep_min_mb:=250}"
  : "${sanitized_runtime_min:=45}"
  : "${sanitized_season_max_gb:=30}"
  : "${sanitized_mbmin_decimals:=1}"

  declare -A res_index=(
    [480p]=0
    [576p]=1
    [720p]=2
    [1080p]=3
    [2160p]=4
  )

  local min_idx="${res_index[$sanitized_video_min_res]:-${res_index[720p]}}"
  local max_idx="${res_index[$sanitized_video_max_res]:-${res_index[1080p]}}"

  local include_720=0
  local include_1080=0

  if ((min_idx <= res_index[720p] && max_idx >= res_index[720p])); then
    include_720=1
  fi
  if ((min_idx <= res_index[1080p] && max_idx >= res_index[1080p])); then
    include_1080=1
  fi

  if ((include_720 == 0 && include_1080 == 0)); then
    include_1080=1
    sanitized_video_min_res="1080p"
    sanitized_video_max_res="1080p"
    min_idx="${res_index[1080p]}"
    max_idx="${res_index[1080p]}"
  fi

  local -a sonarr_qualities=()
  local -a radarr_qualities=()

  if ((include_720)); then
    sonarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
    radarr_qualities+=("HDTV-720p" "WEBRip-720p" "WEBDL-720p" "Bluray-720p")
  fi
  if ((include_1080)); then
    sonarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Bluray-1080p Remux")
    radarr_qualities+=("HDTV-1080p" "WEBRip-1080p" "WEBDL-1080p" "Bluray-1080p" "Remux-1080p")
  fi

  if ((${#sonarr_qualities[@]} == 0)); then
    sonarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi
  if ((${#radarr_qualities[@]} == 0)); then
    radarr_qualities=("WEBRip-1080p" "WEBDL-1080p")
  fi

  local sonarr_quality_yaml=""
  local radarr_quality_yaml=""
  local quality

  for quality in "${sonarr_qualities[@]}"; do
    sonarr_quality_yaml+="    - quality: \"${quality}\"\n"
    sonarr_quality_yaml+="      min: \"${episode_min_mbmin}\"\n"
    sonarr_quality_yaml+="      preferred: \"${episode_pref_mbmin}\"\n"
    sonarr_quality_yaml+="      max: \"${episode_max_mbmin}\"\n"
  done

  for quality in "${radarr_qualities[@]}"; do
    radarr_quality_yaml+="    - quality: \"${quality}\"\n"
    radarr_quality_yaml+="      min: \"${episode_min_mbmin}\"\n"
    radarr_quality_yaml+="      preferred: \"${episode_pref_mbmin}\"\n"
    radarr_quality_yaml+="      max: \"${episode_max_mbmin}\"\n"
  done

  local sonarr_override_path="${runtime_cfs}/sonarr-quality-definition-override.yml"
  local radarr_override_path="${runtime_cfs}/radarr-quality-definition-override.yml"
  local common_cf_path="${runtime_cfs}/common-negative-formats.yml"

  if [[ ! -f "$sonarr_override_path" ]]; then
    local sonarr_content
    sonarr_content="# Auto-generated by ${STACK}.sh for Configarr size guardrails\n"
    sonarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    sonarr_content+="quality_definition:\n"
    sonarr_content+="  qualities:\n"
    sonarr_content+="${sonarr_quality_yaml}"
    atomic_write "$sonarr_override_path" "$sonarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Sonarr quality override: ${sonarr_override_path}"
  else
    ensure_nonsecret_file_mode "$sonarr_override_path"
  fi

  if [[ ! -f "$radarr_override_path" ]]; then
    local radarr_content
    radarr_content="# Auto-generated by ${STACK}.sh for Configarr size guardrails\n"
    radarr_content+="# Derived from ARR_EP_MAX_GB=${sanitized_ep_max_gb} (~${episode_cap_mb} MB) and ARR_TV_RUNTIME_MIN=${sanitized_runtime_min} minutes.\n"
    radarr_content+="quality_definition:\n"
    radarr_content+="  qualities:\n"
    radarr_content+="${radarr_quality_yaml}"
    atomic_write "$radarr_override_path" "$radarr_content" "$NONSECRET_FILE_MODE"
    msg "  Created Radarr quality override: ${radarr_override_path}"
  else
    ensure_nonsecret_file_mode "$radarr_override_path"
  fi

  normalize_toggle() {
    local value="${1:-0}"
    case "$value" in
      1 | true | TRUE | yes | YES | on | ON)
        printf '1'
        ;;
      *)
        printf '0'
        ;;
    esac
  }

  sanitize_score() {
    local value="${1:-0}"
    local default="${2:-0}"
    if [[ "$value" =~ ^-?[0-9]+$ ]]; then
      printf '%s' "$value"
    else
      warn "Configarr: invalid score '${value}', using ${default}"
      printf '%s' "$default"
    fi
  }

  local english_only
  english_only="$(normalize_toggle "${ARR_ENGLISH_ONLY:-1}")"
  local discourage_multi
  discourage_multi="$(normalize_toggle "${ARR_DISCOURAGE_MULTI:-1}")"
  local penalize_hd_x265
  penalize_hd_x265="$(normalize_toggle "${ARR_PENALIZE_HD_X265:-1}")"
  local strict_junk_block
  strict_junk_block="$(normalize_toggle "${ARR_STRICT_JUNK_BLOCK:-1}")"

  local junk_score
  junk_score="$(sanitize_score "${ARR_JUNK_NEGATIVE_SCORE:- -1000}" "-1000")"
  local x265_score
  x265_score="$(sanitize_score "${ARR_X265_HD_NEGATIVE_SCORE:- -200}" "-200")"
  local multi_score
  multi_score="$(sanitize_score "${ARR_MULTI_NEGATIVE_SCORE:- -50}" "-50")"
  local english_bias_raw
  english_bias_raw="$(sanitize_score "${ARR_ENGLISH_POSITIVE_SCORE:-50}" "50")"

  local english_penalty_score="-${english_bias_raw#-}"

  local -a policy_profile_targets=("WEB-1080p" "HD Bluray + WEB")
  append_cf_block() {
    local score="$1"
    local label="$2"
    shift 2 || return 0
    local -a ids=("$@")
    if [[ -z "$score" || "$score" == "0" ]]; then
      return 0
    fi
    if ((${#ids[@]} == 0)); then
      return 0
    fi
    local block="  # ${label}\n  - trash_ids:\n"
    local id
    for id in "${ids[@]}"; do
      block+="      - $(arr_yaml_escape "${id}")\n"
    done
    block+="    assign_scores_to:\n"
    local target
    for target in "${policy_profile_targets[@]}"; do
      block+="      - name: $(arr_yaml_escape "${target}")\n"
      block+="        score: $(arr_yaml_escape "${score}")\n"
    done
    printf '%s' "$block"
  }

  local configarr_helper_dir
  configarr_helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=scripts/configarr-custom-formats.sh
  source "${configarr_helper_dir}/configarr-custom-formats.sh"

  local -a CF_IDS_LQ=()
  local -a CF_IDS_LQ_TITLE=()
  local -a CF_IDS_UPSCALED=()
  local -a CF_IDS_LANGUAGE=()
  local -a CF_IDS_MULTI=()
  local -a CF_IDS_X265=()

  configarr_load_custom_format_ids \
    CF_IDS_LQ \
    CF_IDS_LQ_TITLE \
    CF_IDS_UPSCALED \
    CF_IDS_LANGUAGE \
    CF_IDS_MULTI \
    CF_IDS_X265

  local common_cf_body=""
  local block=""

  if ((strict_junk_block)); then
    block="$(append_cf_block "$junk_score" "LQ releases" "${CF_IDS_LQ[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block "$junk_score" "LQ (Release Title)" "${CF_IDS_LQ_TITLE[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
    block="$(append_cf_block "$junk_score" "Upscaled flags" "${CF_IDS_UPSCALED[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((english_only)); then
    block="$(append_cf_block "$english_penalty_score" "Language: Not English" "${CF_IDS_LANGUAGE[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((discourage_multi)); then
    block="$(append_cf_block "$multi_score" "MULTi releases" "${CF_IDS_MULTI[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  if ((penalize_hd_x265)); then
    block="$(append_cf_block "$x265_score" "x265 (HD)" "${CF_IDS_X265[@]}")"
    if [[ -n "$block" ]]; then
      common_cf_body+="$block\n"
    fi
  fi

  local common_cf_exists=0
  if [[ -n "$common_cf_body" ]]; then
    local cf_payload="# Auto-generated by ${STACK}.sh to reinforce Configarr scoring\n"
    cf_payload+="# Adjust ARR_* environment variables to regenerate; delete this file to rebuild.\n"
    cf_payload+="custom_formats:\n"
    cf_payload+="$common_cf_body"
    if [[ ! -f "$common_cf_path" ]]; then
      atomic_write "$common_cf_path" "$cf_payload" "$NONSECRET_FILE_MODE"
      msg "  Created shared custom-format reinforcements: ${common_cf_path}"
    else
      ensure_nonsecret_file_mode "$common_cf_path"
    fi
    common_cf_exists=1
  elif [[ -f "$common_cf_path" ]]; then
    ensure_nonsecret_file_mode "$common_cf_path"
    common_cf_exists=1
  fi

  local -a sonarr_templates=("sonarr-quality-definition-series")
  local sonarr_profile_template="${SONARR_TRASH_TEMPLATE:-sonarr-v4-quality-profile-web-1080p}"
  if [[ -n "$sonarr_profile_template" ]]; then
    sonarr_templates+=("${sonarr_profile_template}")
  fi
  sonarr_templates+=("sonarr-v4-custom-formats-web-1080p")
  if [[ -f "$sonarr_override_path" ]]; then
    sonarr_templates+=("sonarr-quality-definition-override")
  fi
  if ((common_cf_exists)); then
    sonarr_templates+=("common-negative-formats")
  fi

  local -a radarr_templates=("radarr-quality-definition")
  local radarr_profile_template="${RADARR_TRASH_TEMPLATE:-radarr-v5-quality-profile-hd-bluray-web}"
  if [[ -n "$radarr_profile_template" ]]; then
    radarr_templates+=("${radarr_profile_template}")
  fi
  radarr_templates+=("radarr-v5-custom-formats-hd-bluray-web")
  if [[ -f "$radarr_override_path" ]]; then
    radarr_templates+=("radarr-quality-definition-override")
  fi
  if ((common_cf_exists)); then
    radarr_templates+=("common-negative-formats")
  fi

  local sonarr_include_yaml=""
  local template
  for template in "${sonarr_templates[@]}"; do
    sonarr_include_yaml+="      - template: $(arr_yaml_escape "${template}")\n"
  done
  sonarr_include_yaml+="      # - template: sonarr-v4-quality-profile-web-2160p\n"
  sonarr_include_yaml+="      # - template: sonarr-v4-custom-formats-web-2160p\n"

  local radarr_include_yaml=""
  for template in "${radarr_templates[@]}"; do
    radarr_include_yaml+="      - template: $(arr_yaml_escape "${template}")\n"
  done
  radarr_include_yaml+="      # - template: radarr-v5-quality-profile-uhd-bluray-web\n"
  radarr_include_yaml+="      # - template: radarr-v5-custom-formats-uhd-bluray-web\n"

  local default_config
  default_config=$(
    cat <<EOF_CFG
# Auto-generated by the stack script. Edit cautiously or disable via ENABLE_CONFIGARR=0.
version: 1

localConfigTemplatesPath: /app/cfs
# localCustomFormatsPath: /app/cfs

sonarr:
  main:
    define: true
    host: http://${LOCALHOST_IP}:${SONARR_PORT}
    apiKey: !secret SONARR_API_KEY
    include:
${sonarr_include_yaml}    custom_formats: []

radarr:
  main:
    define: true
    host: http://${LOCALHOST_IP}:${RADARR_PORT}
    apiKey: !secret RADARR_API_KEY
    include:
${radarr_include_yaml}    custom_formats: []
EOF_CFG
  )

  if [[ ! -f "$runtime_config" ]]; then
    atomic_write "$runtime_config" "$default_config" "$NONSECRET_FILE_MODE"
    msg "  Installed default config: ${runtime_config}"
  else
    ensure_nonsecret_file_mode "$runtime_config"
  fi

  if [[ ! -f "$runtime_secrets" ]]; then
    local secrets_stub
    secrets_stub=$(
      cat <<'EOF'
SONARR_API_KEY: "REPLACE_WITH_SONARR_API_KEY"
RADARR_API_KEY: "REPLACE_WITH_RADARR_API_KEY"
PROWLARR_API_KEY: "REPLACE_WITH_PROWLARR_API_KEY"
SABNZBD_API_KEY: "REPLACE_WITH_SABNZBD_API_KEY"
EOF
    )
    atomic_write "$runtime_secrets" "$secrets_stub" "$SECRET_FILE_MODE"
    msg "  Stubbed secrets file: ${runtime_secrets}"
  else
    ensure_secret_file_mode "$runtime_secrets"
  fi

  if [[ -f "$runtime_secrets" ]]; then
    if ! grep -q '^SABNZBD_API_KEY:' "$runtime_secrets" 2>/dev/null; then
      printf 'SABNZBD_API_KEY: "REPLACE_WITH_SABNZBD_API_KEY"\n' >>"$runtime_secrets"
      ensure_secret_file_mode "$runtime_secrets"
      msg "  Added SABnzbd placeholder to Configarr secrets"
    fi

    if [[ "${ARR_SAB_API_KEY_STATE:-}" == "set" ]]; then
      local sab_secret_result=""
      if sab_secret_result="$(arr_update_secret_line "$runtime_secrets" "SABNZBD_API_KEY" "$SABNZBD_API_KEY" 0 2>/dev/null)"; then
        case "$sab_secret_result" in
          updated | created | appended)
            msg "  Configarr secrets: synced SABnzbd API key"
            ;;
        esac
      fi
    fi
  fi

  local resolution_display="${sanitized_video_min_res}–${sanitized_video_max_res}"
  local lang_primary="${ARR_LANG_PRIMARY:-en}"
  lang_primary="${lang_primary,,}"

  configarr_policy[resolution]="$resolution_display"
  configarr_policy[episode_cap_gb]="$sanitized_ep_max_gb"
  configarr_policy[episode_mbmin]="$episode_max_mbmin"
  configarr_policy[runtime]="$sanitized_runtime_min"
  configarr_policy[season_cap_gb]="$sanitized_season_max_gb"
  configarr_policy[language_primary]="$lang_primary"

  if ((english_only)); then
    configarr_policy[english_bias]="ON (score ${english_penalty_score})"
  else
    configarr_policy[english_bias]="OFF"
  fi
  if ((discourage_multi)); then
    configarr_policy[multi_penalty]="ON (score ${multi_score})"
  else
    configarr_policy[multi_penalty]="OFF"
  fi
  if ((penalize_hd_x265)); then
    configarr_policy[x265_penalty]="ON (score ${x265_score})"
  else
    configarr_policy[x265_penalty]="OFF"
  fi
  if ((strict_junk_block)); then
    if ((common_cf_exists)); then
      configarr_policy[junk_reinforce]="ON (score ${junk_score})"
    else
      configarr_policy[junk_reinforce]="ON (template missing)"
    fi
  else
    configarr_policy[junk_reinforce]="OFF"
  fi

  CONFIGARR_POLICY_RESOLUTION="${configarr_policy[resolution]}"
  CONFIGARR_POLICY_EP_GB="${configarr_policy[episode_cap_gb]}"
  CONFIGARR_POLICY_EP_MBMIN="${configarr_policy[episode_mbmin]}"
  CONFIGARR_POLICY_RUNTIME="${configarr_policy[runtime]}"
  CONFIGARR_POLICY_SEASON_GB="${configarr_policy[season_cap_gb]}"
  CONFIGARR_POLICY_LANG="${configarr_policy[language_primary]}"
  CONFIGARR_POLICY_ENGLISH="${configarr_policy[english_bias]}"
  CONFIGARR_POLICY_MULTI="${configarr_policy[multi_penalty]}"
  CONFIGARR_POLICY_X265="${configarr_policy[x265_penalty]}"
  CONFIGARR_POLICY_JUNK="${configarr_policy[junk_reinforce]}"
  export CONFIGARR_POLICY_RESOLUTION CONFIGARR_POLICY_EP_GB CONFIGARR_POLICY_EP_MBMIN \
    CONFIGARR_POLICY_RUNTIME CONFIGARR_POLICY_SEASON_GB CONFIGARR_POLICY_LANG \
    CONFIGARR_POLICY_ENGLISH CONFIGARR_POLICY_MULTI CONFIGARR_POLICY_X265 CONFIGARR_POLICY_JUNK

  msg "  Configarr policy: ${resolution_display}, cap ${sanitized_ep_max_gb} GB (~${episode_max_mbmin} MB/min)"
  msg "  Penalties: English=${configarr_policy[english_bias]}, Multi=${configarr_policy[multi_penalty]}, x265=${configarr_policy[x265_penalty]}, Junk=${configarr_policy[junk_reinforce]}"
}

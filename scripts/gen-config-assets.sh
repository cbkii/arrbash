# shellcheck shell=bash
# Purpose: Generate runtime asset files for services (Gluetun, qBittorrent, Configarr, helpers).
# Inputs: Requires ARR_DOCKER_DIR, STACK, SABNZBD_ENABLED, and credential variables.
# Outputs: Writes scripts/config assets on disk and updates environment variables when regenerating credentials.
# Exit codes: Functions return non-zero when file writes fail or validations detect invalid configurations.
if [[ -n "${__CONFIG_ASSETS_LOADED:-}" ]]; then
  return 0
fi
__CONFIG_ASSETS_LOADED=1

_configarr_sanitize_score() {
  local label="$1"
  local raw_value="$2"
  local default_value="$3"
  local min_value="${4:-}"
  local max_value="${5:-}"
  local value="$raw_value"
  local display="${raw_value:-<empty>}"

  if [[ -z "$value" ]]; then
    value="$default_value"
  fi

  if [[ ! "$value" =~ ^-?[0-9]+$ ]]; then
    warn "Configarr: ${label}=${display} is not an integer; using ${default_value}"
    value="$default_value"
  else
    if [[ -n "$min_value" ]] && ((value < min_value)); then
      warn "Configarr: ${label}=${value} below minimum ${min_value}; clamping"
      value="$min_value"
    fi
    if [[ -n "$max_value" ]] && ((value > max_value)); then
      warn "Configarr: ${label}=${value} above maximum ${max_value}; clamping"
      value="$max_value"
    fi
  fi

  printf '%s\n' "$value"
}

write_gluetun_control_assets() {
  msg "Preparing Gluetun control assets for Proton port forwarding"

  local gluetun_root="${ARR_DOCKER_DIR}/gluetun"

  ensure_data_dir_mode "$gluetun_root"
  ensure_dir_mode "${gluetun_root}/state" "$DATA_DIR_MODE"

  local auth_dir="${gluetun_root}/auth"
  local auth_config="${auth_dir}/config.toml"
  ensure_dir_mode "$auth_dir" "$DATA_DIR_MODE"

  # Only write role-based auth for Gluetun >=3.40 to avoid confusing older builds
  if gluetun_version_requires_auth_config 2>/dev/null && [[ -n "${GLUETUN_API_KEY:-}" ]]; then
    local sanitized_key
    sanitized_key=${GLUETUN_API_KEY//$'\r'/}
    if [[ "$sanitized_key" == *$'\n'* ]]; then
      sanitized_key=${sanitized_key//$'\n'/}
      warn "Stripped newline characters from GLUETUN_API_KEY before writing Gluetun auth config"
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
  # Port forwarding endpoints (unified endpoint for Gluetun v3.40+)
  "GET /v1/portforward",
  
  # VPN status endpoints (both OpenVPN and WireGuard)
  "GET /v1/openvpn/status",
  "PUT /v1/openvpn/status",
  "GET /v1/wireguard/status",
  "PUT /v1/wireguard/status",

  # Public IP information
  "GET /v1/publicip/ip",
  
  # Health check (typically doesn't require auth but included for completeness)
  "GET /healthcheck"
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
      msg "Gluetun auth config ${auth_action} at ${auth_config}"
    fi
  else
    if gluetun_version_requires_auth_config 2>/dev/null; then
      warn "GLUETUN_API_KEY is empty; skipping Gluetun auth config generation (Gluetun 3.40+ requires an API key for control routes)"
    fi
  fi

  ensure_dir_mode "${gluetun_root}/hooks" "$DATA_DIR_MODE"
}

# Copies the shared Gluetun helper script into the stack workspace
sync_gluetun_library() {

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/vpn-gluetun.sh" "$ARR_STACK_DIR/scripts/vpn-gluetun.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/vpn-gluetun.sh" 755
}

# Syncs VPN auto-reconnect scripts with executable permissions into the stack
sync_vpn_auto_reconnect_assets() {

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  local helper
  for helper in \
    vpn-auto-stack.sh \
    vpn-auto-state.sh \
    vpn-auto-config.sh; do
    cp "${REPO_ROOT}/scripts/${helper}" "$ARR_STACK_DIR/scripts/${helper}"
    ensure_file_mode "$ARR_STACK_DIR/scripts/${helper}" 755
  done

  cp "${REPO_ROOT}/scripts/vpn-auto-reconnect-daemon.sh" "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/vpn-auto-reconnect-daemon.sh" 755
}

# Copies vpn-port-guard controller assets into the stack scripts directory
sync_vpn_port_guard_assets() {

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  local asset
  for asset in \
    vpn-port-guard.sh \
    gluetun-api.sh \
    qbt-api.sh \
    vpn-port-guard-hook.sh; do
    cp "${REPO_ROOT}/scripts/${asset}" "$ARR_STACK_DIR/scripts/${asset}"
    ensure_file_mode "$ARR_STACK_DIR/scripts/${asset}" 755
  done

  msg "vpn-port-guard scripts: ${ARR_STACK_DIR}/scripts"
}

# Installs SABnzbd helper into the stack scripts directory
write_sab_helper_script() {

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/stack-sab-helper.sh" "$ARR_STACK_DIR/scripts/sab-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/sab-helper.sh" 755

  msg "SABnzbd helper: ${ARR_STACK_DIR}/scripts/sab-helper.sh"
}

# Installs qBittorrent helper shim into the stack scripts directory
write_qbt_helper_script() {

  ensure_dir_mode "$ARR_STACK_DIR/scripts" 755

  cp "${REPO_ROOT}/scripts/stack-qbt-helper.sh" "$ARR_STACK_DIR/scripts/qbt-helper.sh"
  ensure_file_mode "$ARR_STACK_DIR/scripts/qbt-helper.sh" 755

  rm -f "$ARR_STACK_DIR/scripts/qbt-webui.sh"

  msg "qBittorrent helper (also init hook): ${ARR_STACK_DIR}/scripts/qbt-helper.sh"
}

# Reconciles qBittorrent configuration defaults while preserving user customizations
write_qbt_config() {
  local docker_root
  docker_root="$(arr_docker_data_root)"

  local config_dir
  local runtime_dir
  local conf_file

  config_dir="$(arr_qbt_config_root "$docker_root")"
  runtime_dir="$(arr_qbt_runtime_dir "$docker_root")"
  conf_file="$(arr_qbt_conf_path "$docker_root")"

  arr_qbt_migrate_legacy_conf "$docker_root"

  ensure_dir "$config_dir"
  ensure_dir "$runtime_dir"
  local default_auth_whitelist="${LOCALHOST_IP}/32,::1/128"
  local qb_lan_whitelist=""
  if qb_lan_whitelist="$(lan_ipv4_host_cidr "${LAN_IP:-}" 2>/dev/null)" && [[ -n "$qb_lan_whitelist" ]]; then
    default_auth_whitelist="${qb_lan_whitelist},${default_auth_whitelist}"
  fi

  local auth_whitelist
  auth_whitelist="$(normalize_csv "${QBT_AUTH_WHITELIST:-$default_auth_whitelist}")"
  QBT_AUTH_WHITELIST="$auth_whitelist"
  msg "Stored WebUI auth whitelist entries: ${auth_whitelist}"

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
General\UseRandomPort=true
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
      warn "Unable to read ${conf_file}; falling back to defaults"
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
    "General\\UseRandomPort=true"
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
  local docker_root
  docker_root="$(arr_docker_data_root)"

  arr_qbt_migrate_legacy_conf "$docker_root"

  local canonical_conf
  canonical_conf="$(arr_qbt_conf_path "$docker_root")"

  if [[ -f "$canonical_conf" ]]; then
    return 0
  fi

  local legacy_conf
  legacy_conf="$(arr_qbt_legacy_conf_path "$docker_root")"
  if [[ -f "$legacy_conf" ]]; then
    warn "Legacy qBittorrent.conf detected at ${legacy_conf}; remove it so the canonical config at ${canonical_conf} can be used."
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

  local configarr_root="${ARR_DOCKER_DIR}/configarr"
  local runtime_cfs="${configarr_root}/cfs"
  local -A configarr_policy=()

  ensure_dir_mode "$configarr_root" "$DATA_DIR_MODE"
  ensure_dir_mode "$runtime_cfs" "$DATA_DIR_MODE"

  local english_only
  english_only="$(arr_normalize_bool "${ARR_ENGLISH_ONLY:-1}")"

  local discourage_multi
  discourage_multi="$(arr_normalize_bool "${ARR_DISCOURAGE_MULTI:-1}")"

  local penalize_hd_x265
  penalize_hd_x265="$(arr_normalize_bool "${ARR_PENALIZE_HD_X265:-1}")"

  local strict_junk_block
  strict_junk_block="$(arr_normalize_bool "${ARR_STRICT_JUNK_BLOCK:-1}")"

  local english_penalty_score
  english_penalty_score="$(_configarr_sanitize_score 'ARR_ENGLISH_POSITIVE_SCORE' "${ARR_ENGLISH_POSITIVE_SCORE:-}" 50 0 1000)"

  local multi_score
  multi_score="$(_configarr_sanitize_score 'ARR_MULTI_NEGATIVE_SCORE' "${ARR_MULTI_NEGATIVE_SCORE:-}" -50 '' 0)"

  local x265_score
  x265_score="$(_configarr_sanitize_score 'ARR_X265_HD_NEGATIVE_SCORE' "${ARR_X265_HD_NEGATIVE_SCORE:-}" -200 '' 0)"

  local junk_score
  junk_score="$(_configarr_sanitize_score 'ARR_JUNK_NEGATIVE_SCORE' "${ARR_JUNK_NEGATIVE_SCORE:-}" -1000 '' 0)"

  local common_cf_exists=0
  local -a _configarr_cf_search=()
  if [[ -n "${ARRCONF_DIR:-}" ]]; then
    _configarr_cf_search+=("${ARRCONF_DIR}/configarr/cfs")
  fi
  _configarr_cf_search+=("$runtime_cfs")

  local search_dir
  for search_dir in "${_configarr_cf_search[@]}"; do
    [[ -d "$search_dir" ]] || continue
    if compgen -G "${search_dir%/}/common*.yml" >/dev/null 2>&1 \
      || compgen -G "${search_dir%/}/common*.yaml" >/dev/null 2>&1; then
      common_cf_exists=1
      break
    fi
  done

  local sanitized_video_min_res=""
  local sanitized_video_max_res=""
  local episode_max_mbmin=""
  local sanitized_ep_max_gb=""
  local sanitized_runtime_min=""
  local sanitized_season_max_gb=""

  local policy_eval_output=""

  if policy_eval_output="$(
    ARR_VIDEO_MIN_RES="${ARR_VIDEO_MIN_RES:-}" \
      ARR_VIDEO_MAX_RES="${ARR_VIDEO_MAX_RES:-}" \
      ARR_EP_MAX_GB="${ARR_EP_MAX_GB:-}" \
      ARR_EP_MIN_MB="${ARR_EP_MIN_MB:-}" \
      ARR_TV_RUNTIME_MIN="${ARR_TV_RUNTIME_MIN:-}" \
      ARR_SEASON_MAX_GB="${ARR_SEASON_MAX_GB:-}" \
      ARR_MBMIN_DECIMALS="${ARR_MBMIN_DECIMALS:-}" \
      awk '
      function abs_val(x) { return x < 0 ? -x : x }
      function trim(s) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
        return s
      }
      function warn_msg(msg) { warnings[++warn_count] = msg }
      function sanitize_resolution(name, default_value, raw, lowered, i) {
        raw = trim(ENVIRON[name])
        if (raw == "") {
          return default_value
        }
        lowered = tolower(raw)
        for (i = 1; i <= allowed_count; i++) {
          if (tolower(allowed[i]) == lowered) {
            return allowed[i]
          }
        }
        warn_msg(name "='" raw "' not supported; using " default_value)
        return default_value
      }
      function parse_float(name, default_value, min_set, minimum, max_set, maximum, raw, trimmed, value) {
        if (!(name in ENVIRON)) {
          return default_value
        }
        raw = ENVIRON[name]
        trimmed = trim(raw)
        if (trimmed == "" && raw != "0") {
          return default_value
        }
        if (trimmed == "" && raw == "0") {
          trimmed = "0"
        }
        if (trimmed !~ /^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$/) {
          warn_msg(name "='" raw "' is not numeric; using " default_value)
          return default_value
        }
        value = trimmed + 0
        if (min_set && value < minimum) {
          warn_msg(name "=" raw " below minimum " minimum "; clamping")
          value = minimum
        }
        if (max_set && value > maximum) {
          warn_msg(name "=" raw " above maximum " maximum "; clamping")
          value = maximum
        }
        return value
      }
      function trim_float(value, precision, rounded, text) {
        if (precision == "") {
          precision = 2
        }
        rounded = (value >= 0 ? int(value + 0.5) : int(value - 0.5))
        if (abs_val(value - rounded) < 1e-9) {
          return sprintf("%d", rounded)
        }
        text = sprintf("%.*f", precision, value)
        sub(/0+$/, "", text)
        sub(/\.$/, "", text)
        return text
      }
      function round_value(value) { return (value >= 0 ? int(value + 0.5) : int(value - 0.5)) }
      function max_value(a, b) { return a > b ? a : b }
      function min_value(a, b) { return a < b ? a : b }
      BEGIN {
        warn_count = 0
        allowed_count = split("480p 576p 720p 1080p 2160p", allowed, " ")
        for (i = 1; i <= allowed_count; i++) {
          res_index[allowed[i]] = i
        }
        min_res = sanitize_resolution("ARR_VIDEO_MIN_RES", "720p")
        max_res = sanitize_resolution("ARR_VIDEO_MAX_RES", "1080p")
        if (res_index[min_res] > res_index[max_res]) {
          warn_msg("ARR_VIDEO_MIN_RES='" min_res "' and ARR_VIDEO_MAX_RES='" max_res "' conflict; using 720p–1080p")
          min_res = "720p"
          max_res = "1080p"
        }
        max_gb = parse_float("ARR_EP_MAX_GB", 5.0, 1, 1.0, 1, 20.0)
        min_mb = parse_float("ARR_EP_MIN_MB", 250.0, 1, 1.0, 0, 0)
        runtime = parse_float("ARR_TV_RUNTIME_MIN", 45.0, 1, 1.0, 0, 0)
        season_cap = parse_float("ARR_SEASON_MAX_GB", 30.0, 1, 1.0, 0, 0)
        dec_raw = ENVIRON["ARR_MBMIN_DECIMALS"]
        if (dec_raw == "") {
          dec_raw = "1"
        }
        dec_trim = trim(dec_raw)
        if (dec_trim == "") {
          dec_trim = "1"
        }
        if (dec_trim !~ /^[-+]?[0-9]+$/) {
          warn_msg("ARR_MBMIN_DECIMALS='" dec_raw "' invalid; using 1")
          decimals = 1
        } else {
          decimals = dec_trim + 0
        }
        if (decimals < 0) {
          warn_msg("ARR_MBMIN_DECIMALS below 0; clamping to 0")
          decimals = 0
        } else if (decimals > 3) {
          warn_msg("ARR_MBMIN_DECIMALS above 3; clamping to 3")
          decimals = 3
        }
        max_total_mb = max_gb * 1024.0
        if (min_mb >= max_total_mb) {
          warn_msg("ARR_EP_MIN_MB=" min_mb " must be smaller than ARR_EP_MAX_GB*1024=" max_total_mb "; reducing")
          min_mb = min_value(250.0, max_total_mb * 0.5)
          if (min_mb <= 0) {
            min_mb = max_total_mb * 0.25
          }
        }
        episode_max_mbmin = max_total_mb / runtime
        episode_min_mbmin = min_mb / runtime
        if (episode_max_mbmin < 20.0) {
          warn_msg("Derived episode max " sprintf("%.2f", episode_max_mbmin) " MB/min is too small; using 60")
          episode_max_mbmin = 60.0
        }
        if (episode_min_mbmin >= episode_max_mbmin) {
          episode_min_mbmin = max_value(episode_max_mbmin * 0.5, 1.0)
        }
        episode_pref_mbmin = (episode_min_mbmin + episode_max_mbmin) / 2.0
        printf("sanitized_video_min_res=%s\n", min_res)
        printf("sanitized_video_max_res=%s\n", max_res)
        printf("episode_max_mbmin=%s\n", sprintf("%.*f", decimals, episode_max_mbmin))
        printf("sanitized_ep_max_gb=%s\n", trim_float(max_gb, 2))
        printf("sanitized_runtime_min=%s\n", trim_float(runtime, 1))
        printf("sanitized_season_max_gb=%s\n", trim_float(season_cap, 1))
        for (i = 1; i <= warn_count; i++) {
          printf("warn::%s\n", warnings[i])
        }
      }
    '
  )"; then
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
        sanitized_ep_max_gb=*)
          sanitized_ep_max_gb="${line#*=}"
          ;;
        sanitized_runtime_min=*)
          sanitized_runtime_min="${line#*=}"
          ;;
        sanitized_season_max_gb=*)
          sanitized_season_max_gb="${line#*=}"
          ;;
      esac
    done <<<"$policy_eval_output"
  else
    warn "Configarr: failed to evaluate policy heuristics; using defaults"
    sanitized_video_min_res="720p"
    sanitized_video_max_res="1080p"
    episode_max_mbmin="113.8"
    sanitized_ep_max_gb="5"
    sanitized_runtime_min="45"
    sanitized_season_max_gb="30"
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

  msg "Configarr: ${resolution_display}, cap ${sanitized_ep_max_gb} GB (~${episode_max_mbmin} MB/min)"
  msg "Penalties: EN=${configarr_policy[english_bias]}, Multi=${configarr_policy[multi_penalty]}, x265=${configarr_policy[x265_penalty]}, Junk=${configarr_policy[junk_reinforce]}"
}

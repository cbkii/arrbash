# shellcheck disable=SC1090,SC2154
# Alias sanity summary:
# - arr.vpn.* helpers rely on Gluetun's control API via scripts/vpn-gluetun.sh.
# - Template no longer references legacy .arraliases, proxy, or internal CA helpers.
# - Behaviour remains identical for bash and zsh users sourcing the generated file.

ARR_STACK_DIR=${ARR_STACK_DIR:-__ARR_STACK_DIR__}

_arr_alias_current_source_path() {
  if [ -n "${BASH_SOURCE[0]-}" ]; then
    printf '%s\n' "${BASH_SOURCE[0]}"
    return 0
  fi

  if [ -n "${ZSH_VERSION:-}" ]; then
    local zsh_source
    zsh_source=$(eval 'printf %s "${(%):-%N}"' 2>/dev/null || true)
    if [ -n "$zsh_source" ] && [ "$zsh_source" != "zsh" ]; then
      printf '%s\n' "$zsh_source"
      return 0
    fi
  fi

  if [ -n "${0:-}" ]; then
    printf '%s\n' "$0"
    return 0
  fi

  return 1
}

_arr_alias_source_dir() {
  local source_path
  source_path="$(_arr_alias_current_source_path 2>/dev/null || true)"

  if [ -z "$source_path" ]; then
    printf '%s\n' "$(pwd)"
    return 0
  fi

  if [ -d "$source_path" ]; then
    printf '%s\n' "$(cd "$source_path" && pwd)"
    return 0
  fi

  printf '%s\n' "$(cd "$(dirname "$source_path")" && pwd)"
}

if [ -z "${ARR_STACK_DIR:-}" ] || [ "${ARR_STACK_DIR}" = "__ARR_STACK_DIR__" ]; then
  ARR_STACK_DIR="$(_arr_alias_source_dir)"
fi
ARR_ENV_FILE=${ARR_ENV_FILE:-__ARR_ENV_FILE__}
ARR_DOCKER_DIR=${ARR_DOCKER_DIR:-__ARR_DOCKER_DIR__}
ARRCONF_DIR=${ARRCONF_DIR:-__ARRCONF_DIR__}
: "${ARR_ENV_FILE:=${ARR_STACK_DIR}/.env}"
: "${ARR_DOCKER_DIR:=${ARR_STACK_DIR}/dockarr}"
: "${ARRCONF_DIR:=${ARR_STACK_DIR}/arrconf}"

_arr_alias_resolve_var() {
  local name="$1"
  local value=""

  if [ -z "$name" ]; then
    printf '%s' ""
    return 0
  fi

  # shellcheck disable=SC1083
  eval "value=\"\${${name}:-}\""
  printf '%s' "$value"
}

_arr_alias_source_name() {
  local candidate

  candidate="$(_arr_alias_resolve_var "BASH_SOURCE[0]")"
  if [ -n "$candidate" ]; then
    printf '%s' "${candidate##*/}"
    return 0
  fi

  candidate="$(_arr_alias_resolve_var "0")"
  if [ -n "$candidate" ]; then
    printf '%s' "${candidate##*/}"
    return 0
  fi

  printf '%s' ".aliasarr"
}

_arr_alias_template_guard() {
  local source_name="$(_arr_alias_source_name)"
  local name value
  for name in ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR; do
    value="$(_arr_alias_resolve_var "$name")"
    case "$value" in
      __ARR_*__)
        printf 'arr: refusing to source %s because %s is still set to placeholder %s.\n' \
          "${source_name}" "${name}" "${value}" >&2
        printf 'arr: run ./arr.sh --refresh-aliases and source the generated .aliasarr instead.\n' >&2
        return 1
        ;;
    esac
  done
  return 0
}

if ! _arr_alias_template_guard; then
  return 1 2>/dev/null || exit 1
fi

export ARR_STACK_DIR ARR_ENV_FILE ARR_DOCKER_DIR ARRCONF_DIR

if [ -f "$ARR_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ARR_ENV_FILE" 2>/dev/null || true
  set +a

  if [ -z "${GLUETUN_API_KEY:-}" ]; then
    export GLUETUN_API_KEY="$(grep '^GLUETUN_API_KEY=' "$ARR_ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
  if [ -z "${GLUETUN_CONTROL_PORT:-}" ]; then
    export GLUETUN_CONTROL_PORT="$(grep '^GLUETUN_CONTROL_PORT=' "$ARR_ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
  if [ -z "${LOCALHOST_IP:-}" ]; then
    export LOCALHOST_IP="$(grep '^LOCALHOST_IP=' "$ARR_ENV_FILE" | head -n1 | cut -d= -f2- | tr -d '"' | tr -d '\r')"
  fi
fi

_arr_alias_source_if_present() {
  local file="$1"
  [ -f "$file" ] && . "$file"
}

_arr_alias_source_if_present "${ARRCONF_DIR}/userr.conf.defaults.sh"
_arr_alias_source_if_present "${ARRCONF_DIR}/userr.conf"

if command -v arr_set_docker_services_list >/dev/null 2>&1; then
  arr_set_docker_services_list
fi

_arr_gluetun_lib="${ARR_STACK_DIR}/scripts/vpn-gluetun.sh"
if [ -f "${_arr_gluetun_lib}" ]; then
  # shellcheck disable=SC1090
  . "${_arr_gluetun_lib}"
fi
unset _arr_gluetun_lib

if ! command -v msg >/dev/null 2>&1; then
  msg() { printf '%s\n' "$*"; }
fi

if ! command -v warn >/dev/null 2>&1; then
  warn() { printf '[WARN] %s\n' "$*" >&2; }
fi

if ! command -v step >/dev/null 2>&1; then
  step() { msg "$@"; }
fi

_arr_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

_arr_lowercase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

_arr_sanitize_error() {
  local value="$1"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="$(_arr_trim "$value")"
  printf '%s' "$value"
}

_arr_clean_ip_payload() {
  local payload="$1"
  payload="$(printf '%s' "$payload" | tr -d '\r')"
  payload="$(_arr_trim "$payload")"
  printf '%s' "$payload"
}

_arr_extract_public_ip() {
  local payload="$1"
  local value=""

  if [ -z "$payload" ]; then
    return 0
  fi

  value="$(_arr_json_get "$payload" public_ip)"
  if [ -z "$value" ]; then
    value="$(_arr_json_get "$payload" ip)"
  fi

  if [ -z "$value" ]; then
    value="$(printf '%s\n' "$payload" | LC_ALL=C sed -n 's/^"\(.*\)"$/\1/p' | head -n1)"
    # Fallback: strip quotes via parameter expansion if sed didn't remove them
    if [ -z "$value" ] || [ "$value" != "${value#\"}" ] || [ "$value" != "${value%\"}" ]; then
      value="${payload#\"}"
      value="${value%\"}"
    fi
  fi

  if [ -z "$value" ]; then
    value="$payload"
  fi

  value="$(_arr_trim "$value")"
  printf '%s' "$value"
}

_arr_csv_to_array() {
  local input="$1"
  [ -n "$input" ] || return 0
  printf '%s\n' "$input" | awk -F',' '
    {
      for (i = 1; i <= NF; i++) {
        item = $i
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", item)
        if (length(item) > 0) {
          print item
        }
      }
    }
  '
}

_arr_unique_lines() {
  awk 'NF {
    lower = tolower($0)
    if (!seen[lower]++) {
      print $0
    }
  }'
}

_arr_json_get() {
  local payload="$1"
  local key="$2"
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$payload" | jq -r --arg key "$key" '.[$key] // empty' 2>/dev/null
    return
  fi

  local sanitized value
  sanitized="$(printf '%s\n' "$payload" | tr -d '\r')"
  value="$(printf '%s\n' "$sanitized" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\\1/p" | head -n1)"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return
  fi
  value="$(printf '%s\n' "$sanitized" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\\1/p" | head -n1)"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return
  fi
  value="$(printf '%s\n' "$sanitized" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\\1/p" | head -n1)"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
  fi
}

_arr_bool() {
  case "$1" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

_arr_vpn_rotation_state_file() {
  local dir="${ARR_STACK_DIR}/.state"
  mkdir -p "$dir" 2>/dev/null || true
  printf '%s\n' "${dir}/pvpn-rotation.index"
}

_arr_vpn_auto_status_file() {
  printf '%s/.vpn-auto-reconnect-status.json\n' "$ARR_STACK_DIR"
}

_arr_vpn_auto_override_path() {
  local suffix="$1"
  printf '%s/.vpn-auto-reconnect-%s\n' "$ARR_STACK_DIR" "$suffix"
}

_arr_vpn_auto_state_dir() {
  local primary="${ARR_DOCKER_DIR}/gluetun/auto-reconnect"
  if [ -d "$primary" ]; then
    printf '%s\n' "$primary"
    return 0
  fi
  printf '%s\n' "${ARR_STACK_DIR}/dockarr/gluetun/auto-reconnect"
}

_arr_vpn_record_index() {
  local index="$1"
  local file="$(_arr_vpn_rotation_state_file)"
  printf '%s\n' "$index" >"$file"
}

_arr_vpn_read_index() {
  local file="$(_arr_vpn_rotation_state_file)"
  local value
  if [ -f "$file" ]; then
    value="$(cat "$file" 2>/dev/null || true)"
    case "$value" in
      ''|*[!0-9]*) return 1 ;;
      *) printf '%s\n' "$value"; return 0 ;;
    esac
  fi
  return 1
}

_arr_vpn_rotation_candidates() {
  local env_base default_base user_list combined=""
  env_base="$(_arr_env_get SERVER_COUNTRIES 2>/dev/null || true)"
  default_base="${SERVER_COUNTRIES:-}"
  user_list="${PVPN_ROTATE_COUNTRIES:-}"
  if [ -z "$default_base" ]; then
    default_base="Switzerland,Iceland,Romania,Netherlands"
  fi
  local part
  for part in "$user_list" "$env_base" "$default_base"; do
    if [ -n "$part" ]; then
      if [ -n "$combined" ]; then
        combined="${combined},${part}"
      else
        combined="$part"
      fi
    fi
  done
  if [ -z "$combined" ]; then
    combined="Switzerland,Iceland,Romania,Netherlands"
  fi
  _arr_csv_to_array "$combined" | _arr_unique_lines
}

_arr_env_get() {
  local key="$1"
  [[ -f "$ARR_ENV_FILE" ]] || return 1
  awk -F= -v k="$key" '$1==k{print substr($0, index($0,"=")+1); exit}' "$ARR_ENV_FILE"
}

_arr_env_get_list() {
  local key="$1"
  local raw
  raw="$(_arr_env_get "$key" 2>/dev/null || true)"
  [ -n "$raw" ] || return 1

  raw="${raw//,/ }"
  raw="${raw//$'\n'/ }"
  raw="${raw//$'\t'/ }"
  local old_ifs="$IFS"
  IFS=' '
  set -f
  for word in $raw; do
    [ -n "$word" ] || continue
    printf '%s\n' "$word"
  done
  set +f
  IFS="$old_ifs"
}

_arr_loopback() {
  local host
  host="$(_arr_env_get LOCALHOST_IP)"
  if [ -z "$host" ]; then
    host="127.0.0.1"
  fi
  printf '%s' "$host"
}

_arr_services=()
_arr_services_cached=0

_arr_services_populate() {
  if ((_arr_services_cached)); then
    return 0
  fi

  _arr_services=()

  if declare -p ARR_DOCKER_SERVICES >/dev/null 2>&1; then
    # shellcheck disable=SC2154 # ARR_DOCKER_SERVICES may come from sourced config
    if ((${#ARR_DOCKER_SERVICES[@]} > 0)); then
      _arr_services=("${ARR_DOCKER_SERVICES[@]}")
    fi
  fi

  if ((${#_arr_services[@]} == 0)); then
    while IFS= read -r svc; do
      [ -n "$svc" ] || continue
      _arr_services+=("$svc")
    done <<EOF
$(_arr_env_get_list ARR_DOCKER_SERVICES 2>/dev/null || true)
EOF
  fi

  if ((${#_arr_services[@]} == 0)); then
    local services_output
    services_output="$(_arr_compose_services 2>/dev/null || true)"
    if [ -n "$services_output" ]; then
      while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        _arr_services+=("$svc")
      done <<EOF
$services_output
EOF
    fi
  fi

  if ((${#_arr_services[@]} == 0)) && _arr_bool "${SABNZBD_ENABLED:-$(_arr_env_get SABNZBD_ENABLED)}"; then
    _arr_services+=(sabnzbd)
  fi

  _arr_services_cached=1
}

_arr_compose_cmd_cache=()
_arr_compose_cmd_cached=0

_arr_compose_cmd() {
  if ((_arr_compose_cmd_cached)); then
    if ((${#_arr_compose_cmd_cache[@]} > 0)); then
      return 0
    fi
    return 1
  fi

  _arr_compose_cmd_cache=()

  if ((${#DOCKER_COMPOSE_CMD[@]} > 0)) && [ -n "${DOCKER_COMPOSE_CMD[*]}" ]; then
    _arr_compose_cmd_cache=("${DOCKER_COMPOSE_CMD[@]}")
    _arr_compose_cmd_cached=1
    return 0
  fi

  if [ -n "${DOCKER_COMPOSE_CMD:-}" ]; then
    # shellcheck disable=SC2206 # word-splitting is intentional to respect user-provided command
    _arr_compose_cmd_cache=($DOCKER_COMPOSE_CMD)
    if ((${#_arr_compose_cmd_cache[@]} > 0)); then
      _arr_compose_cmd_cached=1
      return 0
    fi
  fi

  if docker compose version >/dev/null 2>&1; then
    _arr_compose_cmd_cache=(docker compose)
    _arr_compose_cmd_cached=1
    return 0
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    _arr_compose_cmd_cache=(docker-compose)
    _arr_compose_cmd_cached=1
    return 0
  fi

  printf 'arr: docker compose command not found.\n' >&2
  _arr_compose_cmd_cached=0
  _arr_compose_cmd_cache=()
  return 1
}

_arr_compose() {
  if ! _arr_compose_cmd; then
    return 1
  fi

  (cd "$ARR_STACK_DIR" && "${_arr_compose_cmd_cache[@]}" "$@" )
}

_arr_compose_services_cache=""
_arr_compose_services_cache_rc=0
_arr_compose_services_cache_init=""

_arr_compose_services() {
  if [ -z "${_arr_compose_services_cache_init}" ]; then
    if _arr_compose_services_cache="$(_arr_compose config --services 2>/dev/null)"; then
      _arr_compose_services_cache_rc=0
    else
      _arr_compose_services_cache_rc=$?
      _arr_compose_services_cache=""
    fi
    _arr_compose_services_cache_init=1
  fi
  printf '%s\n' "${_arr_compose_services_cache}"
}

_arr_service_defined() {
  local svc="$1"
  if [ -z "$svc" ]; then
    return 1
  fi

  local services
  services="$(_arr_compose_services)"
  if [ -n "$services" ]; then
    printf '%s\n' "$services" | grep -Fxq "$svc"
    return $?
  fi

  local fallback
  _arr_services_populate
  for fallback in "${_arr_services[@]}"; do
    if [ "$fallback" = "$svc" ]; then
      return 0
    fi
  done
  return 1
}

_arr_service_container_id() {
  local svc="$1"

  if [ -z "$svc" ]; then
    return 1
  fi

  local id=""
  id="$(_arr_compose ps -q "$svc" 2>/dev/null | head -n1 | tr -d '\r')"

  if [ -z "$id" ]; then
    return 1
  fi

  printf '%s' "$id"
}

_arr_wait_for_container_health() {
  local svc="$1"
  local timeout="${2:-150}"
  local interval="${3:-5}"
  local waited=0
  local container=""

  if [ -z "$svc" ]; then
    return 1
  fi

  while [ "$waited" -lt "$timeout" ]; do
    if [ -z "$container" ]; then
      container="$(_arr_service_container_id "$svc" 2>/dev/null || true)"
      if [ -z "$container" ]; then
        sleep "$interval"
        waited=$((waited + interval))
        continue
      fi
    fi

    local status
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || printf '')"

    case "$status" in
      healthy|running)
        return 0
        ;;
      unhealthy|exited|dead)
        printf 'arr: %s reported status %s while waiting for health.\n' "$container" "$status" >&2
        return 1
        ;;
      '')
        container=""
        ;;
    esac

    sleep "$interval"
    waited=$((waited + interval))
  done

  printf 'arr: timeout while waiting for %s to become healthy.\n' "$container" >&2
  return 1
}

_arr_stack_restart_services() {
  local -a order=()

  _arr_services_populate

  local svc
  for svc in "${_arr_services[@]}"; do
    case "$svc" in
      sabnzbd)
        if _arr_bool "${SABNZBD_ENABLED:-$(_arr_env_get SABNZBD_ENABLED)}"; then
          order+=(sabnzbd)
        fi
        ;;
      qbittorrent|sonarr|radarr|lidarr|prowlarr|bazarr|flaresolverr)
        order+=("$svc")
        ;;
    esac
  done

  printf '%s\n' "${order[@]}"
}

_arr_is_tty() { [ -t 1 ]; }

_arr_host() {
  local host
  host="$(_arr_env_get LAN_IP)"
  if [ -z "$host" ] || [ "$host" = "0.0.0.0" ]; then
    host="$(_arr_loopback)"
  fi
  printf '%s' "$host"
}

_arr_first_available_value() {
  local name value=""
  for name in "$@"; do
    if [ -z "$name" ]; then
      continue
    fi
    # shellcheck disable=SC1083
    eval "value=\"\${${name}:-}\""
    if [ -n "${value:-}" ]; then
      printf '%s' "$value"
      return 0
    fi
    value="$(_arr_env_get "$name" 2>/dev/null || true)"
    if [ -n "${value:-}" ]; then
      printf '%s' "$value"
      return 0
    fi
  done
  return 1
}

_arr_service_port() {
  local svc="$1"
  local value=""
  case "$svc" in
    qbittorrent)
      value="$(_arr_first_available_value QBT_PORT QBT_INT_PORT)"
      ;;
    sonarr)
      value="$(_arr_first_available_value SONARR_PORT SONARR_INT_PORT)"
      ;;
    radarr)
      value="$(_arr_first_available_value RADARR_PORT RADARR_INT_PORT)"
      ;;
    lidarr)
      value="$(_arr_first_available_value LIDARR_PORT LIDARR_INT_PORT)"
      ;;
    prowlarr)
      value="$(_arr_first_available_value PROWLARR_PORT PROWLARR_INT_PORT)"
      ;;
    bazarr)
      value="$(_arr_first_available_value BAZARR_PORT BAZARR_INT_PORT)"
      ;;
    flaresolverr)
      value="$(_arr_first_available_value FLARR_PORT FLARR_INT_PORT)"
      ;;
    sabnzbd)
      value="$(_arr_first_available_value SABNZBD_PORT SABNZBD_INT_PORT)"
      ;;
    *)
      return 1
      ;;
  esac
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return 0
  fi
  return 1
}

_arr_service_base() {
  local svc="$1"
  local host=""
  local port=""

  case "$svc" in
    qbittorrent|sonarr|radarr|lidarr|prowlarr|bazarr|flaresolverr)
      host="$(_arr_host)"
      ;;
    sabnzbd)
      host="${SABNZBD_HOST:-$(_arr_env_get SABNZBD_HOST)}"
      if [ -z "$host" ] || [ "$host" = "0.0.0.0" ]; then
        host="$(_arr_host)"
      fi
      ;;
    *)
      return 1
      ;;
  esac

  if ! port="$(_arr_service_port "$svc")"; then
    return 1
  fi

  printf 'http://%s:%s' "$host" "$port"
}

_arr_url_host() {
  local url="$1"
  url="${url#*://}"
  url="${url%%/*}"
  printf '%s' "$url"
}

_arr_is_ipv4() {
  if [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0   # valid shape
  else
    return 1   # invalid
  fi
}

_arr_curl_resolve_flags() {
  local url="$1" host ip
  host="$(_arr_url_host "$url")"
  ip="$(_arr_host)"
  if [ -z "$host" ] || [ -z "$ip" ]; then
    return 0
  fi
  if _arr_is_ipv4 "$host"; then
    return 0
  fi
  printf '%s\n' --resolve "${host}:80:${ip}" --resolve "${host}:443:${ip}"
}

_arr_has_cmd() { command -v "$1" >/dev/null 2>&1; }

_arr_pretty_json() {
  if _arr_has_cmd jq; then
    jq '.'
  else
    cat
  fi
}

_arr_pretty_guess() {
  local data
  data="$(cat)"
  if [ -z "$data" ]; then
    return 0
  fi
  case "$data" in
    \{*|\[* )
      if _arr_has_cmd jq; then
        printf '%s' "$data" | jq '.'
      else
        printf '%s\n' "$data"
      fi
      ;;
    *)
      printf '%s\n' "$data"
      ;;
  esac
}

_arr_indent() {
  local prefix="${1:-  }"
  sed "s/^/${prefix}/"
}

_arr_section_exec() {
  local title="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    printf '== %s ==\n' "$title"
    if [ -n "$output" ]; then
      printf '%s\n' "$output" | _arr_indent
    fi
    return 0
  else
    local rc=$?
    printf '== %s ==\n' "$title"
    if [ -n "$output" ]; then
      printf '%s\n' "$output" | _arr_indent
    fi
    printf '  (exit %d)\n' "$rc"
    return $rc
  fi
}

_arr_query_suffix_from_args() {
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  local first=1 part
  for part in "$@"; do
    [ -n "$part" ] || continue
    if [ $first -eq 1 ]; then
      printf '?%s' "$part"
      first=0
    else
      printf '&%s' "$part"
    fi
  done
}

_arr_urlencode() {
  local value="$1"
  if _arr_has_cmd jq; then
    printf '%s' "$value" | jq -sRr @uri
    return
  fi
  # Comprehensive URL encoding fallback (POSIX shell)
  local i=1 c hex encoded=""
  while [ $i -le "$(printf '%s' "$value" | wc -c)" ]; do
    c=$(printf '%s' "$value" | cut -c"$i")
    case "$c" in
      [a-zA-Z0-9.~_-]) encoded="$encoded$c" ;;
      *) hex=$(printf '%%%02X' "'$c"); encoded="$encoded$hex" ;;
    esac
    i=$((i + 1))
  done
  printf '%s' "$encoded"
}

_arr_gluetun_port() { printf '%s' "${GLUETUN_CONTROL_PORT:-$(_arr_env_get GLUETUN_CONTROL_PORT || echo 8000)}"; }

_arr_gluetun_host() {
  local host
  host="${GLUETUN_CONTROL_HOST:-$(_arr_env_get GLUETUN_CONTROL_HOST)}"
  if [ -z "$host" ]; then
    host="$(_arr_loopback)"
  fi
  printf '%s' "$host"
}

_arr_gluetun_key() {
  if [ -n "${GLUETUN_API_KEY:-}" ]; then
    printf '%s' "$GLUETUN_API_KEY"
  else
    _arr_env_get GLUETUN_API_KEY
  fi
}

_arr_pf_state_file() {
  local name
  name="$(_arr_env_get PF_ASYNC_STATE_FILE)"
  if [ -z "$name" ]; then
    name="${PF_ASYNC_STATE_FILE:-pf-state.json}"
  fi
  printf '%s/%s' "${ARR_DOCKER_DIR}/gluetun" "$name"
}

_arr_pf_log_file() {
  local name
  name="$(_arr_env_get PF_ASYNC_LOG_FILE)"
  if [ -z "$name" ]; then
    name="${PF_ASYNC_LOG_FILE:-port-forwarding.log}"
  fi
  printf '%s/%s' "${ARR_DOCKER_DIR}/gluetun" "$name"
}

_arr_pf_status_file_path() {
  local path
  path="${PM_STATUS_FILE:-$(_arr_env_get PM_STATUS_FILE 2>/dev/null || echo '')}"
  if [ -z "$path" ]; then
    path="/tmp/gluetun/forwarded_port"
  fi
  printf '%s' "$path"
}

_arr_pf_host_status_file() {
  local status_file
  status_file="$(_arr_pf_status_file_path)"
  if command -v gluetun_port_forward_status_host_path >/dev/null 2>&1; then
    VPN_PORT_FORWARDING_STATUS_FILE="$status_file" gluetun_port_forward_status_host_path
    return
  fi
  printf '%s' "$status_file"
}

_arr_pf_valid_port() {
  case "$1" in
    ''|0|*[!0-9]*) return 1 ;;
    *)
      if [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; then
        return 0
      fi
      return 1
      ;;
  esac
}

_arr_pf_pm_script() {
  local candidate
  candidate="${ARR_STACK_DIR}/scripts/vpn-port-watch.sh"
  if [ -x "$candidate" ]; then
    printf '%s' "$candidate"
    return 0
  fi
  candidate="${ARR_STACK_DIR}/../scripts/vpn-port-watch.sh"
  if [ -x "$candidate" ]; then
    printf '%s' "$candidate"
    return 0
  fi
  warn "vpn-port-watch.sh not found; ensure port-manager helpers are installed"
  return 1
}

_arr_pf_run_once() {
  local override="$1"
  local dry_run="$2"
  local script
  script="$(_arr_pf_pm_script)" || return 1
  local status_file
  status_file="$(_arr_pf_status_file_path)"

  local qbt_user="${QBT_USER:-$(_arr_env_get QBT_USER 2>/dev/null || printf '')}"
  local qbt_pass="${QBT_PASS:-$(_arr_env_get QBT_PASS 2>/dev/null || printf '')}"
  local qbt_web_port="${QBT_WEB_PORT:-$(_arr_env_get QBT_WEB_PORT 2>/dev/null || printf '')}"
  local control_port="${GLUETUN_CONTROL_PORT:-$(_arr_env_get GLUETUN_CONTROL_PORT 2>/dev/null || printf '')}"
  local api_key="${GLUETUN_API_KEY:-$(_arr_env_get GLUETUN_API_KEY 2>/dev/null || printf '')}"
  local qbt_host="${QBT_HOST:-$(_arr_env_get QBT_HOST 2>/dev/null || printf '')}"

  if [ -z "$qbt_host" ]; then
    qbt_host="${LAN_IP:-$(_arr_env_get LAN_IP 2>/dev/null || printf '')}"
  fi
  if [ -z "$qbt_host" ]; then
    qbt_host="${LOCALHOST_IP:-$(_arr_env_get LOCALHOST_IP 2>/dev/null || printf '127.0.0.1')}"
  fi

  if [ -z "$qbt_user" ] || [ -z "$qbt_pass" ]; then
    warn "qBittorrent credentials not available (QBT_USER/QBT_PASS)"
    return 1
  fi
  if [ -z "$qbt_web_port" ]; then
    qbt_web_port=8080
  fi
  if [ -z "$control_port" ]; then
    control_port=8000
  fi

  local -a env_args=(
    "PM_RUN_ONCE=1"
    "PM_STATUS_FILE=${status_file}"
    "QBT_USER=${qbt_user}"
    "QBT_PASS=${qbt_pass}"
    "QBT_WEB_PORT=${qbt_web_port}"
    "QBT_HOST=${qbt_host}"
    "GLUETUN_CONTROL_PORT=${control_port}"
  )

  if [ -n "${api_key}" ]; then
    env_args+=("GLUETUN_API_KEY=${api_key}")
  fi
  if [ -n "${PM_LOG_LEVEL:-}" ]; then
    env_args+=("PM_LOG_LEVEL=${PM_LOG_LEVEL}")
  fi
  if [ -n "$override" ]; then
    env_args+=("PM_OVERRIDE_PORT=${override}")
  fi
  if [ -n "$dry_run" ]; then
    env_args+=("PM_DRY_RUN=${dry_run}")
  fi

  if _arr_docker_available && _arr_compose_cmd; then
    local container_id
    container_id="$(_arr_container_id_for_service port-manager 0 2>/dev/null || printf '')"
    if [ -n "$container_id" ]; then
      if _arr_compose exec port-manager env "${env_args[@]}" /pm-watch.sh; then
        return 0
      fi
      warn "port-manager container exec failed; attempting on-demand run"
    fi

    local -a run_args=(--rm)
    local env_var
    for env_var in "${env_args[@]}"; do
      run_args+=(-e "$env_var")
    done
    if _arr_compose run "${run_args[@]}" port-manager /pm-watch.sh; then
      return 0
    fi
  fi

  env "${env_args[@]}" "$script"
}

_arr_vpn_last_error=""

_arr_docker_available() { command -v docker >/dev/null 2>&1; }

_arr_container_id_for_service() {
  local service="$1"
  local include_stopped="${2:-0}"
  local error_var="${3:-}"

  if [ -z "$service" ]; then
    if [ -n "$error_var" ]; then
      printf -v "$error_var" 'Service name is required.'
    fi
    return 1
  fi

  if ! _arr_docker_available; then
    if [ -n "$error_var" ]; then
      printf -v "$error_var" 'Docker command not available in this shell.'
    fi
    return 1
  fi

  local -a ps_flags=()
  if [ "$include_stopped" = "1" ]; then
    ps_flags=(-a)
  fi

  local id
  id="$(docker ps "${ps_flags[@]}" --filter "label=com.docker.compose.service=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
  if [ -z "$id" ]; then
    id="$(docker ps "${ps_flags[@]}" --filter "name=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
  fi

  if [ -z "$id" ] && [ "$include_stopped" != "1" ]; then
    ps_flags=(-a)
    id="$(docker ps "${ps_flags[@]}" --filter "label=com.docker.compose.service=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
    if [ -z "$id" ]; then
      id="$(docker ps "${ps_flags[@]}" --filter "name=${service}" --format '{{.ID}}' | head -n1 | tr -d '\r')"
    fi
  fi

  if [ -n "$id" ]; then
    printf '%s' "$id"
    return 0
  fi

  if [ -n "$error_var" ]; then
    printf -v "$error_var" 'Unable to locate a container for service %s.' "$service"
  fi

  return 1
}

_arr_vpn_container_id() {
  local include_stopped="${1:-0}"
  _arr_vpn_last_error=""
  if _arr_container_id_for_service gluetun "$include_stopped" _arr_vpn_last_error; then
    return 0
  fi
  if [ -z "${_arr_vpn_last_error:-}" ]; then
    _arr_vpn_last_error="Unable to locate a Gluetun container."
  fi
  return 1
}

_arr_vpn_container_name() {
  local include_stopped="${1:-0}"
  local container
  if ! container="$(_arr_vpn_container_id "$include_stopped" 2>/dev/null || true)"; then
    return 1
  fi
  docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's#^/##'
}

_arr_vpn_container_health_status() {
  local include_stopped="${1:-1}"
  local container
  if ! container="$(_arr_vpn_container_id "$include_stopped" 2>/dev/null || true)"; then
    return 1
  fi
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null
}

_arr_gluetun_last_error=""

_arr_gluetun_api() {
  local endpoint="$1"
  local method="${2:-GET}"
  local data="${3:-}"
  _arr_gluetun_last_error=""

  if ! _arr_has_cmd curl; then
    _arr_gluetun_last_error="curl is not available to query the Gluetun control API."
    return 1
  fi

  local key
  key="$(_arr_gluetun_key)"
  if [ -z "$key" ]; then
    _arr_gluetun_last_error="GLUETUN_API_KEY not found. Run ./arr.sh --rotate-api-key to generate one."
    return 1
  fi

  local port host url
  port="$(_arr_gluetun_port)"
  host="$(_arr_gluetun_host)"
  url="http://${host}:${port}${endpoint}"

  local -a curl_cmd=(curl -fsS -H "X-Api-Key: ${key}")
  if [ "$method" != "GET" ]; then
    curl_cmd+=(-X "$method")
  fi
  if [ -n "$data" ]; then
    curl_cmd+=(-H "Content-Type: application/json" --data "$data")
  fi
  curl_cmd+=("$url")

  local response result
  response="$("${curl_cmd[@]}" 2>&1)"
  result=$?

  if [ $result -eq 0 ]; then
    printf '%s\n' "$response"
    return 0
  fi

  local sanitized_response
  sanitized_response="$(_arr_sanitize_error "$response")"
  if [ -n "$sanitized_response" ]; then
    case "$sanitized_response" in
      curl:*|*Could\ not\ resolve*|*Failed\ to\ connect*|*Connection\ refused*)
        _arr_gluetun_last_error="Unable to reach the Gluetun control API at ${host}:${port}."
        ;;
      *)
        _arr_gluetun_last_error="$sanitized_response"
        ;;
    esac
  else
    _arr_gluetun_last_error="Unable to reach the Gluetun control API at ${host}:${port}."
  fi

  if ! _arr_vpn_container_id >/dev/null 2>&1; then
    if [ -n "${_arr_vpn_last_error:-}" ]; then
      _arr_gluetun_last_error="$(_arr_sanitize_error "${_arr_vpn_last_error}")"
    fi
  fi

  return 1
}

_arr_gluetun_is_transport_error() {
  case "${_arr_gluetun_last_error:-}" in
    ''|Unable\ to\ reach*|Unable\ to\ locate\ a\ Gluetun\ container.*|curl\ is\ not\ available*)
      return 0
      ;;
  esac
  return 1
}

_arr_gluetun_set_openvpn_status() {
  local desired="$1"
  local payload
  payload="{\"status\":\"${desired}\"}"
  if _arr_gluetun_api /v1/openvpn/status PUT "$payload" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

_arr_gluetun_cycle_openvpn() {
  if ! _arr_gluetun_set_openvpn_status stopped; then
    local err
    err="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
    if [ -n "$err" ]; then
      _arr_gluetun_last_error="Unable to stop OpenVPN tunnel via control API: ${err}"
    else
      _arr_gluetun_last_error="Unable to stop OpenVPN tunnel via control API."
    fi
    return 1
  fi

  if command -v sleep >/dev/null 2>&1; then
    sleep 1
  fi

  if ! _arr_gluetun_set_openvpn_status running; then
    local err
    err="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
    if [ -n "$err" ]; then
      _arr_gluetun_last_error="Unable to start OpenVPN tunnel via control API: ${err}"
    else
      _arr_gluetun_last_error="Unable to start OpenVPN tunnel via control API."
    fi
    return 1
  fi

  return 0
}

_arr_qbt_base() { _arr_service_base qbittorrent; }

_arr_qbt_cookie_path() { printf '%s/.qbt_cookies.%s' "${TMPDIR:-/tmp}" "$$"; }

_arr_qbt_login() {
  local user pass base host
  user="${QBT_USER:-$(_arr_env_get QBT_USER)}"
  pass="${QBT_PASS:-$(_arr_env_get QBT_PASS)}"
  if [ -z "$user" ] || [ -z "$pass" ]; then
    echo "qBittorrent credentials missing (set QBT_USER/QBT_PASS)." >&2
    return 1
  fi
  base="$(_arr_qbt_base)"
  host="$(_arr_url_host "$base")"
  local cookie
  cookie="$(_arr_qbt_cookie_path)"
  local -a curl_cmd=(curl -fsS -c "$cookie" -b "$cookie" -d "username=${user}&password=${pass}" "$base/api/v2/auth/login")
  local -a resolve_flags=()
  while IFS= read -r _arr_line; do
    resolve_flags+=("$_arr_line")
  done < <(_arr_curl_resolve_flags "$base") || true
  unset _arr_line
  if [ ${#resolve_flags[@]} -gt 0 ]; then
    local curl_prog=""
    local -a curl_args=()
    local _arr_arg
    for _arr_arg in "${curl_cmd[@]}"; do
      if [ -z "$curl_prog" ]; then
        curl_prog="$_arr_arg"
      else
        curl_args+=("$_arr_arg")
      fi
    done
    curl_cmd=("$curl_prog" "${resolve_flags[@]}" "${curl_args[@]}")
  fi
  "${curl_cmd[@]}" >/dev/null
}

_arr_api_key() {
  local svc="$1"
  local file="${ARR_DOCKER_DIR}/${svc}/config.xml"
  local key

  [ -f "$file" ] || return 1

  key="$(awk '
    /<ApiKey>/ {
      line=$0
      sub(/.*<ApiKey>[[:space:]]*/, "", line)
      sub(/[[:space:]]*<\/ApiKey>.*/, "", line)
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      print line
      exit
    }
  ' "$file" 2>/dev/null)"

  [ -n "$key" ] || return 1
  printf '%s\n' "$key"
}

_arr_service_call() {
  local svc="$1"; shift
  local method="$1"; shift
  local path="$1"; shift
  local base="$(_arr_service_base "$svc")"
  local key="$(_arr_api_key "$svc")"
  if [ -z "$base" ]; then
    echo "Unsupported service: $svc" >&2
    return 1
  fi
  if [ -z "$key" ]; then
    echo "Missing API key for $svc (check ${ARR_DOCKER_DIR}/$svc/config.xml)." >&2
    return 1
  fi
  local -a curl_cmd=(curl -fsS -X "$method" -H "X-Api-Key: ${key}")
  if [ "$method" = "POST" ] || [ "$method" = "PUT" ]; then
    curl_cmd+=(-H 'Content-Type: application/json')
  fi
  local -a resolve_flags=()
  while IFS= read -r _arr_line; do
    resolve_flags+=("$_arr_line")
  done < <(_arr_curl_resolve_flags "$base") || true
  unset _arr_line
  if [ ${#resolve_flags[@]} -gt 0 ]; then
    curl_cmd+=("${resolve_flags[@]}")
  fi
  curl_cmd+=("$@")
  curl_cmd+=("${base}${path}")
  "${curl_cmd[@]}"
}

_arr_bazarr_call() {
  local method="$1"; shift
  local path="$1"; shift
  local base="$(_arr_service_base bazarr)"
  local key="$(_arr_api_key bazarr)"
  if [ -z "$key" ]; then
    echo "Missing Bazarr API key." >&2
    return 1
  fi
  local url="${base}${path}"
  case "$url" in
    *\?*) url="${url}&apikey=${key}" ;;
    *)    url="${url}?apikey=${key}" ;;
  esac
  local -a curl_cmd=(curl -fsS -X "$method")
  local -a resolve_flags=()
  while IFS= read -r _arr_line; do
    resolve_flags+=("$_arr_line")
  done < <(_arr_curl_resolve_flags "$base") || true
  if [ ${#resolve_flags[@]} -gt 0 ]; then
    curl_cmd+=("${resolve_flags[@]}")
  fi
  curl_cmd+=("$@")
  curl_cmd+=("$url")
  "${curl_cmd[@]}"
}

_arr_gluetun_http() {
  local method="$1"; shift
  local endpoint="$1"; shift
  local key="$(_arr_gluetun_key)"
  local port="$(_arr_gluetun_port)"
  local host="$(_arr_gluetun_host)"
  if [ -z "$key" ]; then
    echo "GLUETUN_API_KEY missing." >&2
    return 1
  fi
  curl -fsS -X "$method" -H "X-Api-Key: ${key}" "$@" "http://${host}:${port}${endpoint}"
}

arr.gluetun.help() {
  cat <<'EOF'
Gluetun helpers:
  arr.gluetun.ip             Show VPN egress IP (GET /v1/publicip/ip)
  arr.gluetun.status         Inspect OpenVPN status (GET /v1/openvpn/status)
  arr.gluetun.status.set '{}'  Update OpenVPN status payload (PUT /v1/openvpn/status)
  arr.gluetun.portfwd        Inspect forwarded port (GET /v1/openvpn/portforwarded)
  arr.gluetun.health         Check Gluetun control health (GET /healthz)
EOF
}

arr.gluetun.ip()          { _arr_gluetun_http GET /v1/publicip/ip        | _arr_pretty_guess; }
arr.gluetun.status()      { _arr_gluetun_http GET /v1/openvpn/status     | _arr_pretty_guess; }
arr.gluetun.status.set()  {
  local payload="${1:-{}}"
  _arr_gluetun_http PUT /v1/openvpn/status -H 'Content-Type: application/json' --data "$payload" | _arr_pretty_guess
}
arr.gluetun.portfwd()     { _arr_gluetun_http GET /v1/openvpn/portforwarded | _arr_pretty_guess; }
arr.gluetun.health()      { _arr_gluetun_http GET /healthz              | _arr_pretty_guess; }

arr.compose() { _arr_compose "$@"; }

arr.up() { _arr_compose up -d "$@"; }
arr.down() { _arr_compose down "$@"; }
arr.restart() {
  if [ $# -eq 0 ]; then
    _arr_services_populate
    _arr_compose restart "${_arr_services[@]}"
  else
    _arr_compose restart "$@"
  fi
}
arr.restart.stack() {
  printf '==> Stopping stack containers\n'
  if ! _arr_compose stop >/dev/null 2>&1; then
    printf 'arr: docker compose stop failed; continuing with restart.\n' >&2
  fi

  if ! _arr_compose down --remove-orphans >/dev/null 2>&1; then
    printf 'arr: docker compose down failed; attempting restart anyway.\n' >&2
  fi

  if _arr_service_defined gluetun; then
    printf '==> Starting gluetun (VPN)\n'
    if ! _arr_compose up -d gluetun >/dev/null 2>&1; then
      printf 'arr: failed to start gluetun; aborting restart.\n' >&2
      return 1
    fi

    if ! _arr_wait_for_container_health gluetun 150 5; then
      printf 'arr: gluetun did not become ready; aborting restart.\n' >&2
      return 1
    fi
  else
    printf 'arr: gluetun service not defined in compose configuration; skipping VPN warm-up.\n' >&2
  fi

  local -a desired=()
  while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    if _arr_service_defined "$svc"; then
      desired+=("$svc")
    fi
  done < <(_arr_stack_restart_services)

  local svc
  for svc in "${desired[@]}"; do
    printf '==> Starting %s\n' "$svc"
    if ! _arr_compose up -d "$svc" >/dev/null 2>&1; then
      printf 'arr: failed to start %s; check docker compose logs.\n' "$svc" >&2
      continue
    fi
    sleep 3
  done

  sleep 5

  local -a created_svcs=()
  local -a created_ids=()
  for svc in "${desired[@]}"; do
    local container_id
    container_id="$(_arr_service_container_id "$svc" 2>/dev/null || true)"
    if [ -z "$container_id" ]; then
      continue
    fi
    local status
    status="$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || printf '')"
    if [ "$status" = "created" ]; then
      created_svcs+=("$svc")
      created_ids+=("$container_id")
    fi
  done

  if [ ${#created_svcs[@]} -gt 0 ]; then
    printf 'arr: forcing start for services stuck in created state: %s\n' "${created_svcs[*]}" >&2
    local idx
    for idx in "${!created_svcs[@]}"; do
      local svc_name="${created_svcs[$idx]}"
      if ! _arr_compose start "$svc_name" >/dev/null 2>&1; then
        local container_id="${created_ids[$idx]}"
        docker start "$container_id" >/dev/null 2>&1 || true
      fi
    done
  fi

  printf '==> Stack restart sequence complete. Containers may need additional time to pass health checks.\n'
}
arr.pull() { _arr_compose pull "$@"; }
arr.logs() {
  local -a tail_args=()
  if [ $# -gt 0 ] && [ "${1#*[!0-9]}" = "$1" ]; then
    tail_args=(--tail "$1")
    shift
  fi
  _arr_compose logs "${tail_args[@]}" -f "$@"
}
arr.ps() { _arr_compose ps "$@"; }
arr.stats() {
  _arr_services_populate
  docker stats "${_arr_services[@]}" "$@"
}
arr.shell() {
  local svc="${1:-qbittorrent}"; shift || true
  if _arr_is_tty; then
    docker exec -it "$svc" "${@:-/bin/sh}"
  else
    docker exec -i "$svc" "${@:-/bin/sh}"
  fi
}
arr.health() {
  _arr_services_populate
  local svc container_id status label
  for svc in "${_arr_services[@]}"; do
    label="$svc"
    container_id="$(_arr_service_container_id "$svc" 2>/dev/null || true)"
    if [ -n "$container_id" ]; then
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || printf '')"
    else
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$svc" 2>/dev/null || printf '')"
    fi
    if [ -n "$status" ]; then
      printf '%s: %s\n' "$label" "$status"
    else
      printf '%s: not running\n' "$label"
    fi
  done
}
arr.backup() {
  local dest="${1:-${ARR_STACK_DIR}/backups/$(date +%Y%m%d-%H%M%S)}"
  mkdir -p "$dest"
  _arr_services_populate
  local svc
  for svc in "${_arr_services[@]}"; do
    if [ -d "${ARR_DOCKER_DIR}/${svc}" ]; then
      tar -czf "${dest}/${svc}.tgz" -C "${ARR_DOCKER_DIR}" "$svc"
    fi
  done
  printf 'Backups stored in %s\n' "$dest"
}

arr.compose.config() { _arr_compose config "$@"; }

arr.env.get() {
  if [ -z "${1:-}" ]; then
    printf 'Usage: arr.env.get <KEY>\n' >&2
    return 1
  fi
  local value
  value="$(_arr_env_get "$1")" || true
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return 0
  fi
  return 1
}

arr.env.set() {
  if [ $# -lt 2 ]; then
    printf 'Usage: arr.env.set <KEY> <VALUE>\n' >&2
    return 1
  fi
  local key="$1"
  shift
  local value="$*"
  local tmp
  tmp="$(mktemp)"
  [ -n "$tmp" ] || { echo 'mktemp failed' >&2; return 1; }
  if [ -f "$ARR_ENV_FILE" ]; then
    awk -v k="$key" -v v="$value" '
      BEGIN { done=0 }
      /^[[:space:]]*#/ { print; next }
      $0 ~ ("^" k "=") { print k "=" v; done=1; next }
      { print }
      END { if (!done) print k "=" v }
    ' "$ARR_ENV_FILE" >"$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >"$tmp"
  fi
  if ! mv "$tmp" "$ARR_ENV_FILE"; then
    rm -f "$tmp"
    return 1
  fi
  printf '%s=%s\n' "$key" "$value"
}

arr.env.list() {
  if [ ! -f "$ARR_ENV_FILE" ]; then
    printf 'Missing %s\n' "$ARR_ENV_FILE" >&2
    return 1
  fi
  sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$ARR_ENV_FILE" | sort
}

arr.data.usage() {
  local dirs=()
  if [ ! -d "$ARR_DOCKER_DIR" ]; then
    printf 'Missing %s\n' "$ARR_DOCKER_DIR" >&2
    return 1
  fi
  while IFS= read -r -d '' path; do
    dirs+=("$path")
  done < <(find "$ARR_DOCKER_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
  if [ ${#dirs[@]} -eq 0 ]; then
    printf 'No service data directories found in %s\n' "$ARR_DOCKER_DIR"
    return 0
  fi
  du -sh "${dirs[@]}" 2>/dev/null | sort -h
}

arr.open() {
  local opener=""
  if command -v xdg-open >/dev/null 2>&1; then
    opener=xdg-open
  elif command -v open >/dev/null 2>&1; then
    opener=open
  fi

  local host qbt_port sonarr_port radarr_port lidarr_port prowlarr_port bazarr_port flaresolverr_port
  host="$(_arr_host)"
  qbt_port="${QBT_PORT:-$(_arr_env_get QBT_PORT)}"
  sonarr_port="${SONARR_PORT:-$(_arr_env_get SONARR_PORT)}"
  radarr_port="${RADARR_PORT:-$(_arr_env_get RADARR_PORT)}"
  lidarr_port="${LIDARR_PORT:-$(_arr_env_get LIDARR_PORT)}"
  prowlarr_port="${PROWLARR_PORT:-$(_arr_env_get PROWLARR_PORT)}"
  bazarr_port="${BAZARR_PORT:-$(_arr_env_get BAZARR_PORT)}"
  flaresolverr_port="${FLARR_PORT:-$(_arr_env_get FLARR_PORT)}"

  printf 'Direct service endpoints:\n'
  local -a urls=(
    "qBittorrent" "http://${host}:${qbt_port}"
    "Sonarr" "http://${host}:${sonarr_port}"
    "Radarr" "http://${host}:${radarr_port}"
    "Lidarr" "http://${host}:${lidarr_port}"
    "Prowlarr" "http://${host}:${prowlarr_port}"
    "Bazarr" "http://${host}:${bazarr_port}"
    "FlareSolverr" "http://${host}:${flaresolverr_port}"
  )

  local i=0
  while [ $i -lt ${#urls[@]} ]; do
    local name="${urls[$i]}"
    local url="${urls[$((i + 1))]}"
    printf '  %s -> %s\n' "$name" "$url"
    if [ -n "$opener" ]; then
      "$opener" "$url" >/dev/null 2>&1 &
    fi
    i=$((i + 2))
  done
}

arr.help() {
  cat <<'EOF'
ARR Stack alias help
====================

Core stack management:
  arr.compose [args...]        Run docker compose from ${ARR_STACK_DIR}
  arr.up [services...]         Start the stack (defaults to core services) in detached mode
  arr.down [services...]       Stop services
  arr.restart [services...]    Restart one or more services (defaults to the core set)
  arr.restart.stack            Fully recycle the stack with ordered restart sequencing
  arr.pull [services...]       Pull updated container images
  arr.logs [N] [services...]   Follow compose logs (prefix with a number to set --tail)
  arr.ps                       Show container status via docker compose
  arr.stats                    Stream docker stats for the core containers
  arr.shell [svc] [cmd]        Open an interactive shell inside a container (defaults to qbittorrent)
  arr.health                   Summarise container health checks
  arr.backup [dest]            Create tarball backups of service configs under ARR_DOCKER_DIR
  arr.compose.config [args]    Inspect the rendered docker compose configuration
  arr.open                     Print (and optionally open) service URLs
  arr.data.usage               Report disk usage for each service directory in ${ARR_DOCKER_DIR}

Environment helpers:
  arr.env.get KEY              Read a value from ${ARR_ENV_FILE}
  arr.env.set KEY VALUE        Update or append a key in ${ARR_ENV_FILE}
  arr.env.list                 List non-comment variables from ${ARR_ENV_FILE}

Stack diagnostics:
  arr.all.health               Hit health-ish endpoints across the stack
  arr.all.status               Summarise version/status across services
  arr.all.urls                 Show current base URLs
  arr.check.ports              Quick HTTP reachability checks
  arr.diag.env                 Dump derived environment context (without secrets)

ProtonVPN & Gluetun (arr.vpn ...):
  arr.vpn status               Show the current exit IP and forwarded port
  arr.vpn switch [COUNTRY]     Rotate Proton servers. Without a country it advances through PVPN_ROTATE_COUNTRIES (a superset of SERVER_COUNTRIES)
  arr.vpn connect              Start Gluetun and qBittorrent
  arr.vpn reconnect            Restart the Gluetun container
  arr.vpn logs                 Follow Gluetun logs
  arr.vpn servers [LIMIT]      Display Proton's server catalogue (fallbacks to the local JSON cache)
  arr.vpn countries [LIST]     Show or override SERVER_COUNTRIES in ${ARR_ENV_FILE}
  arr.vpn fastest              Query the top 15 fastest Proton endpoints (requires gluetun CLI)
  arr.vpn.auto.status          Show the auto-reconnect status JSON snapshot
  arr.vpn.auto.pause           Pause monitoring by creating the override file
  arr.vpn.auto.resume          Resume monitoring and clear override files/state
  arr.vpn.auto.kill            Disable auto-reconnect for 24 hours
  arr.vpn.auto.once            Force a single reconnect attempt (clears one-shot flag after use)
  arr.vpn port                 Show the forwarded port (OpenVPN only)
  arr.vpn port.state           Dump the async port-forwarding state JSON
  arr.vpn port.watch           Tail the async worker log (Ctrl+C to stop)
  arr.vpn port.sync            Run a one-shot async port acquisition attempt
  arr.vpn pf                   Dump the forwarded port JSON payload
  arr.vpn ip                   Show the current public IP reported by Gluetun
  arr.vpn health               Print the Gluetun container health status
  arr.vpn paths                Display credential/config paths for ProtonVPN assets
  arr.vpn creds                Open ${ARRCONF_DIR}/proton.auth in $EDITOR for quick edits

Port manager helpers (arr.pf ...):
  arr.pf port                 Print the forwarded port (file first, then control API)
  arr.pf sync                 Run vpn-port-watch.sh once to refresh qBittorrent
  arr.pf tail                 Follow the forwarded port file with timestamps
  arr.pf logs                 Stream port-manager container logs
  arr.pf test <port>          Dry-run an explicit listen_port update

ARR service surfaces:
  arr.gluetun.help             Documented Gluetun control commands
  arr.qbt.help                 qBittorrent Web API helpers
  arr.son.help                 Sonarr v3 API helpers
  arr.rad.help                 Radarr v3 API helpers
  arr.prowl.help               Prowlarr v1 API helpers
  arr.baz.help                 Bazarr API helpers
  arr.fsolv.help               FlareSolverr helpers
  arr.sab.help                 SABnzbd helper commands (if enabled)

Compatibility utilities:
  arr.son.url|logs|restart|refresh|rss
  arr.rad.url|logs|restart|refresh|rss
  arr.prowl.url|logs|restart
  arr.baz.url|logs|restart
  arr.fsolv.url|logs|restart

Legacy prefixes (sonarr, radarr, bazarr, fsolver, flaresolverr, prowlarr) remain as wrappers.
EOF
}

arr.vpn() {
  local raw_action="${1:-status}"
  shift || true
  local action
  action="$(_arr_lowercase "$raw_action")"
  case "$action" in
    connect|c) arr.vpn.connect "$@";;
    reconnect|restart|r) arr.vpn.reconnect "$@";;
    status|s) arr.vpn.status "$@";;
    creds|edit) arr.vpn.creds "$@";;
    port|forward) arr.vpn.port "$@";;
    paths|path) arr.vpn.paths "$@";;
    switch) arr.vpn.switch "$@";;
    servers) arr.vpn.servers "$@";;
    countries|country) arr.vpn.countries "$@";;
    fastest) arr.vpn.fastest "$@";;
    logs) arr.vpn.logs "$@";;
    ip) arr.vpn.ip "$@";;
    pf|portforward|forwarded) arr.vpn.pf "$@";;
    health) arr.vpn.health "$@";;
    help|h)
      printf 'Usage: arr.vpn {status|connect|reconnect|switch|servers|countries|fastest|creds|port|paths|logs|ip|pf|health}\n' >&2
      return 0
      ;;
    *)
      warn "arr.vpn subcommand '${raw_action}' is not available."
      return 1
      ;;
  esac
}

arr.vpn.connect() {
  local -a compose_args=("$@")

  if _arr_compose_cmd >/dev/null 2>&1; then
    if _arr_compose up -d "${compose_args[@]}" gluetun qbittorrent; then
      return 0
    fi
  fi

  if ! _arr_docker_available; then
    warn "Unable to start Gluetun: docker command not available in this shell."
    return 1
  fi

  local container qb_container
  container="$(_arr_vpn_container_id 1 2>/dev/null || printf '')"
  if [ -n "$container" ] && docker start "$container" >/dev/null 2>&1; then
    qb_container="$(_arr_container_id_for_service qbittorrent 1 2>/dev/null || printf '')"
    if [ -n "$qb_container" ]; then
      docker start "$qb_container" >/dev/null 2>&1 || true
    fi
    return 0
  fi

  warn "Unable to start Gluetun via compose; run this command on the host where the stack is installed."
  return 1
}

arr.vpn.reconnect() {
  local force_container=0
  local control_error=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --container|--force-container)
        force_container=1
        shift
        ;;
      --help|-h)
        printf 'Usage: arr.vpn.reconnect [--container]\n' >&2
        return 0
        ;;
      *)
        warn "Unknown flag for arr.vpn.reconnect: $1"
        return 1
        ;;
    esac
  done

  if [ "$force_container" -ne 1 ]; then
    if _arr_gluetun_cycle_openvpn; then
      msg 'Restarted Gluetun OpenVPN tunnel via control API.'
      arr.vpn.status
      return 0
    fi
    control_error="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
  else
    control_error='skipped (forced container restart)'
  fi

  local compose_available=0
  if _arr_compose_cmd >/dev/null 2>&1; then
    compose_available=1
    msg 'Restarting Gluetun via docker compose...'
    if _arr_compose restart gluetun >/dev/null 2>&1; then
      arr.vpn.status
      return 0
    fi
  fi

  local docker_available=0
  local container=""
  if _arr_docker_available; then
    docker_available=1
    container="$(_arr_vpn_container_id 1 2>/dev/null || printf '')"
    if [ -n "$container" ]; then
      msg 'Restarting Gluetun container via docker...'
      if docker restart "$container" >/dev/null 2>&1; then
        arr.vpn.status
        return 0
      fi
    fi
  fi

  local parts
  if [ -n "$control_error" ]; then
    parts="control API: ${control_error}"
  else
    parts="control API unavailable"
  fi

  if [ "$compose_available" -eq 1 ]; then
    parts="${parts}; docker compose restart failed"
  else
    parts="${parts}; docker compose command unavailable"
  fi

  if [ "$docker_available" -eq 1 ]; then
    if [ -n "$container" ]; then
      parts="${parts}; docker restart failed"
    else
      local container_error
      container_error="$(_arr_sanitize_error "${_arr_vpn_last_error:-}")"
      if [ -n "$container_error" ]; then
        parts="${parts}; ${container_error}"
      else
        parts="${parts}; Gluetun container not found"
      fi
    fi
  else
    parts="${parts}; docker command unavailable"
  fi

  parts="$(_arr_trim "$parts")"
  warn "VPN reconnect is not available in this environment (${parts})."
  return 1
}

arr.vpn.status() {
  local status_payload
  if ! status_payload="$(_arr_gluetun_api /v1/openvpn/status 2>/dev/null)"; then
    if _arr_gluetun_is_transport_error; then
      warn 'VPN status is not available in this environment (cannot reach Gluetun control API).'
    else
      local err
      err="$(_arr_sanitize_error "${_arr_gluetun_last_error:-Unable to query Gluetun OpenVPN status.}")"
      warn "$err"
    fi
    return 0
  fi

  local provider
  provider="${VPN_SERVICE_PROVIDER:-$(_arr_env_get VPN_SERVICE_PROVIDER 2>/dev/null || printf '')}"
  provider="$(_arr_trim "$provider")"
  if [ -z "$provider" ]; then
    provider="protonvpn"
  fi
  local provider_display
  case "$(_arr_lowercase "$provider")" in
    protonvpn) provider_display="ProtonVPN" ;;
    *) provider_display="$provider" ;;
  esac

  local countries
  countries="${SERVER_COUNTRIES:-$(_arr_env_get SERVER_COUNTRIES 2>/dev/null || printf '')}"
  countries="$(_arr_trim "$countries")"
  local region_display
  if [ -n "$countries" ]; then
    region_display="$countries"
  else
    region_display="not configured"
  fi
  msg "Provider: ${provider_display} (regions: ${region_display})"

  local tunnel_status
  tunnel_status="$(_arr_json_get "$status_payload" status)"
  tunnel_status="$(_arr_trim "${tunnel_status:-}")"
  if [ -z "$tunnel_status" ]; then
    tunnel_status="unknown"
  fi
  msg "Tunnel status: ${tunnel_status}"

  local ip_payload_raw ip_payload ip_value ip_error
  ip_value=""
  ip_error=""
  if ip_payload_raw="$(_arr_gluetun_api /v1/publicip/ip 2>/dev/null)"; then
    ip_payload="$(_arr_clean_ip_payload "$ip_payload_raw")"
    ip_value="$(_arr_extract_public_ip "$ip_payload")"
  else
    ip_error="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
  fi
  if [ -n "$ip_value" ]; then
    msg "Exit IP: ${ip_value}"
  else
    if [ -n "$ip_error" ]; then
      msg "Exit IP: unavailable (${ip_error})"
    else
      msg 'Exit IP: unavailable'
    fi
  fi

  local vpn_type pf_setting provider_key
  vpn_type="${VPN_TYPE:-$(_arr_env_get VPN_TYPE 2>/dev/null || printf '')}"
  vpn_type="$(_arr_lowercase "$vpn_type")"
  if [ -z "$vpn_type" ]; then
    vpn_type="openvpn"
  fi
  pf_setting="${VPN_PORT_FORWARDING:-$(_arr_env_get VPN_PORT_FORWARDING 2>/dev/null || printf '')}"
  if [ -z "$pf_setting" ]; then
    pf_setting="on"
  fi
  pf_setting="$(_arr_lowercase "$pf_setting")"
  provider_key="$(_arr_lowercase "$provider")"
  local pf_enabled=1
  case "$pf_setting" in
    ''|0|off|false|disabled|no) pf_enabled=0 ;;
  esac

  if [ "$vpn_type" != "openvpn" ] || [ "$provider_key" != "protonvpn" ] || [ "$pf_enabled" -ne 1 ]; then
    msg 'Forwarded port: not available for this configuration'
    return 0
  fi

  local pf_payload pf_port pf_status pf_error
  if pf_payload="$(_arr_gluetun_api /v1/openvpn/portforwarded 2>/dev/null)"; then
    pf_port="$(_arr_json_get "$pf_payload" port)"
    pf_status="$(_arr_json_get "$pf_payload" status)"
    pf_port="$(_arr_trim "${pf_port:-}")"
    pf_status="$(_arr_trim "${pf_status:-}")"
    local port_value=""
    if [ -n "$pf_port" ]; then
      case "$pf_port" in
        ''|*[!0-9]*)
          ;;
        0)
          ;;
        *)
          port_value="$pf_port"
          ;;
      esac
    fi
    if [ -n "$port_value" ]; then
      msg "Forwarded port: ${port_value}"
    else
      if [ -n "$pf_status" ]; then
        msg "Forwarded port: not currently assigned (status: ${pf_status})"
      else
        msg 'Forwarded port: not currently assigned'
      fi
    fi
  else
    pf_error="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
    if [ -n "$pf_error" ]; then
      msg "Forwarded port: unavailable (${pf_error})"
    else
      msg 'Forwarded port: unavailable'
    fi
  fi
}

arr.vpn.creds() { "${EDITOR:-nano}" "${ARRCONF_DIR}/proton.auth"; }

arr.vpn.port() {
  local type="$(_arr_env_get VPN_TYPE)"
  if [ "${type:-openvpn}" != "openvpn" ]; then
    warn 'Port forwarding is only available for OpenVPN configurations.'
    return 1
  fi
  local state_file="$(_arr_pf_state_file)"
  if [ -f "$state_file" ]; then
    local cached_port cached_status
    if command -v jq >/dev/null 2>&1; then
      cached_port="$(jq -r '.port // 0' "$state_file" 2>/dev/null || printf '0')"
      cached_status="$(jq -r '.status // ""' "$state_file" 2>/dev/null || printf '')"
    else
      cached_port="$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$state_file" | head -n1 || printf '0')"
      cached_status="$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state_file" | head -n1 || printf '')"
    fi
    if [ "${cached_port}" != "0" ]; then
      printf '%s\n' "$cached_port"
      return 0
    fi
    if [ -n "$cached_status" ] && [ "$cached_status" != "pending" ]; then
      warn "State: ${cached_status} (see ${state_file})"
    fi
  fi
  local payload summary
  if ! payload="$(_arr_gluetun_api /v1/openvpn/portforwarded 2>/dev/null)"; then
    warn "${_arr_gluetun_last_error:-Unable to query forwarded port.}"
    return 1
  fi
  if command -v gluetun_port_forward_summary >/dev/null 2>&1; then
    summary="$(gluetun_port_forward_summary "$payload" 2>/dev/null || printf '')"
    if [ -n "${GLUETUN_PORT_FORWARD_PORT:-}" ] && [ "${GLUETUN_PORT_FORWARD_PORT}" != "0" ]; then
      printf '%s\n' "$GLUETUN_PORT_FORWARD_PORT"
      return 0
    fi
    if [ -n "$summary" ]; then
      printf '%s\n' "$summary" >&2
    else
      printf '%s\n' "$payload" >&2
    fi
    return 1
  fi
  printf '%s\n' "$payload"
}

arr.vpn.port.state() {
  local file="$(_arr_pf_state_file)"
  if [ ! -f "$file" ]; then
    warn "State file not found: ${file}"
    return 1
  fi
  cat "$file"
}

arr.vpn.port.watch() {
  local file="$(_arr_pf_log_file)"
  local dir
  dir="$(dirname "$file")"
  mkdir -p "$dir"
  if [ ! -f "$file" ]; then
    msg "Creating log placeholder at ${file}"
    : >"$file"
  fi
  tail -n 20 -f "$file"
}

arr.vpn.port.sync() {
  local key
  key="$(_arr_gluetun_key)"
  if [ -z "$key" ]; then
    warn "GLUETUN_API_KEY not found. Run ./arr.sh --rotate-api-key to refresh it."
    return 1
  fi
  ( cd "$ARR_STACK_DIR" && GLUETUN_API_KEY="$key" PF_ASYNC_ENABLE=1 bash -c '. scripts/vpn-gluetun.sh; async_port_forward_worker --oneshot' )
}

arr.vpn.paths() { printf 'Config: %s\nAuth: %s\n' "${ARRCONF_DIR}" "${ARR_DOCKER_DIR}/gluetun"; }

arr.vpn.logs() {
  local container
  container="$(_arr_vpn_container_id 1 2>/dev/null)" || container=""
  if [ -z "$container" ]; then
    warn "${_arr_vpn_last_error:-Unable to locate Gluetun container for log streaming.}"
    return 1
  fi

  if ! _arr_docker_available; then
    warn "Docker command not available in this shell."
    return 1
  fi

  local -a log_args=("$@")
  if [ ${#log_args[@]} -eq 0 ]; then
    log_args=(-f)
  fi

  docker logs "${log_args[@]}" "$container"
}
arr.vpn.ip() {
  local payload
  if ! payload="$(_arr_gluetun_api /v1/publicip/ip 2>/dev/null)"; then
    warn "${_arr_gluetun_last_error:-Unable to query public IP.}"
    return 1
  fi
  if command -v gluetun_public_ip_details >/dev/null 2>&1 && gluetun_public_ip_details "$payload"; then
    printf '%s\n' "$GLUETUN_PUBLIC_IP"
    return 0
  fi
  printf '%s\n' "$payload"
}

arr.vpn.pf() {
  if _arr_gluetun_api /v1/openvpn/portforwarded; then
    printf '\n'
  else
    warn "${_arr_gluetun_last_error:-Unable to query forwarded port payload.}"
    return 1
  fi
}

arr.pf.port() {
  local status_file port
  status_file="$(_arr_pf_status_file_path)"
  port="$(VPN_PORT_FORWARDING_STATUS_FILE="$status_file" gluetun_read_forwarded_port_file 2>/dev/null || printf '')"
  if _arr_pf_valid_port "$port"; then
    printf '%s\n' "$port"
    return 0
  fi
  if command -v fetch_forwarded_port >/dev/null 2>&1; then
    port="$(fetch_forwarded_port 2>/dev/null || printf '0')"
    if _arr_pf_valid_port "$port"; then
      printf '%s\n' "$port"
      return 0
    fi
  fi
  warn 'Forwarded port not available.'
  return 1
}

arr.pf.sync() {
  _arr_pf_run_once "" 0
}

arr.pf.tail() {
  local file
  file="$(_arr_pf_host_status_file)"
  if [ ! -f "$file" ]; then
    warn "Forwarded port file not found yet: ${file}"
  fi
  if ! command -v date >/dev/null 2>&1; then
    tail -f "$file"
    return
  fi
  tail -n 0 -F "$file" | while IFS= read -r line; do
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$line"
  done
}

arr.pf.logs() {
  if ! _arr_docker_available; then
    warn "Docker command not available in this shell."
    return 1
  fi
  local container
  container="$(_arr_container_id_for_service port-manager 1 2>/dev/null || printf '')"
  if [ -z "$container" ]; then
    warn 'port-manager container not found.'
    return 1
  fi
  docker logs -f "$container"
}

arr.pf.test() {
  if [ $# -ne 1 ]; then
    printf 'Usage: arr.pf.test <port>\n' >&2
    return 1
  fi
  local port="$1"
  if ! _arr_pf_valid_port "$port"; then
    warn "Invalid port: ${port}"
    return 1
  fi
  _arr_pf_run_once "$port" 1
}

arr.pf.help() {
  cat <<'EOF'
Port manager helpers:
  arr.pf.port        Show the forwarded port (file first, then Gluetun control API)
  arr.pf.sync        Run a one-shot port sync using vpn-port-watch.sh
  arr.pf.tail        Follow the forwarded port status file with timestamps
  arr.pf.logs        Stream docker logs from the port-manager container
  arr.pf.test <port> Dry-run qBittorrent listen_port update with an explicit port
EOF
}

arr.vpn.health() {
  local container
  container="$(_arr_vpn_container_id 1 2>/dev/null)" || container=""
  if [ -z "$container" ]; then
    warn "${_arr_vpn_last_error:-Unable to locate Gluetun container.}"
    return 1
  fi

  if ! _arr_docker_available; then
    warn "Docker command not available in this shell."
    return 1
  fi

  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || printf 'unknown\n'
}

arr.vpn.servers() {
  local limit="${1:-20}"

  case "$limit" in
    ''|*[!0-9]*) limit=20 ;;
  esac

  local container
  container="$(_arr_vpn_container_id 0 2>/dev/null)" || container=""
  if [ -z "$container" ]; then
    warn "${_arr_vpn_last_error:-Unable to locate Gluetun container.}"
    return 1
  fi

  if ! _arr_docker_available; then
    warn "Docker command not available in this shell."
    return 1
  fi

  if docker exec "$container" /bin/sh -c 'command -v gluetun >/dev/null 2>&1' >/dev/null 2>&1; then
    if docker exec "$container" /bin/sh -c "gluetun servers --format table --limit ${limit}" 2>/dev/null; then
      return 0
    fi
    warn "Unable to query gluetun CLI for server catalog."
    return 1
  fi

  local payload
  payload="$(docker exec "$container" cat /gluetun/servers.json 2>/dev/null || printf '')"
  if [ -z "$payload" ]; then
    warn "Unable to read gluetun server catalog."
    return 1
  fi

  printf '%s\n' "$payload" | awk -v limit="$limit" '
    BEGIN {
      count=0
      name=""
      country=""
      region=""
    }
    /"name"[[:space:]]*:/ {
      name=$0
      sub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", name)
      sub(/".*/, "", name)
    }
    /"country"[[:space:]]*:/ {
      country=$0
      sub(/.*"country"[[:space:]]*:[[:space:]]*"/, "", country)
      sub(/".*/, "", country)
    }
    /"region"[[:space:]]*:/ {
      region=$0
      sub(/.*"region"[[:space:]]*:[[:space:]]*"/, "", region)
      sub(/".*/, "", region)
      if (name != "" && country != "" && region != "") {
        printf "%s - %s (%s)\n", name, country, region
        count++
        if (count >= limit) {
          exit
        }
        name=""
        country=""
        region=""
      }
    }
  ' || {
    warn "Unable to parse server catalog."
    return 1
  }
}

arr.vpn.countries() {
  if [ $# -eq 0 ]; then
    printf 'Current SERVER_COUNTRIES=%s\n' "$(_arr_env_get SERVER_COUNTRIES)"
    return 0
  fi
  local countries="$*"
  local tmp="$(mktemp)"
  if [ -f "$ARR_ENV_FILE" ]; then
    awk -v v="SERVER_COUNTRIES=${countries}" 'BEGIN{done=0} /^SERVER_COUNTRIES=/{print v; done=1; next} {print} END{if(!done)print v}' "$ARR_ENV_FILE" >"$tmp"
    mv "$tmp" "$ARR_ENV_FILE"
    printf 'SERVER_COUNTRIES updated to %s. Restart Gluetun to apply.\n' "$countries"
  else
    printf 'Missing %s\n' "$ARR_ENV_FILE" >&2
    return 1
  fi
}

# Rotation validation:
# - arr.vpn.fastest cycles Gluetun via the documented control server and only falls back to
#   container restarts when that API is unavailable, keeping qBittorrent inside Gluetun's
#   network namespace at all times.
# - arr.vpn.switch defaults to control-only rotation when no target is supplied, updates
#   SERVER_COUNTRIES only when explicitly requested, and forces a container restart so new
#   region filters actually load (previous logic rewrote SERVER_COUNTRIES but reused the
#   control restart, leaving Gluetun on the old region).
# - Both commands surface a single warn on unsupported providers, respect ARR_STACK_DIR by
#   delegating to arr.env.set / arr.vpn.reconnect, and introduce no legacy exposure paths.
arr.vpn.fastest() {
  if _arr_gluetun_cycle_openvpn; then
    msg 'Cycling Gluetun OpenVPN tunnel via control API.'
    arr.vpn.status
    return 0
  fi

  local control_error
  control_error="$(_arr_sanitize_error "${_arr_gluetun_last_error:-}")"
  if [ -n "$control_error" ]; then
    warn "Unable to cycle Gluetun OpenVPN via control API (${control_error})."
  else
    warn 'Unable to cycle Gluetun OpenVPN via control API.'
  fi
  warn 'Falling back to a Gluetun container restart.'
  arr.vpn.reconnect --container
}

arr.vpn.switch() {
  local action="cycle"
  local requested=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --next)
        action="next"
        shift
        ;;
      --help|-h)
        printf 'Usage: arr.vpn.switch [--next|<country>]\n' >&2
        return 0
        ;;
      *)
        action="set"
        requested="$(_arr_trim "$1")"
        shift
        ;;
    esac
  done

  if [ "$action" = "cycle" ]; then
    msg 'Cycling Gluetun within the existing SERVER_COUNTRIES set...'
    return arr.vpn.fastest
  fi

  local candidates_raw
  candidates_raw="$(_arr_vpn_rotation_candidates 2>/dev/null || printf '')"

  local sanitized_candidates=""
  if [ -n "$candidates_raw" ]; then
    local candidate
    while IFS= read -r candidate; do
      candidate="$(_arr_trim "$candidate")"
      [ -n "$candidate" ] || continue
      if [ -n "$sanitized_candidates" ]; then
        sanitized_candidates="${sanitized_candidates}"$'\n'"${candidate}"
      else
        sanitized_candidates="$candidate"
      fi
    done <<<"$candidates_raw"
  fi

  local target=""
  if [ "$action" = "next" ]; then
    if [ -z "$sanitized_candidates" ]; then
      warn 'Region switching / fastest endpoint selection is not implemented for this provider in this build.'
      return 0
    fi
    local count
    count="$(printf '%s\n' "$sanitized_candidates" | awk 'NF{count++} END{print count+0}')"
    if [ "$count" -eq 0 ]; then
      warn 'Region switching / fastest endpoint selection is not implemented for this provider in this build.'
      return 0
    fi
    local last_index
    if ! last_index="$(_arr_vpn_read_index 2>/dev/null)"; then
      last_index=-1
    fi
    case "$last_index" in
      ''|*[!0-9]*) last_index=-1 ;;
    esac
    local next_index=$(((last_index + 1) % count))
    local idx=0
    while IFS= read -r candidate; do
      candidate="$(_arr_trim "$candidate")"
      [ -n "$candidate" ] || continue
      if [ "$idx" -eq "$next_index" ]; then
        target="$candidate"
        break
      fi
      idx=$((idx + 1))
    done <<<"$sanitized_candidates"
    if [ -z "$target" ]; then
      warn 'Region switching / fastest endpoint selection is not implemented for this provider in this build.'
      return 0
    fi
    _arr_vpn_record_index "$next_index"
  else
    local requested_lower
    requested_lower="$(_arr_lowercase "$requested")"
    local idx=0
    if [ -n "$sanitized_candidates" ]; then
      local candidate
      while IFS= read -r candidate; do
        candidate="$(_arr_trim "$candidate")"
        [ -n "$candidate" ] || continue
        if [ "$(_arr_lowercase "$candidate")" = "$requested_lower" ]; then
          target="$candidate"
          _arr_vpn_record_index "$idx"
          break
        fi
        idx=$((idx + 1))
      done <<<"$sanitized_candidates"
    fi
    if [ -z "$target" ]; then
      target="$requested"
    fi
  fi

  target="$(_arr_trim "$target")"
  if [ -z "$target" ]; then
    warn 'Region switching / fastest endpoint selection is not implemented for this provider in this build.'
    return 0
  fi

  local current_countries
  current_countries="$(_arr_trim "${SERVER_COUNTRIES:-$(_arr_env_get SERVER_COUNTRIES 2>/dev/null || printf '')}")"
  local current_lower
  current_lower="$(_arr_lowercase "$current_countries")"
  local target_lower
  target_lower="$(_arr_lowercase "$target")"
  if [ -n "$current_lower" ] && [ "$current_lower" = "$target_lower" ]; then
    msg "SERVER_COUNTRIES already set to ${target}; cycling tunnel within the existing region set."
    return arr.vpn.fastest
  fi

  msg "Switching allowed ProtonVPN region to: ${target}"
  local env_output
  if ! env_output="$(arr.env.set SERVER_COUNTRIES "$target" 2>&1)"; then
    warn "$env_output"
    warn "Failed to update SERVER_COUNTRIES in ${ARR_ENV_FILE}."
    return 1
  fi
  msg "$env_output"
  msg 'Restarting Gluetun to apply the updated region filter...'
  if ! arr.vpn.reconnect --container; then
    warn 'Gluetun restart failed. Apply the change manually if required.'
    return 1
  fi
  return 0
}

arr.vpn.auto.status() {
  local file
  file="$(_arr_vpn_auto_status_file)"
  if [ -f "$file" ]; then
    cat "$file"
  else
    echo "Auto-reconnect status file not found at $file" >&2
    return 1
  fi
}

arr.vpn.auto.pause() {
  local file
  file="$(_arr_vpn_auto_override_path pause)"
  touch "$file"
  echo "Auto-reconnect paused. Remove ${file} or run arr.vpn.auto.resume to resume."
}

arr.vpn.auto.resume() {
  local pause_file kill_file state_dir state_file
  pause_file="$(_arr_vpn_auto_override_path pause)"
  kill_file="$(_arr_vpn_auto_override_path 'kill-24h')"
  rm -f "$pause_file" "$kill_file"
  state_dir="$(_arr_vpn_auto_state_dir)"
  state_file="${state_dir}/state.json"
  if [ -f "$state_file" ]; then
    rm -f "$state_file"
    echo "Cleared auto-reconnect state file at ${state_file}"
  fi
  echo "Auto-reconnect resumed."
}

arr.vpn.auto.kill() {
  local file
  file="$(_arr_vpn_auto_override_path 'kill-24h')"
  touch "$file"
  echo "Auto-reconnect disabled for 24 hours (override file: ${file})."
}

arr.vpn.auto.once() {
  local once_file pause_file
  once_file="$(_arr_vpn_auto_override_path once)"
  pause_file="$(_arr_vpn_auto_override_path pause)"
  rm -f "$pause_file"
  touch "$once_file"
  echo "One-shot reconnect requested via ${once_file}."
}

_arr_qbt_call() {
  local method="$1"; shift
  local endpoint="$1"; shift
  local base="$(_arr_qbt_base)"
  local cookie
  cookie="$(_arr_qbt_cookie_path)"
  local -a resolve_flags=()
  while IFS= read -r _arr_flag; do
    resolve_flags+=("$_arr_flag")
  done < <(_arr_curl_resolve_flags "$base") || true
  unset _arr_flag
  local attempt=0
  while [ $attempt -lt 2 ]; do
    if [ ! -s "$cookie" ]; then
      _arr_qbt_login || return 1
    fi
    local tmp_body http_code
    tmp_body="$(mktemp)" || return 1
    local -a curl_cmd=(curl -sS -X "$method" -o "$tmp_body" -w '%{http_code}' -c "$cookie" -b "$cookie")
    if [ ${#resolve_flags[@]} -gt 0 ]; then
      curl_cmd+=("${resolve_flags[@]}")
    fi
    curl_cmd+=("$@")
    curl_cmd+=("${base}${endpoint}")
    http_code="$("${curl_cmd[@]}")"
    local rc=$?
    if [ $rc -ne 0 ]; then
      rm -f "$tmp_body"
      return $rc
    fi
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
      : >"$cookie"
      rm -f "$tmp_body"
      attempt=$((attempt + 1))
      _arr_qbt_login || return 1
      continue
    fi
    cat "$tmp_body"
    rm -f "$tmp_body"
    case "$http_code" in
      ''|000) return 1 ;;
      2??|3??) return 0 ;;
      *) return 1 ;;
    esac
  done
  echo "qBittorrent request failed after reauthentication attempts." >&2
  return 1
}

arr.qbt.help() {
  cat <<'EOF'
qBittorrent helpers:
  arr.qbt.url                 Show resolved base URL
  arr.qbt.version             Print app version (GET /api/v2/app/version)
  arr.qbt.prefs               Dump preferences JSON (GET /api/v2/app/preferences)
  arr.qbt.setprefs '{...}'    Update preferences JSON (POST /api/v2/app/setPreferences)
  arr.qbt.transfer            Inspect transfer stats (GET /api/v2/transfer/info)
  arr.qbt.torrents.info [q]   List torrents (GET /api/v2/torrents/info)
  arr.qbt.torrents.properties <hash>
  arr.qbt.torrents.files <hash>
  arr.qbt.torrents.trackers <hash>
  arr.qbt.torrents.add.url <url>
  arr.qbt.torrents.add.file <path>
  arr.qbt.torrents.pause [hashes]
  arr.qbt.torrents.resume [hashes]
  arr.qbt.torrents.reannounce [hashes]
  arr.qbt.torrents.recheck [hashes]
  arr.qbt.torrents.delete [hashes] [deleteFiles=false]
  arr.qbt.torrents.setlocation <path> [hashes]
  arr.qbt.torrents.setcategory <category> [hashes]
  arr.qbt.categories          List categories (GET /api/v2/torrents/categories)
  arr.qbt.port.get            Current listen port
  arr.qbt.port.set <port>     Update listen port
  arr.qbt.port.sync           Align listen port with Gluetun forwarded port
  arr.qbt.list                Back-compatible torrent name listing
  arr.qbt.pause.all           Pause all torrents
  arr.qbt.resume.all          Resume all torrents
  arr.qbt.reannounce          Reannounce all torrents
  arr.qbt.limit DL UL         Set download/upload limits (KiB/s)
EOF
}

arr.qbt.url()      { printf '%s\n' "$(_arr_qbt_base)"; }
arr.qbt.version()  { _arr_qbt_call GET /api/v2/app/version; }
arr.qbt.prefs()    { _arr_qbt_call GET /api/v2/app/preferences | _arr_pretty_json; }
arr.qbt.setprefs() {
  local json="${1:-}"
  if [ -z "$json" ]; then
    printf 'Usage: arr.qbt.setprefs <json>\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/app/setPreferences --data-urlencode "json=${json}"
}
arr.qbt.transfer() { _arr_qbt_call GET /api/v2/transfer/info | _arr_pretty_json; }

arr.qbt.torrents.info() {
  local suffix
  suffix="$(_arr_query_suffix_from_args "$@")"
  _arr_qbt_call GET "/api/v2/torrents/info${suffix}" | _arr_pretty_json
}

arr.qbt.torrents.properties() {
  local hash="${1:-}"
  if [ -z "$hash" ]; then
    printf 'Usage: arr.qbt.torrents.properties <hash>\n' >&2
    return 1
  fi
  _arr_qbt_call GET "/api/v2/torrents/properties$(_arr_query_suffix_from_args "hash=${hash}")" | _arr_pretty_json
}

arr.qbt.torrents.files() {
  local hash="${1:-}"
  if [ -z "$hash" ]; then
    printf 'Usage: arr.qbt.torrents.files <hash>\n' >&2
    return 1
  fi
  _arr_qbt_call GET "/api/v2/torrents/files$(_arr_query_suffix_from_args "hash=${hash}")" | _arr_pretty_json
}

arr.qbt.torrents.trackers() {
  local hash="${1:-}"
  if [ -z "$hash" ]; then
    printf 'Usage: arr.qbt.torrents.trackers <hash>\n' >&2
    return 1
  fi
  _arr_qbt_call GET "/api/v2/torrents/trackers$(_arr_query_suffix_from_args "hash=${hash}")" | _arr_pretty_json
}

arr.qbt.torrents.add.url() {
  local url="${1:-}"
  if [ -z "$url" ]; then
    printf 'Usage: arr.qbt.torrents.add.url <torrent-or-magnet>\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/torrents/add --data-urlencode "urls=${url}"
}

arr.qbt.torrents.add.file() {
  local file="${1:-}"
  if [ -z "$file" ]; then
    printf 'Usage: arr.qbt.torrents.add.file <path.torrent>\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/torrents/add -F "torrents=@${file}"
}

arr.qbt.torrents.pause()   { _arr_qbt_call POST /api/v2/torrents/pause --data-urlencode "hashes=${1:-all}"; }
arr.qbt.torrents.resume()  { _arr_qbt_call POST /api/v2/torrents/resume --data-urlencode "hashes=${1:-all}"; }
arr.qbt.torrents.reannounce() { _arr_qbt_call POST /api/v2/torrents/reannounce --data-urlencode "hashes=${1:-all}"; }
arr.qbt.torrents.recheck() { _arr_qbt_call POST /api/v2/torrents/recheck --data-urlencode "hashes=${1:-all}"; }

arr.qbt.torrents.delete() {
  local hashes="${1:-all}"
  local delete_flag="${2:-false}"
  _arr_qbt_call POST /api/v2/torrents/delete --data-urlencode "hashes=${hashes}" --data "deleteFiles=${delete_flag}"
}

arr.qbt.torrents.setlocation() {
  local location="${1:-}"
  if [ -z "$location" ]; then
    printf 'Usage: arr.qbt.torrents.setlocation <path> [hashes]\n' >&2
    return 1
  fi
  local hashes="${2:-all}"
  _arr_qbt_call POST /api/v2/torrents/setLocation --data-urlencode "location=${location}" --data-urlencode "hashes=${hashes}"
}

arr.qbt.torrents.setcategory() {
  local category="${1:-}"
  if [ -z "$category" ]; then
    printf 'Usage: arr.qbt.torrents.setcategory <category> [hashes]\n' >&2
    return 1
  fi
  local hashes="${2:-all}"
  _arr_qbt_call POST /api/v2/torrents/setCategory --data-urlencode "hashes=${hashes}" --data-urlencode "category=${category}"
}

arr.qbt.categories() { _arr_qbt_call GET /api/v2/torrents/categories | _arr_pretty_json; }

arr.qbt.port.get() {
  local json value
  json="$(_arr_qbt_call GET /api/v2/app/preferences 2>/dev/null)" || return 1
  value="$(printf '%s\n' "$json" | sed -n 's/.*"listen_port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
  else
    echo "unknown"
  fi
}

arr.qbt.port.set() {
  if [ -z "$1" ]; then
    printf 'Usage: arr.qbt.port.set <port>\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/app/setPreferences --data "json={\"listen_port\":$1}"
  printf 'Requested port set to %s\n' "$1"
}

arr.qbt.port.sync() {
  local payload port=""
  payload="$(_arr_gluetun_api /v1/openvpn/portforwarded 2>/dev/null || true)"
  if [ -z "$payload" ]; then
    echo 'Unable to query forwarded port.' >&2
    return 1
  fi
  if command -v gluetun_port_forward_details >/dev/null 2>&1 && gluetun_port_forward_details "$payload"; then
    port="$GLUETUN_PORT_FORWARD_PORT"
  else
    port="$(printf '%s\n' "$payload" | grep -oE '[0-9]+' | head -n1 || true)"
  fi
  if [ -z "$port" ] || [ "$port" = "0" ]; then
    echo 'No forwarded port available.'
    return 1
  fi
  arr.qbt.port.set "$port"
}

arr.qbt.list() {
  local output
  output="$(arr.qbt.torrents.info "$@" 2>/dev/null)" || return 1
  if _arr_has_cmd jq; then
    printf '%s' "$output" | jq -r '.[].name'
  else
    printf '%s\n' "$output" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
  fi
}

arr.qbt.pause.all() { arr.qbt.torrents.pause all; }
arr.qbt.resume.all() { arr.qbt.torrents.resume all; }
arr.qbt.reannounce() { arr.qbt.torrents.reannounce all; }

arr.qbt.limit() {
  if [ $# -lt 2 ]; then
    printf 'Usage: arr.qbt.limit <down KiB/s> <up KiB/s>\n' >&2
    return 1
  fi
  _arr_qbt_call POST /api/v2/transfer/setDownloadLimit --data "limit=$1"
  _arr_qbt_call POST /api/v2/transfer/setUploadLimit --data "limit=$2"
}

_arr_service_helper() {
  local svc="$1"; shift
  case "$1" in
    url) printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get "$2")";;
    logs) docker logs -f "$svc";;
    restart) docker restart "$svc";;
    refresh) curl -fsS "http://$(_arr_host):$3/api/command" -X POST -d "name=$4";;
    rss) curl -fsS "http://$(_arr_host):$3/api/command" -X POST -d "name=RssSync";;
    *) printf 'Unsupported command\n' >&2; return 1;;
  esac
}

arr.son.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get SONARR_PORT)"; }
arr.son.logs() { docker logs -f sonarr; }
arr.son.restart() { docker restart sonarr; }
arr.son.refresh() {
  local key="$(_arr_api_key sonarr)"
  if [ -z "$key" ]; then echo 'Sonarr API key unavailable'; return 1; fi
  local host="$(_arr_host)"
  local port="$(_arr_env_get SONARR_PORT)"
  [ -n "$port" ] || port=8989
  curl -fsS -X POST "http://${host}:${port}/api/v3/command" -H "X-Api-Key: ${key}" -H 'Content-Type: application/json' -d '{"name":"RescanFolders"}'
}
arr.son.rss() {
  local key="$(_arr_api_key sonarr)"
  if [ -z "$key" ]; then echo 'Sonarr API key unavailable'; return 1; fi
  local host="$(_arr_host)"
  local port="$(_arr_env_get SONARR_PORT)"
  [ -n "$port" ] || port=8989
  curl -fsS -X POST "http://${host}:${port}/api/v3/command" -H "X-Api-Key: ${key}" -H 'Content-Type: application/json' -d '{"name":"RssSync"}'
}

arr.son.help() {
  cat <<'EOF'
Sonarr helpers:
  arr.son.status             GET /api/v3/system/status
  arr.son.health             GET /api/v3/health
  arr.son.disk               GET /api/v3/diskspace
  arr.son.series.list        GET /api/v3/series
  arr.son.series.get <id>
  arr.son.series.add '{...}'
  arr.son.series.upd <id> '{...}'
  arr.son.series.del <id>
  arr.son.lookup <term>     GET /api/v3/series/lookup
  arr.son.episodes <seriesId>
  arr.son.episode.get <id>
  arr.son.episodefile.list <seriesId>
  arr.son.episodefile.get <id>
  arr.son.calendar <startISO> <endISO>
  arr.son.queue              GET /api/v3/queue
  arr.son.queue.details      GET /api/v3/queue/details
  arr.son.blocklist          GET /api/v3/blocklist
  arr.son.profile.list       GET /api/v3/profile
  arr.son.qualitydef         GET /api/v3/qualitydefinition
  arr.son.root.list          GET /api/v3/rootfolder
  arr.son.remotepath.list    GET /api/v3/remotePathMapping
  arr.son.tag.list           GET /api/v3/tag
  arr.son.command '{...}'    POST /api/v3/command
  arr.son.backups            GET /api/v3/system/backup
EOF
}

arr.son.status()        { _arr_service_call sonarr GET /api/v3/system/status       | _arr_pretty_json; }
arr.son.health()        { _arr_service_call sonarr GET /api/v3/health              | _arr_pretty_json; }
arr.son.disk()          { _arr_service_call sonarr GET /api/v3/diskspace           | _arr_pretty_json; }
arr.son.series.list()   { _arr_service_call sonarr GET /api/v3/series              | _arr_pretty_json; }
arr.son.series.get()    { _arr_service_call sonarr GET "/api/v3/series/${1:?id}" | _arr_pretty_json; }
arr.son.series.add()    { _arr_service_call sonarr POST /api/v3/series --data "${1:?JSON}" | _arr_pretty_json; }
arr.son.series.upd()    { _arr_service_call sonarr PUT "/api/v3/series/${1:?id}" --data "${2:?JSON}" | _arr_pretty_json; }
arr.son.series.del()    { _arr_service_call sonarr DELETE "/api/v3/series/${1:?id}"; }
arr.son.lookup()        {
  local term="$(_arr_urlencode "${1:-}")"
  if [ -z "$term" ]; then
    printf 'Usage: arr.son.lookup <term>\n' >&2
    return 1
  fi
  _arr_service_call sonarr GET "/api/v3/series/lookup?term=${term}" | _arr_pretty_json
}
arr.son.episodes()      { _arr_service_call sonarr GET "/api/v3/episode?seriesId=${1:?seriesId}" | _arr_pretty_json; }
arr.son.episode.get()   { _arr_service_call sonarr GET "/api/v3/episode/${1:?id}" | _arr_pretty_json; }
arr.son.episodefile.list() { _arr_service_call sonarr GET "/api/v3/episodefile?seriesId=${1:?seriesId}" | _arr_pretty_json; }
arr.son.episodefile.get()  { _arr_service_call sonarr GET "/api/v3/episodefile/${1:?id}" | _arr_pretty_json; }
arr.son.calendar() {
  local start="$(_arr_urlencode "${1:-}")" end="$(_arr_urlencode "${2:-}")"
  if [ -z "$start" ] || [ -z "$end" ]; then
    printf 'Usage: arr.son.calendar <startISO> <endISO>\n' >&2
    return 1
  fi
  _arr_service_call sonarr GET "/api/v3/calendar?start=${start}&end=${end}" | _arr_pretty_json
}
arr.son.queue()         { _arr_service_call sonarr GET /api/v3/queue               | _arr_pretty_json; }
arr.son.queue.details() { _arr_service_call sonarr GET /api/v3/queue/details        | _arr_pretty_json; }
arr.son.blocklist()     { _arr_service_call sonarr GET /api/v3/blocklist           | _arr_pretty_json; }
arr.son.profile.list()  { _arr_service_call sonarr GET /api/v3/profile             | _arr_pretty_json; }
arr.son.qualitydef()    { _arr_service_call sonarr GET /api/v3/qualitydefinition   | _arr_pretty_json; }
arr.son.root.list()     { _arr_service_call sonarr GET /api/v3/rootfolder          | _arr_pretty_json; }
arr.son.remotepath.list(){ _arr_service_call sonarr GET /api/v3/remotePathMapping   | _arr_pretty_json; }
arr.son.tag.list()      { _arr_service_call sonarr GET /api/v3/tag                 | _arr_pretty_json; }
arr.son.command()       { _arr_service_call sonarr POST /api/v3/command --data "${1:?JSON}" | _arr_pretty_json; }
arr.son.backups()       { _arr_service_call sonarr GET /api/v3/system/backup       | _arr_pretty_json; }

arr.rad.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get RADARR_PORT)"; }
arr.rad.logs() { docker logs -f radarr; }
arr.rad.restart() { docker restart radarr; }
arr.rad.refresh() {
  local key="$(_arr_api_key radarr)"
  if [ -z "$key" ]; then echo 'Radarr API key unavailable'; return 1; fi
  local host="$(_arr_host)"
  local port="$(_arr_env_get RADARR_PORT)"
  [ -n "$port" ] || port=7878
  curl -fsS -X POST "http://${host}:${port}/api/v3/command" -H "X-Api-Key: ${key}" -H 'Content-Type: application/json' -d '{"name":"RescanMovie"}'
}
arr.rad.rss() {
  local key="$(_arr_api_key radarr)"
  if [ -z "$key" ]; then echo 'Radarr API key unavailable'; return 1; fi
  local host="$(_arr_host)"
  local port="$(_arr_env_get RADARR_PORT)"
  [ -n "$port" ] || port=7878
  curl -fsS -X POST "http://${host}:${port}/api/v3/command" -H "X-Api-Key: ${key}" -H 'Content-Type: application/json' -d '{"name":"RssSync"}'
}

arr.rad.help() {
  cat <<'EOF'
Radarr helpers:
  arr.rad.status             GET /api/v3/system/status
  arr.rad.health             GET /api/v3/health
  arr.rad.disk               GET /api/v3/diskspace
  arr.rad.movies             GET /api/v3/movie
  arr.rad.movie.get <id>
  arr.rad.movie.add '{...}'
  arr.rad.movie.upd <id> '{...}'
  arr.rad.movie.del <id>
  arr.rad.lookup <term>     GET /api/v3/movie/lookup
  arr.rad.moviefile.list    GET /api/v3/moviefile
  arr.rad.moviefile.get <id>
  arr.rad.queue              GET /api/v3/queue
  arr.rad.history            GET /api/v3/history
  arr.rad.blocklist          GET /api/v3/blocklist
  arr.rad.indexers           GET /api/v3/indexer
  arr.rad.downloadclients    GET /api/v3/downloadclient
  arr.rad.profile.list       GET /api/v3/profile
  arr.rad.qualitydef         GET /api/v3/qualitydefinition
  arr.rad.remotepath.list    GET /api/v3/remotePathMapping
  arr.rad.tag.list           GET /api/v3/tag
  arr.rad.command '{...}'    POST /api/v3/command
  arr.rad.backups            GET /api/v3/system/backup
EOF
}

arr.rad.status()        { _arr_service_call radarr GET /api/v3/system/status        | _arr_pretty_json; }
arr.rad.health()        { _arr_service_call radarr GET /api/v3/health               | _arr_pretty_json; }
arr.rad.disk()          { _arr_service_call radarr GET /api/v3/diskspace            | _arr_pretty_json; }
arr.rad.movies()        { _arr_service_call radarr GET /api/v3/movie                | _arr_pretty_json; }
arr.rad.movie.get()     { _arr_service_call radarr GET "/api/v3/movie/${1:?id}"    | _arr_pretty_json; }
arr.rad.movie.add()     { _arr_service_call radarr POST /api/v3/movie --data "${1:?JSON}" | _arr_pretty_json; }
arr.rad.movie.upd()     { _arr_service_call radarr PUT "/api/v3/movie/${1:?id}" --data "${2:?JSON}" | _arr_pretty_json; }
arr.rad.movie.del()     { _arr_service_call radarr DELETE "/api/v3/movie/${1:?id}"; }
arr.rad.lookup()        {
  local term="$(_arr_urlencode "${1:-}")"
  if [ -z "$term" ]; then
    printf 'Usage: arr.rad.lookup <term>\n' >&2
    return 1
  fi
  _arr_service_call radarr GET "/api/v3/movie/lookup?term=${term}" | _arr_pretty_json
}
arr.rad.moviefile.list(){
  if [ -n "${1:-}" ]; then
    _arr_service_call radarr GET "/api/v3/moviefile?movieId=${1}" | _arr_pretty_json
  else
    _arr_service_call radarr GET /api/v3/moviefile | _arr_pretty_json
  fi
}
arr.rad.moviefile.get() { _arr_service_call radarr GET "/api/v3/moviefile/${1:?id}"| _arr_pretty_json; }
arr.rad.queue()         { _arr_service_call radarr GET /api/v3/queue                | _arr_pretty_json; }
arr.rad.history()       { _arr_service_call radarr GET /api/v3/history              | _arr_pretty_json; }
arr.rad.blocklist()     { _arr_service_call radarr GET /api/v3/blocklist            | _arr_pretty_json; }
arr.rad.indexers()      { _arr_service_call radarr GET /api/v3/indexer              | _arr_pretty_json; }
arr.rad.downloadclients(){ _arr_service_call radarr GET /api/v3/downloadclient       | _arr_pretty_json; }
arr.rad.profile.list()  { _arr_service_call radarr GET /api/v3/profile              | _arr_pretty_json; }
arr.rad.qualitydef()    { _arr_service_call radarr GET /api/v3/qualitydefinition    | _arr_pretty_json; }
arr.rad.remotepath.list(){ _arr_service_call radarr GET /api/v3/remotePathMapping    | _arr_pretty_json; }
arr.rad.tag.list()      { _arr_service_call radarr GET /api/v3/tag                  | _arr_pretty_json; }
arr.rad.command()       { _arr_service_call radarr POST /api/v3/command --data "${1:?JSON}" | _arr_pretty_json; }
arr.rad.backups()       { _arr_service_call radarr GET /api/v3/system/backup        | _arr_pretty_json; }

arr.lid.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get LIDARR_PORT)"; }
arr.lid.logs() { docker logs -f lidarr; }
arr.lid.restart() { docker restart lidarr; }
arr.lid.refresh() {
  local key="$(_arr_api_key lidarr)"
  if [ -z "$key" ]; then echo 'Lidarr API key unavailable'; return 1; fi
  local host="$(_arr_host)"
  local port="$(_arr_env_get LIDARR_PORT)"
  [ -n "$port" ] || port=8686
  curl -fsS -X POST "http://${host}:${port}/api/v1/command" -H "X-Api-Key: ${key}" -H 'Content-Type: application/json' -d '{"name":"RescanFolders"}'
}

arr.lid.help() {
  cat <<'EOF'
Lidarr helpers:
  arr.lid.status             GET /api/v1/system/status
  arr.lid.health             GET /api/v1/health
  arr.lid.artist.list        GET /api/v1/artist
  arr.lid.artist.get <id>
  arr.lid.album.list         GET /api/v1/album
  arr.lid.command '{...}'    POST /api/v1/command
  arr.lid.backups            GET /api/v1/system/backup
EOF
}

arr.lid.status()        { _arr_service_call lidarr GET /api/v1/system/status      | _arr_pretty_json; }
arr.lid.health()        { _arr_service_call lidarr GET /api/v1/health             | _arr_pretty_json; }
arr.lid.artist.list()   { _arr_service_call lidarr GET /api/v1/artist            | _arr_pretty_json; }
arr.lid.artist.get()    { _arr_service_call lidarr GET "/api/v1/artist/${1:?id}" | _arr_pretty_json; }
arr.lid.album.list()    { _arr_service_call lidarr GET /api/v1/album             | _arr_pretty_json; }
arr.lid.command()       { _arr_service_call lidarr POST /api/v1/command --data "${1:?JSON}" | _arr_pretty_json; }
arr.lid.backups()       { _arr_service_call lidarr GET /api/v1/system/backup      | _arr_pretty_json; }

arr.prowl.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get PROWLARR_PORT)"; }
arr.prowl.logs() { docker logs -f prowlarr; }
arr.prowl.restart() { docker restart prowlarr; }

arr.prowl.help() {
  cat <<'EOF'
Prowlarr helpers:
  arr.prowl.status             GET /api/v1/system/status
  arr.prowl.health             GET /api/v1/health
  arr.prowl.indexers           GET /api/v1/indexer
  arr.prowl.index.get <id>
  arr.prowl.index.add '{...}'
  arr.prowl.index.upd <id> '{...}'
  arr.prowl.index.del <id>
  arr.prowl.index.schema       GET /api/v1/indexer/schema
  arr.prowl.index.config <id>  GET /api/v1/indexer/<id>/config
  arr.prowl.index.test '{...}' POST /api/v1/indexer/test
  arr.prowl.command '{...}'    POST /api/v1/command
  arr.prowl.log                GET /api/v1/log
  arr.prowl.backups            GET /api/v1/backup
EOF
}

arr.prowl.status()        { _arr_service_call prowlarr GET /api/v1/system/status | _arr_pretty_json; }
arr.prowl.health()        { _arr_service_call prowlarr GET /api/v1/health        | _arr_pretty_json; }
arr.prowl.indexers()      { _arr_service_call prowlarr GET /api/v1/indexer       | _arr_pretty_json; }
arr.prowl.index.get()     { _arr_service_call prowlarr GET "/api/v1/indexer/${1:?id}" | _arr_pretty_json; }
arr.prowl.index.add()     { _arr_service_call prowlarr POST /api/v1/indexer --data "${1:?JSON}" | _arr_pretty_json; }
arr.prowl.index.upd()     { _arr_service_call prowlarr PUT "/api/v1/indexer/${1:?id}" --data "${2:?JSON}" | _arr_pretty_json; }
arr.prowl.index.del()     { _arr_service_call prowlarr DELETE "/api/v1/indexer/${1:?id}"; }
arr.prowl.index.schema()  { _arr_service_call prowlarr GET /api/v1/indexer/schema | _arr_pretty_json; }
arr.prowl.index.config()  { _arr_service_call prowlarr GET "/api/v1/indexer/${1:?id}/config" | _arr_pretty_json; }
arr.prowl.index.test()    { _arr_service_call prowlarr POST /api/v1/indexer/test --data "${1:?JSON}" | _arr_pretty_json; }
arr.prowl.command()       { _arr_service_call prowlarr POST /api/v1/command --data "${1:?JSON}" | _arr_pretty_json; }
arr.prowl.log()           { _arr_service_call prowlarr GET /api/v1/log            | _arr_pretty_json; }
arr.prowl.backups()       { _arr_service_call prowlarr GET /api/v1/backup         | _arr_pretty_json; }

arr.baz.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get BAZARR_PORT)"; }
arr.baz.logs() { docker logs -f bazarr; }
arr.baz.restart() { docker restart bazarr; }

arr.baz.help() {
  cat <<'EOF'
Bazarr helpers:
  arr.baz.info             GET /api/system/info
  arr.baz.series.wanted    GET /api/series/wanted
  arr.baz.series.history   GET /api/series/history
  arr.baz.movies.wanted    GET /api/movies/wanted
  arr.baz.movies.history   GET /api/movies/history
EOF
}

arr.baz.info()           { _arr_bazarr_call GET /api/system/info      | _arr_pretty_json; }
arr.baz.series.wanted()  { _arr_bazarr_call GET /api/series/wanted    | _arr_pretty_json; }
arr.baz.series.history() { _arr_bazarr_call GET /api/series/history   | _arr_pretty_json; }
arr.baz.movies.wanted()  { _arr_bazarr_call GET /api/movies/wanted    | _arr_pretty_json; }
arr.baz.movies.history() { _arr_bazarr_call GET /api/movies/history   | _arr_pretty_json; }

arr.fsolv.url() { printf 'http://%s:%s\n' "$(_arr_host)" "$(_arr_env_get FLARR_PORT)"; }
arr.fsolv.logs() { docker logs -f flaresolverr; }
arr.fsolv.restart() { docker restart flaresolverr; }

arr.fsolv.help() {
  cat <<'EOF'
FlareSolverr helpers:
  arr.fsolv.health          GET /health
  arr.fsolv.solve '{...}'   POST /v1 (JSON payload)
EOF
}

arr.fsolv.health() {
  local base="$(_arr_service_base flaresolverr)"
  local -a cmd=(curl -fsS)
  local -a resolve=()
  while IFS= read -r _arr_resolve; do
    resolve+=("$_arr_resolve")
  done < <(_arr_curl_resolve_flags "$base") || true
  unset _arr_resolve
  if [ ${#resolve[@]} -gt 0 ]; then
    cmd+=("${resolve[@]}")
  fi
  cmd+=("${base}/health")
  "${cmd[@]}" | _arr_pretty_guess
}

arr.fsolv.solve() {
  local payload="${1:-}"
  if [ -z "$payload" ]; then
    printf 'Usage: arr.fsolv.solve <json>\n' >&2
    return 1
  fi
  local base="$(_arr_service_base flaresolverr)"
  local -a cmd=(curl -fsS -X POST -H 'Content-Type: application/json' --data "$payload")
  local -a resolve=()
  while IFS= read -r _arr_resolve; do
    resolve+=("$_arr_resolve")
  done < <(_arr_curl_resolve_flags "$base") || true
  unset _arr_resolve
  if [ ${#resolve[@]} -gt 0 ]; then
    cmd+=("${resolve[@]}")
  fi
  cmd+=("${base}/v1")
  "${cmd[@]}" | _arr_pretty_guess
}

_arr_clone_alias_group() {
  local new_prefix="$1"
  local legacy_prefix="$2"
  shift 2 || true
  local name
  for name in "$@"; do
    # Only allow valid function names: letters, numbers, underscores, dots
    if [[ "$legacy_prefix" =~ ^[a-zA-Z0-9_.]+$ ]] && [[ "$new_prefix" =~ ^[a-zA-Z0-9_.]+$ ]] && [[ "$name" =~ ^[a-zA-Z0-9_.]+$ ]]; then
      eval "arr.${legacy_prefix}.${name}(){ arr.${new_prefix}.${name} \"\$@\"; }"
    else
      printf 'Invalid function name or prefix: legacy_prefix="%s", new_prefix="%s", name="%s"\n' "$legacy_prefix" "$new_prefix" "$name" >&2
    fi
  done
}

_arr_clone_alias_group son sonarr \
  url logs restart refresh rss help status health disk \
  series.list series.get series.add series.upd series.del \
  lookup episodes episode.get episodefile.list episodefile.get \
  calendar queue queue.details blocklist profile.list qualitydef \
  root.list remotepath.list tag.list command backups

_arr_clone_alias_group rad radarr \
  url logs restart refresh rss help status health disk movies \
  movie.get movie.add movie.upd movie.del lookup moviefile.list \
  moviefile.get queue history blocklist indexers downloadclients \
  profile.list qualitydef remotepath.list tag.list command backups

_arr_clone_alias_group lid lidarr \
  url logs restart refresh help status health artist.list artist.get \
  album.list command backups

_arr_clone_alias_group baz bazarr \
  url logs restart help info series.wanted series.history \
  movies.wanted movies.history

_arr_clone_alias_group fsolv fsolver \
  help health solve

_arr_clone_alias_group fsolv flaresolverr \
  url logs restart

_arr_clone_alias_group prowl prowlarr \
  url logs restart

arr.all.health() {
  local rc=0
  _arr_section_exec "Gluetun health" arr.gluetun.health || rc=1
  _arr_section_exec "qBittorrent transfer" arr.qbt.transfer || rc=1
  _arr_section_exec "Sonarr health" arr.son.health || rc=1
  _arr_section_exec "Radarr health" arr.rad.health || rc=1
  _arr_section_exec "Lidarr health" arr.lid.health || rc=1
  _arr_section_exec "Prowlarr health" arr.prowl.health || rc=1
  _arr_section_exec "Bazarr info" arr.baz.info || rc=1
  _arr_section_exec "FlareSolverr health" arr.fsolv.health || rc=1
  return $rc
}

arr.all.status() {
  local rc=0
  _arr_section_exec "Gluetun status" arr.gluetun.status || rc=1
  _arr_section_exec "qBittorrent version" arr.qbt.version || rc=1
  _arr_section_exec "Sonarr status" arr.son.status || rc=1
  _arr_section_exec "Radarr status" arr.rad.status || rc=1
  _arr_section_exec "Lidarr status" arr.lid.status || rc=1
  _arr_section_exec "Prowlarr status" arr.prowl.status || rc=1
  _arr_section_exec "Bazarr info" arr.baz.info || rc=1
  _arr_section_exec "FlareSolverr health" arr.fsolv.health || rc=1
  return $rc
}

arr.all.urls() {
  printf 'Direct service endpoints:\n'
  local svc
  for svc in qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr; do
    printf '  %-13s %s\n' "$svc" "$(_arr_service_base "$svc")"
  done
}

arr.check.ports() {
  local expose="${EXPOSE_DIRECT_PORTS:-$(_arr_env_get EXPOSE_DIRECT_PORTS)}"
  printf 'Checking direct service ports on %s...\n' "$(_arr_host)"
  if [ -n "$expose" ] && ! _arr_bool "$expose"; then
    printf '  Warning: EXPOSE_DIRECT_PORTS=%s (services may be unreachable externally)\n' "$expose"
  fi
  local svc base http rc=0
  for svc in qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr; do
    base="$(_arr_service_base "$svc")"
    local -a cmd=(curl -sS -o /dev/null -w '%{http_code}' --max-time 5)
    local -a resolve=()
    while IFS= read -r _arr_resolve; do
      resolve+=("$_arr_resolve")
    done < <(_arr_curl_resolve_flags "$base") || true
    unset _arr_resolve
    if [ ${#resolve[@]} -gt 0 ]; then
      cmd+=("${resolve[@]}")
    fi
    cmd+=("$base")
    http="$("${cmd[@]}" 2>/dev/null || printf '000')"
    if [ "$http" = "000" ]; then
      printf '  %-13s unavailable\n' "$svc"
      rc=1
    else
      printf '  %-13s HTTP %s\n' "$svc" "$http"
    fi
  done
  return $rc
}

arr.diag.env() {
  local expose="${EXPOSE_DIRECT_PORTS:-$(_arr_env_get EXPOSE_DIRECT_PORTS)}"
  local split_vpn="${SPLIT_VPN:-$(_arr_env_get SPLIT_VPN)}"
  printf 'ARR stack directory: %s\n' "$ARR_STACK_DIR"
  printf 'Environment file:    %s\n' "$ARR_ENV_FILE"
  printf 'Config directory:    %s\n' "$ARRCONF_DIR"
  printf 'Docker data dir:     %s\n' "$ARR_DOCKER_DIR"
  printf 'LAN host/IP:         %s\n' "$(_arr_host)"
  printf 'Direct ports exposed:%s\n' "${expose:-unset}"
  printf 'SPLIT_VPN:           %s\n' "${split_vpn:-unset}"
  printf 'Services:\n'
  local svc
  for svc in gluetun qbittorrent sonarr radarr lidarr prowlarr bazarr flaresolverr; do
    case "$svc" in
      gluetun)
        printf '  %-13s host=%s port=%s key=%s\n' "$svc" "$(_arr_gluetun_host)" "$(_arr_gluetun_port)" "$( [ -n "$(_arr_gluetun_key)" ] && echo 'set' || echo 'missing')"
        ;;
      qbittorrent)
        local user_state="unset"
        if [ -n "${QBT_USER:-$(_arr_env_get QBT_USER)}" ] && [ -n "${QBT_PASS:-$(_arr_env_get QBT_PASS)}" ]; then
          user_state="set"
        fi
        printf '  %-13s url=%s auth=%s\n' "$svc" "$(_arr_service_base qbittorrent)" "$user_state"
        ;;
      *)
        printf '  %-13s url=%s\n' "$svc" "$(_arr_service_base "$svc")"
        ;;
    esac
  done
}

#!/bin/sh
# Lightweight watcher to sync qBittorrent's listen port with ProtonVPN's forwarded port.

set -eu

PM_STATUS_FILE=${PM_STATUS_FILE:-/tmp/gluetun/forwarded_port}
PM_POLL_SECONDS=${PM_POLL_SECONDS:-5}
PM_DRY_RUN=${PM_DRY_RUN:-0}
PM_LOG_LEVEL=${PM_LOG_LEVEL:-info}
PM_RUN_ONCE=${PM_RUN_ONCE:-0}
PM_OVERRIDE_PORT=${PM_OVERRIDE_PORT:-}
QBT_HOST=${QBT_HOST:-127.0.0.1}
QBT_WEB_PORT=${QBT_WEB_PORT:-8080}
QBT_USER=${QBT_USER:-}
QBT_PASS=${QBT_PASS:-}
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT:-8000}
GLUETUN_API_KEY=${GLUETUN_API_KEY:-}

pm_level_value() {
  case "$1" in
    debug) printf '10' ;;
    info) printf '20' ;;
    warn) printf '30' ;;
    error) printf '40' ;;
    *) printf '20' ;;
  esac
}

PM_LOG_THRESHOLD="$(pm_level_value "$PM_LOG_LEVEL")"

pm_should_log() {
  level_value="$(pm_level_value "$1")"
  [ "$level_value" -ge "$PM_LOG_THRESHOLD" ]
}

pm_escape_json() {
  printf '%s' "$1" | tr '\n' ' ' | sed 's/"/\\"/g'
}

pm_timestamp() {
  if command -v date >/dev/null 2>&1; then
    date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date 2>/dev/null || printf 'unknown'
  else
    printf 'unknown'
  fi
}

pm_log() {
  level="$1"
  shift || true
  message="$*"
  if pm_should_log "$level"; then
    printf '[pm] level=%s msg="%s" time="%s"\n' "$level" "$(pm_escape_json "$message")" "$(pm_timestamp)"
  fi
}

pm_is_number() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

if ! pm_is_number "$PM_POLL_SECONDS" || [ "$PM_POLL_SECONDS" -lt 1 ]; then
  PM_POLL_SECONDS=5
fi

if ! pm_is_number "$GLUETUN_CONTROL_PORT" || [ "$GLUETUN_CONTROL_PORT" -le 0 ]; then
  GLUETUN_CONTROL_PORT=8000
fi

if ! pm_is_number "$QBT_WEB_PORT" || [ "$QBT_WEB_PORT" -le 0 ]; then
  QBT_WEB_PORT=8080
fi

if [ -z "$QBT_USER" ] || [ -z "$QBT_PASS" ]; then
  pm_log error "QBT_USER and QBT_PASS must be set"
  exit 1
fi

pm_has_curl() { command -v curl >/dev/null 2>&1; }
pm_has_wget() { command -v wget >/dev/null 2>&1; }

if ! pm_has_curl && ! pm_has_wget; then
  pm_log error "curl or wget is required"
  exit 1
fi

pm_http_get() {
  pm_get_url="$1"
  pm_get_header="${2:-}"
  if pm_has_curl; then
    if [ -n "$pm_get_header" ]; then
      curl -fsS -m 10 -H "$pm_get_header" "$pm_get_url"
    else
      curl -fsS -m 10 "$pm_get_url"
    fi
  elif pm_has_wget; then
    if [ -n "$pm_get_header" ]; then
      wget -q -O - --header "$pm_get_header" "$pm_get_url"
    else
      wget -q -O - "$pm_get_url"
    fi
  else
    return 1
  fi
}

pm_http_post_capture() {
  pm_post_url="$1"
  pm_post_data="$2"
  pm_post_body="$3"
  pm_post_header_file="$4"
  shift 4 || true

  pm_headers_tmp=""
  if [ "$#" -gt 0 ]; then
    pm_headers_tmp="$(mktemp "${TMPDIR:-/tmp}/pm-headers.XXXXXX" 2>/dev/null || mktemp /tmp/pm-headers.XXXXXX)"
    if [ -z "$pm_headers_tmp" ] || [ ! -w "$pm_headers_tmp" ]; then
      pm_log error "unable to create temporary header file"
      return 1
    fi
    while [ "$#" -gt 0 ]; do
      pm_header="$1"
      shift || true
      [ -n "$pm_header" ] || continue
      printf '%s\n' "$pm_header" >>"$pm_headers_tmp"
    done
  fi

  if pm_has_curl; then
    set -- curl -fsS -m 10 -D "$pm_post_header_file" -o "$pm_post_body"
    if [ -n "$pm_headers_tmp" ] && [ -f "$pm_headers_tmp" ]; then
      while IFS= read -r pm_header; do
        [ -n "$pm_header" ] || continue
        set -- "$@" -H "$pm_header"
      done <"$pm_headers_tmp"
    fi
    set -- "$@" --data "$pm_post_data" "$pm_post_url"
    "$@"
    pm_status=$?
  elif pm_has_wget; then
    set -- wget -q -S -O "$pm_post_body"
    if [ -n "$pm_headers_tmp" ] && [ -f "$pm_headers_tmp" ]; then
      while IFS= read -r pm_header; do
        [ -n "$pm_header" ] || continue
        set -- "$@" --header "$pm_header"
      done <"$pm_headers_tmp"
    fi
    set -- "$@" --post-data "$pm_post_data" "$pm_post_url"
    "$@" 2>"$pm_post_header_file"
    pm_status=$?
  else
    pm_status=1
  fi

  if [ -n "$pm_headers_tmp" ]; then
    rm -f "$pm_headers_tmp"
  fi

  return "$pm_status"
}

pm_extract_status() {
  pm_header_file="$1"
  if [ ! -f "$pm_header_file" ]; then
    return 1
  fi
  pm_status=$(awk '/^HTTP\//{code=$2} /^  HTTP\//{code=$2} END{if(code!=""){print code}}' "$pm_header_file" 2>/dev/null || true)
  if [ -n "$pm_status" ]; then
    printf '%s' "$pm_status"
    return 0
  fi
  return 1
}

pm_login() {
  pm_login_url="http://${QBT_HOST}:${QBT_WEB_PORT}/api/v2/auth/login"
  pm_payload="username=${QBT_USER}&password=${QBT_PASS}"
  pm_body_file="$(mktemp "${TMPDIR:-/tmp}/pm-login-body.XXXXXX" 2>/dev/null || mktemp /tmp/pm-login-body.XXXXXX)"
  pm_header_file="$(mktemp "${TMPDIR:-/tmp}/pm-login-header.XXXXXX" 2>/dev/null || mktemp /tmp/pm-login-header.XXXXXX)"
  if ! pm_http_post_capture "$pm_login_url" "$pm_payload" "$pm_body_file" "$pm_header_file" "Content-Type: application/x-www-form-urlencoded"; then
    rm -f "$pm_body_file" "$pm_header_file"
    return 1
  fi
  pm_status="$(pm_extract_status "$pm_header_file" || true)"
  pm_cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: SID=\([^;]*\).*/\1/p' "$pm_header_file" | head -n1 | tr -d '\r')
  rm -f "$pm_body_file" "$pm_header_file"
  if [ "$pm_status" != "200" ] || [ -z "$pm_cookie" ]; then
    return 1
  fi
  printf '%s' "$pm_cookie"
  return 0
}

pm_set_port() {
  pm_cookie="$1"
  pm_new_port="$2"
  pm_url="http://${QBT_HOST}:${QBT_WEB_PORT}/api/v2/app/setPreferences"
  pm_data="json={\"listen_port\":${pm_new_port},\"random_port\":false}"
  pm_header_file="$(mktemp "${TMPDIR:-/tmp}/pm-set-header.XXXXXX" 2>/dev/null || mktemp /tmp/pm-set-header.XXXXXX)"
  if pm_http_post_capture "$pm_url" "$pm_data" /dev/null "$pm_header_file" "Cookie: SID=${pm_cookie}" "Content-Type: application/x-www-form-urlencoded"; then
    pm_status="$(pm_extract_status "$pm_header_file" || true)"
    rm -f "$pm_header_file"
    [ "$pm_status" = "200" ]
    return
  fi
  rm -f "$pm_header_file"
  return 1
}

pm_valid_port() {
  pm_candidate="$1"
  if pm_is_number "$pm_candidate" && [ "$pm_candidate" -ge 1 ] && [ "$pm_candidate" -le 65535 ]; then
    return 0
  fi
  return 1
}

pm_read_port_file() {
  if [ ! -f "$PM_STATUS_FILE" ]; then
    return 1
  fi
  pm_value=$(sed -n '1s/^[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PM_STATUS_FILE" | head -n1 | tr -d '\r')
  if pm_valid_port "$pm_value"; then
    printf '%s' "$pm_value"
    return 0
  fi
  return 1
}

pm_fetch_control_port() {
  pm_header=""
  if [ -n "$GLUETUN_API_KEY" ]; then
    pm_header="X-Api-Key: ${GLUETUN_API_KEY}"
  fi
  pm_response=$(pm_http_get "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" "$pm_header" 2>/dev/null || true)
  pm_port=$(printf '%s' "$pm_response" | tr -d '\r\n' | sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
  if pm_valid_port "$pm_port"; then
    printf '%s' "$pm_port"
    return 0
  fi
  return 1
}

pm_acquire_port() {
  if [ -n "$PM_OVERRIDE_PORT" ]; then
    if pm_valid_port "$PM_OVERRIDE_PORT"; then
      printf '%s' "$PM_OVERRIDE_PORT"
      return 0
    fi
    return 1
  fi
  if pm_read_port_file; then
    return 0
  fi
  pm_fetch_control_port
}

pm_apply_port() {
  pm_target="$1"
  if [ "$PM_DRY_RUN" = "1" ]; then
    printf 'json={"listen_port":%s,"random_port":false}\n' "$pm_target"
    pm_log info "dry-run: updated qBittorrent listen_port to $pm_target"
    return 0
  fi
  pm_delay=2
  pm_attempt=1
  while [ $pm_attempt -le 3 ]; do
    pm_cookie=$(pm_login 2>/dev/null || true)
    if [ -n "$pm_cookie" ] && pm_set_port "$pm_cookie" "$pm_target"; then
      pm_log info "updated qBittorrent listen_port to $pm_target"
      return 0
    fi
    if [ $pm_attempt -ge 3 ]; then
      pm_log error "failed to update qBittorrent listen_port to $pm_target"
      return 1
    fi
    pm_log warn "qBittorrent update attempt $pm_attempt failed; retrying in ${pm_delay}s"
    sleep "$pm_delay"
    pm_delay=$((pm_delay * 2))
    pm_attempt=$((pm_attempt + 1))
  done
  return 1
}

pm_last_port=""
pm_log info "port-manager watcher started (poll=${PM_POLL_SECONDS}s)"

while :; do
  pm_port="$(pm_acquire_port 2>/dev/null || true)"
  if pm_valid_port "$pm_port"; then
    if [ "$pm_port" != "$pm_last_port" ]; then
      if pm_apply_port "$pm_port"; then
        pm_last_port="$pm_port"
      fi
    fi
  else
    pm_log warn "no forwarded port available"
  fi
  if [ "$PM_RUN_ONCE" = "1" ]; then
    break
  fi
  sleep "$PM_POLL_SECONDS"
done

exit 0

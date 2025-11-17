# shellcheck shell=bash
# shellcheck disable=SC2250

: "${ARR_PORT_PROBE_TOOL:=}"

__ARR_PORT_PROBE_CACHE_READY=0
__ARR_PORT_PROBE_SELF_READY=0

declare -A __ARR_PORT_PROBE_LISTENERS=()
declare -A __ARR_PORT_PROBE_SELF=()

_arr_port_identity() {
  local host

  host="$(normalize_bind_address "${1:-*}")"

  case "${host}" in
    ''|'*'|'0.0.0.0'|'::')
      printf '*\n'
      ;;
    *)
      printf '%s\n' "${host,,}"
      ;;
  esac
}

arr_port_probe_invalidate() {
  __ARR_PORT_PROBE_CACHE_READY=0
  __ARR_PORT_PROBE_SELF_READY=0
  __ARR_PORT_PROBE_LISTENERS=()
  __ARR_PORT_PROBE_SELF=()
}

__arr_port_probe_detect_tool() {
  local tool

  if [[ -n "${ARR_PORT_PROBE_TOOL}" ]] && have_command "${ARR_PORT_PROBE_TOOL}"; then
    return 0
  fi

  for tool in ss lsof netstat; do
    if have_command "$tool"; then
      ARR_PORT_PROBE_TOOL="$tool"
      return 0
    fi
  done

  ARR_PORT_PROBE_TOOL=""
  return 2
}

__arr_port_probe_record() {
  local proto="$1"
  local port="$2"
  local identity="$3"
  local host="$4"
  local pid="$5"
  local process="$6"
  local key="${proto}|${port}"

  local entry
  entry="${identity}\t${host}\t${pid}\t${process}"

  if [[ -n "${__ARR_PORT_PROBE_LISTENERS[$key]:-}" ]]; then
    __ARR_PORT_PROBE_LISTENERS[$key]+=$'\n'"${entry}"
  else
    __ARR_PORT_PROBE_LISTENERS[$key]="${entry}"
  fi
}

__arr_port_probe_collect_ss() {
  local proto local_addr pid process host port normalized identity

  while IFS='|' read -r proto local_addr pid process; do
    [[ -z "$local_addr" ]] && continue
    proto="${proto,,}"
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
      continue
    fi
    host="${local_addr%:*}"
    port="${local_addr##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    normalized="$(normalize_bind_address "$host")"
    identity="$(_arr_port_identity "$normalized")"
    __arr_port_probe_record "$proto" "$port" "$identity" "$normalized" "$pid" "$process"
  done < <(ss -H -lnptu 2>/dev/null | awk '{
      proto=$1
      local_field=$5
      if (local_field == "") { next }
      gsub(/\[|\]/, "", local_field)
      pid=""; proc=""
      if (match($0, /pid=([0-9]+)/, m)) { pid=m[1] }
      if (match($0, /"([^"]+)"/, m2)) { proc=m2[1] }
      printf "%s|%s|%s|%s\n", proto, local_field, pid, proc
    }')
}

__arr_port_probe_collect_lsof() {
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null |
    awk 'NR>1 {
      addr=$9; pid=$2; proc=$1;
      if (addr == "" || pid == "" || proc == "") { next }
      sub(/\(LISTEN\)/, "", addr)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", addr)
      printf "tcp|%s|%s|%s\n", addr, pid, proc
    }'
  lsof -nP -iUDP 2>/dev/null |
    awk 'NR>1 {
      addr=$9; pid=$2; proc=$1;
      if (addr == "" || pid == "" || proc == "") { next }
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", addr)
      printf "udp|%s|%s|%s\n", addr, pid, proc
    }'
}

__arr_port_probe_collect_netstat() {
  netstat -tunlp 2>/dev/null |
    awk 'NR>2 {
      proto=tolower($1)
      if (proto != "tcp" && proto != "udp") { next }
      local_field=$4
      if (local_field == "") { next }
      if (!match(local_field, /(.*):([0-9]+)$/, m)) { next }
      host=m[1]
      port=m[2]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", host)
      pid=""; proc=""
      if ($7 ~ /^[0-9]+\/[^[:space:]]+$/) {
        split($7, idparts, "/")
        pid=idparts[1]
        proc=idparts[2]
      }
      printf "%s|%s:%s|%s|%s\n", proto, host, port, pid, proc
    }'
}

__arr_port_probe_collect() {
  local rc=0

  if ((__ARR_PORT_PROBE_CACHE_READY)); then
    return 0
  fi

  __ARR_PORT_PROBE_LISTENERS=()

  if ! __arr_port_probe_detect_tool; then
    return 2
  fi

    case "${ARR_PORT_PROBE_TOOL}" in
    ss)
      if ! __arr_port_probe_collect_ss; then
        rc=1
      fi
      ;;
    lsof)
        while IFS='|' read -r proto local_addr pid process; do
          [[ -z "${local_addr}" ]] && continue
          local addr="${local_addr%%[[:space:]]*}"
          addr="${addr%%->*}"
          local host="${addr%:*}"
          local port="${addr##*:}"
          [[ "${port}" =~ ^[0-9]+$ ]] || continue
          host="${host#[}"
          host="${host%]}"
          local normalized
          normalized="$(normalize_bind_address "${host}")"
          local identity
          identity="$(_arr_port_identity "${normalized}")"
          __arr_port_probe_record "${proto}" "${port}" "${identity}" "${normalized}" "${pid}" "${process}"
      done < <(__arr_port_probe_collect_lsof)
      ;;
    netstat)
        while IFS='|' read -r proto local_addr pid process; do
          [[ -z "${local_addr}" ]] && continue
          proto="${proto,,}"
          if [[ "${proto}" != "tcp" && "${proto}" != "udp" ]]; then
            continue
          fi
          local host="${local_addr%:*}"
          local port="${local_addr##*:}"
          [[ "${port}" =~ ^[0-9]+$ ]] || continue
          local normalized
          normalized="$(normalize_bind_address "${host}")"
          local identity
          identity="$(_arr_port_identity "${normalized}")"
          process="${process##*/}"
          pid="${pid%%/*}"
          __arr_port_probe_record "${proto}" "${port}" "${identity}" "${normalized}" "${pid}" "${process}"
        done < <(__arr_port_probe_collect_netstat)
        ;;
    esac

    if ((rc != 0)); then
      return "${rc}"
    fi

  __ARR_PORT_PROBE_CACHE_READY=1
  return 0
}

__arr_port_probe_refresh_self() {
  if ((__ARR_PORT_PROBE_SELF_READY)); then
    return 0
  fi

  __ARR_PORT_PROBE_SELF=()
  __ARR_PORT_PROBE_SELF_READY=1

  if ! have_command docker; then
    return 0
  fi

  local project=""
  if declare -f arr_effective_project_name >/dev/null 2>&1; then
    project="$(arr_effective_project_name 2>/dev/null || true)"
  fi
    if [[ -z "${project}" && -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
      project="${COMPOSE_PROJECT_NAME}"
    fi
    if [[ -z "${project}" ]]; then
      project="${STACK:-arr}"
    fi

  while IFS='|' read -r cid service ports; do
    [[ -z "${service}" ]] && continue
    [[ -z "${ports}" ]] && continue
    IFS=',' read -ra entries <<<"${ports}"
    local entry host_part target proto host port identity key
    for entry in "${entries[@]}"; do
      entry="$(printf '%s' "${entry}" | xargs 2>/dev/null || printf '%s' "${entry}")"
      [[ "${entry}" == *"->"* ]] || continue
      host_part="${entry%%->*}"
      target="${entry##*->}"
      proto="${target##*/}"
      proto="${proto,,}"
      if [[ "${proto}" != "tcp" && "${proto}" != "udp" ]]; then
        continue
      fi
      if [[ "${host_part}" == *":"* ]]; then
        host="${host_part%:*}"
        port="${host_part##*:}"
      else
        host="*"
        port="${host_part}"
      fi
      [[ "${port}" =~ ^[0-9]+$ ]] || continue
      host="${host#[}"
      host="${host%]}"
      host="$(normalize_bind_address "${host}")"
      identity="$(_arr_port_identity "${host}")"
      key="${proto}|${port}|${identity}"
        __ARR_PORT_PROBE_SELF[${key}]="${cid}|${service}"
    done
  done < <(docker ps --filter "label=com.docker.compose.project=${project}" --format '{{.ID}}|{{.Label "com.docker.compose.service"}}|{{.Ports}}' 2>/dev/null || true)
}

__arr_port_probe_is_self() {
  local proto="$1"
  local port="$2"
  local identity="$3"

  __arr_port_probe_refresh_self || true

  local key="${proto}|${port}|${identity}"
    [[ -n "${__ARR_PORT_PROBE_SELF[${key}]:-}" ]]
}

arr_port_probe_conflicts() {
  local proto="${1,,}"
  local port="$2"
  local details_name="${3:-}"
  local desired="${4:-*}"
  local rc=0

    if [[ -n "${details_name}" ]]; then
      printf -v "${details_name}" '%s' ""
    fi

    if [[ -z "${proto}" || -z "${port}" || ! "${port}" =~ ^[0-9]+$ ]]; then
      return 1
    fi

  if ! __arr_port_probe_collect; then
    rc=$?
    if ((rc == 2)); then
      return 2
    fi
    return 2
  fi

  local key="${proto}|${port}"
    local entries_raw="${__ARR_PORT_PROBE_LISTENERS[${key}]:-}"
    if [[ -z "${entries_raw}" ]]; then
      return 1
    fi

  local desired_norm
    desired_norm="$(normalize_bind_address "${desired}")"

  local -a matches=()
    while IFS=$'\t' read -r identity host pid process; do
      [[ -z "${host}" ]] && continue
      if ! address_conflicts "${desired_norm}" "${host}"; then
        continue
      fi
      if __arr_port_probe_is_self "${proto}" "${port}" "${identity}"; then
        continue
      fi
      local detail="${proto^^} ${host}:${port}"
      if [[ -n "${process}" || -n "${pid}" ]]; then
        detail+=" ("
        if [[ -n "${process}" ]]; then
          detail+="${process}"
        fi
        if [[ -n "${pid}" ]]; then
          if [[ -n "${process}" ]]; then
            detail+=" pid ${pid}"
          else
            detail+="pid ${pid}"
          fi
        fi
        detail+=")"
      fi
      matches+=("${detail}")
    done <<<"${entries_raw}"

  if ((${#matches[@]} == 0)); then
    return 1
  fi

    if [[ -n "${details_name}" ]]; then
      printf -v "${details_name}" '%s' "$(printf '%s\n' "${matches[@]}")"
  fi

  return 0
}

port_bound_any() {
  local proto="${1,,}"
  local port="$2"
  local _unused=""

  if arr_port_probe_conflicts "${proto}" "${port}" _unused; then
    return 0
  fi

  local rc=$?
  if ((rc == 2)); then
    return 1
  fi

  return 1
}
# shellcheck disable=SC2034
ARR_PORT_PROBE_LIB_SOURCED=1

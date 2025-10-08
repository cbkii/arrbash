# shellcheck shell=bash
# Opt-in structured xtrace to file with basic secret-masking.
# Usage:
#   export ARR_TRACE=1                       # or pass --trace to arr.sh (see patch)
#   export ARR_TRACE_DEBUG=0|1               # (optional) also log each simple command via DEBUG trap
#   export ARR_TRACE_FILE=/path/to/log       # (optional) override default
#   export ARR_TRACE_MASK_RE='regex|to|mask' # (optional) add extra masking patterns

arr_trace_start() {
  local base_log="${LOG_FILE:-}" trace_file=""

  if [[ -z "$base_log" ]]; then
    local log_dir timestamp stack_name
    if declare -f arr_log_dir >/dev/null 2>&1; then
      log_dir="$(arr_log_dir)"
    elif [[ -n "${ARR_LOG_DIR:-}" ]]; then
      log_dir="${ARR_LOG_DIR%/}"
    elif declare -f arr_stack_dir >/dev/null 2>&1; then
      log_dir="$(arr_stack_dir)/logs"
    elif [[ -n "${ARR_STACK_DIR:-}" ]]; then
      log_dir="${ARR_STACK_DIR%/}/logs"
    else
      log_dir="${REPO_ROOT:-.}/logs"
    fi

    if declare -f ensure_dir_mode >/dev/null 2>&1; then
      ensure_dir_mode "$log_dir" "${DATA_DIR_MODE:-700}"
    else
      mkdir -p "$log_dir"
    fi

    timestamp="${ARR_LOG_TIMESTAMP:-}"
    if [[ -z "$timestamp" ]]; then
      timestamp="$(date +%Y%m%d-%H%M%S)"
      export ARR_LOG_TIMESTAMP="$timestamp"
    fi

    stack_name="${STACK:-arr}"
    base_log="${log_dir}/${stack_name}-${timestamp}.log"
  fi

  if [[ "$base_log" == *.log ]]; then
    trace_file="${base_log%.log}-trace.log"
  else
    trace_file="${base_log}-trace.log"
  fi

  export ARR_TRACE_FILE="${ARR_TRACE_FILE:-$trace_file}"

  local base_mask='([Pp]assword|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey|[Aa]ccess[_-]?[Tt]oken|[Aa]uth|[Ss]ession|[Jj]wt)=[^[:space:]]+|Authorization:[[:space:]]*Basic[[:space:]]+[A-Za-z0-9+/=]+|Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9\-._~+/]+=*|Cookie:[[:space:]]*[^;[:space:]]+'
  local mask="${ARR_TRACE_MASK_RE:+${ARR_TRACE_MASK_RE}|}${base_mask}"

  exec {__arr_trace_fd}> >(
    if [[ -n "$mask" ]]; then
      sed -u -E "s/${mask}/[REDACTED]/g" >>"$ARR_TRACE_FILE"
    else
      cat >>"$ARR_TRACE_FILE"
    fi
  )

  export BASH_XTRACEFD=$__arr_trace_fd

  if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]]; then
    export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] ${FUNCNAME[0]:-main}() '
  else
    export PS4='+ [TRACE] [${BASH_SOURCE##*/}:${LINENO}] ${FUNCNAME[0]:-main}() '
  fi

  set -o xtrace

  if [[ "${ARR_TRACE_DEBUG:-0}" == "1" ]]; then
    if [[ "${BASH_VERSINFO[0]:-0}" -ge 5 ]]; then
      trap 'printf "%s [%s:%s] %s\n" "${EPOCHREALTIME}" "${BASH_SOURCE##*/}" "${LINENO}" "$BASH_COMMAND" >&$__arr_trace_fd' DEBUG
    else
      trap 'printf "%s [%s:%s] %s\n" "${SECONDS}" "${BASH_SOURCE##*/}" "${LINENO}" "$BASH_COMMAND" >&$__arr_trace_fd' DEBUG
    fi
    set -o functrace
  fi

  trap 'arr_trace_stop' EXIT
}

arr_trace_stop() {
  { set +o xtrace; } 2>/dev/null || true
  trap - DEBUG || true
  if [[ -n "${__arr_trace_fd:-}" ]]; then
    exec {__arr_trace_fd}>&- || true
    unset __arr_trace_fd
  fi
}

#!/usr/bin/env bash
# shellcheck shell=bash

if [[ -z "${ARR_YAML_EMIT_LIB_SOURCED:-}" ]]; then
  ARR_YAML_EMIT_LIB_SOURCED=1

  # Produces a YAML-safe double-quoted scalar for literal emission
  arr_yaml_escape() {
    local value="${1-}"
    value="${value//$'\r'/}" # drop carriage returns
    value="${value//$'\t'/\\t}" # normalise tabs for YAML safety
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '"%s"' "$value"
  }

  # Writes key/value pair to YAML with automatic escaping
  arr_yaml_kv() {
    local indent="$1" key="$2" value="${3-}"
    printf '%s%s: %s\n' "$indent" "$key" "$(arr_yaml_escape "$value")"
  }

  # Writes YAML list item with automatic escaping
  arr_yaml_list_item() {
    local indent="$1" value="${2-}"
    if [[ -z "${value//[[:space:]]/}" ]]; then
      return 0
    fi
    printf '%s- %s\n' "$indent" "$(arr_yaml_escape "$value")"
  }

  # Compose streaming helpers shared by docker-compose emission workflows
  declare -Ag ARR_COMPOSE_VARS=()
  declare -Ag ARR_COMPOSE_MISSING=()
  declare -Ag ARR_COMPOSE_REQUIRED_BY=()

  ARR_COMPOSE_CONTEXT="compose"

  arr_compose_reset_tracking() {
    ARR_COMPOSE_VARS=()
    ARR_COMPOSE_MISSING=()
    ARR_COMPOSE_REQUIRED_BY=()
  }

  arr_compose_set_context() {
    ARR_COMPOSE_CONTEXT="$1"
  }

  arr_compose_inline_escape() {
    local value="${1-}"
    value="${value//$'\r'/}" # normalize CRLF
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//#/\\#}"
    printf '%s' "$value"
  }

  arr_compose_can_inline_placeholder() {
    local before="$1" after="$2"
    local open_quote=0
    local prev="" char=""
    local i=0

    for ((i = 0; i < ${#before}; i++)); do
      char="${before:i:1}"
      if [[ "$char" == '"' && "$prev" != '\\' ]]; then
        if ((open_quote)); then
          open_quote=0
        else
          open_quote=1
        fi
      fi
      prev="$char"
    done

    if ((open_quote == 0)); then
      return 1
    fi

    prev=""
    for ((i = 0; i < ${#after}; i++)); do
      char="${after:i:1}"
      if [[ "$char" == '"' && "$prev" != '\\' ]]; then
        return 0
      fi
      prev="$char"
    done

    return 1
  }

  arr_compose_register_placeholder() {
    local name="$1"
    local require_value="${2:-1}"

    if [[ -z "$name" ]]; then
      return
    fi

    ARR_COMPOSE_VARS["$name"]=1

    if ((require_value)); then
      if [[ ${!name+x} ]]; then
        unset 'ARR_COMPOSE_MISSING[$name]'
      else
        ARR_COMPOSE_MISSING["$name"]=1
      fi
    fi

    if [[ -n "$ARR_COMPOSE_CONTEXT" ]]; then
      ARR_COMPOSE_REQUIRED_BY["$name"]="$ARR_COMPOSE_CONTEXT"
    fi
  }

  arr_compose_stream_line() {
    local target="$1"
    local line="$2"
    local processed=""
    local search="$line"

    while [[ "$search" =~ (\$\{[A-Za-z_][A-Za-z0-9_]*([:=\-\?+][^}]*)?\}) ]]; do
      local placeholder="${BASH_REMATCH[1]}"
      local before="${search%%"${placeholder}"*}"
      local after="${search#*"${placeholder}"}"

      # Append text before the placeholder
      processed+="$before"
      local expression="${placeholder:2:${#placeholder}-3}"
      local operator=""
      local sep
      for sep in ':-' '-' ':=' ':?' ':+'; do
        if [[ "$expression" == *"$sep"* ]]; then
          operator="$sep"
          expression="${expression%%"$sep"*}"
          break
        fi
      done

      local require_value=1
      case "$operator" in
        '' | ':?') require_value=1 ;;
        *) require_value=0 ;;
      esac

      local can_inline=0
      if [[ "${COMPOSE_INLINE_VALUES:-0}" == "1" && -z "$operator" && ${!expression+x} ]]; then
        if arr_compose_can_inline_placeholder "$processed" "$after"; then
          can_inline=1
        fi
      fi

      if ((can_inline)); then
        # Inline the value and clear any prior tracking
        local replacement
        replacement="$(arr_compose_inline_escape "${!expression}")"
        processed+="$replacement"
        unset 'ARR_COMPOSE_MISSING[$expression]'
        unset 'ARR_COMPOSE_VARS[$expression]'
      else
        # Emit the placeholder verbatim and register it
        processed+="$placeholder"
        arr_compose_register_placeholder "$expression" "$require_value"
        # If in inline mode with a required-but-unset var, track it for failure
        if [[ "${COMPOSE_INLINE_VALUES:-0}" == "1" && -z "$operator" && ! ${!expression+x} ]]; then
          ARR_COMPOSE_MISSING["$expression"]=1
          ARR_COMPOSE_VARS["$expression"]=1
        fi
      fi

      # Remove the processed chunk from search
      search="$after"
    done

    # Append any remaining text
    processed+="$search"
    printf '%s\n' "$processed" >>"$target"
  }

  arr_compose_stream_block() {
    local target="$1"
    local line=""
    while IFS= read -r line || [[ -n "$line" ]]; do
      arr_compose_stream_line "$target" "$line"
      line=""
    done
  }

  arr_compose_emit_ports_block() {
    local target="$1"
    local indent="$2"
    shift 2

    local comment=""
    if [[ "${1-}" == "--comment" ]]; then
      comment="$2"
      shift 2
    fi

    local -a ports_raw=("$@")
    local -A seen=()
    local -a deduped=()
    local port trimmed host_port

    for port in "${ports_raw[@]}"; do
      trimmed="${port//[[:space:]]/}"
      if [[ -z "$trimmed" ]]; then
        continue
      fi

      host_port="$trimmed"
      if [[ "$host_port" == *":"* ]]; then
        host_port="${host_port#*:}"
        if [[ "$host_port" == *":"* ]]; then
          host_port="${host_port%%:*}"
        fi
      fi
      host_port="${host_port%%/*}"

      if [[ -z "$host_port" ]]; then
        continue
      fi

      if [[ "$host_port" =~ ^[0-9]+$ ]]; then
        :
      elif [[ "$host_port" =~ ^\$\{[A-Za-z_][A-Za-z0-9_:-]*\}$ ]]; then
        :
      else
        continue
      fi

      if [[ -z "${seen[$trimmed]:-}" ]]; then
        seen["$trimmed"]=1
        deduped+=("$trimmed")
      fi
    done

    if ((${#deduped[@]} == 0)); then
      return 0
    fi

    arr_compose_stream_line "$target" "${indent}ports:"
    if [[ -n "$comment" ]]; then
      arr_compose_stream_line "$target" "${indent}  # ${comment}"
    fi

    for port in "${deduped[@]}"; do
      arr_compose_stream_line "$target" "${indent}  - $(arr_yaml_escape "$port")"
    done
  }

  # Writes a YAML comment with consistent escaping of carriage returns
  arr_yaml_comment() {
    local indent="$1" text="${2-}"
    text="${text//$'\r'/}"
    printf '%s# %s\n' "$indent" "$text"
  }

  # Writes a YAML chunk to a file, replacing existing content
  arr_yaml_write() {
    local file="$1"
    shift
    if (($# == 0)); then
      cat >"$file"
    else
      printf '%s\n' "$@" >"$file"
    fi
  }

  # Appends a YAML chunk to a file
  arr_yaml_append() {
    cat >>"$1"
  }

  # Escapes dotenv values and wraps them in double quotes for Compose compatibility
  arr_env_escape_value() {
    local value="${1-}"
    value="${value//$'\r'/}" # normalize CRLF
    value="${value//$'\t'/ }"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\$}"
    value="${value//$'\n'/ }"
    if [[ -z "${value//[[:space:]]/}" ]]; then
      value=""
    fi
    printf '"%s"' "$value"
  }

  # Emits KEY="escaped" lines while validating variable names
  arr_write_env_kv() {
    local name="$1"
    local value="${2-}"

    if [[ -z "$name" ]]; then
      printf '%s\n' "arr_write_env_kv requires a variable name" >&2
      return 1
    fi

    if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      printf '[env] invalid var name: %s\n' "$name" >&2
      return 1
    fi

    printf '%s=%s\n' "$name" "$(arr_env_escape_value "$value")"
  }

  # Writes a full dotenv file using arr_write_env_kv for each key/value pair
  arr_write_env_file() {
    local out="$1"
    shift || return 0

    : >"$out" || return 1

    while (($#)); do
      local key="$1"
      if (($# < 2)); then
        printf '[env] missing value for %s in arr_write_env_file\n' "$key" >&2
        return 1
      fi
      local value="$2"
      shift 2
      if ! arr_write_env_kv "$key" "$value" >>"$out"; then
        return 1
      fi
    done
  }
fi

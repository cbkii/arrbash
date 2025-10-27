#!/usr/bin/env bash
# shellcheck shell=bash

if [[ -z "${ARR_YAML_EMIT_LIB_SOURCED:-}" ]]; then
  ARR_YAML_EMIT_LIB_SOURCED=1

  # Produces a YAML-safe double-quoted scalar for literal emission
  arr_yaml_escape() {
    local value="${1-}"
    value="${value//$'\r'/}" # drop carriage returns
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
    printf '%s- %s\n' "$indent" "$(arr_yaml_escape "$value")"
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

fi

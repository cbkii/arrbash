# shellcheck shell=bash
# Purpose: Handle docker-compose generation, validation, and repair helpers for the stack.
# Inputs: Uses ARR_STACK_DIR, ARR_ENV_FILE, DOCKER_COMPOSE_CMD, compose template variables, and env toggles like ENABLE_CADDY.
# Outputs: Writes docker-compose.yml files, logs validation summaries, and emits diagnostics to logs/compose-repair.log.
# Exit codes: Functions return non-zero when compose validation or file writes fail.
if [[ -n "${__COMPOSE_RUNTIME_LOADED:-}" ]]; then
  return 0
fi
__COMPOSE_RUNTIME_LOADED=1

arr_prune_compose_backups() {
  local prefix="$1"

  local nullglob_was_set=0
  if shopt -q nullglob; then
    nullglob_was_set=1
  fi
  shopt -s nullglob

  local -a backups=("${prefix}".*)

  if ((nullglob_was_set == 0)); then
    shopt -u nullglob
  fi

  if ((${#backups[@]} <= 3)); then
    return 0
  fi

  local -a sorted_backups=()
  mapfile -t sorted_backups < <(printf '%s\n' "${backups[@]}" | sort -r)

  local idx
  for idx in "${!sorted_backups[@]}"; do
    if ((idx >= 3)); then
      rm -f -- "${sorted_backups[$idx]}" 2>/dev/null || true
    fi
  done
}

arr_safe_compose_write() {
  local target="$1"
  local tmp="$2"
  local backup_prefix="${target}.backup"
  local backup_created=""

  if [[ -f "${backup_prefix}" ]]; then
    local legacy_name
    legacy_name="${backup_prefix}.$(date +%Y%m%d%H%M%S%N).legacy"
    if ! mv "${backup_prefix}" "${legacy_name}" 2>/dev/null; then
      rm -f "${backup_prefix}" 2>/dev/null || true
    fi
  fi

  if [[ -f "$target" ]]; then
    local timestamp
    timestamp="$(date +%Y%m%d%H%M%S%N)"
    backup_created="${backup_prefix}.${timestamp}"
    if [[ -e "$backup_created" ]]; then
      backup_created+=".${RANDOM}"
    fi
    if ! cp -f "$target" "$backup_created" 2>/dev/null; then
      warn "Failed to create compose backup at ${backup_created}"
      return 1
    fi
    arr_prune_compose_backups "$backup_prefix"
  fi

  if mv "$tmp" "$target"; then
    arr_unregister_temp_path "$tmp"
    return 0
  fi

  warn "Failed to activate ${target}; attempting to restore previous version"

  if [[ -n "$backup_created" && -f "$backup_created" ]]; then
    cp -f "$backup_created" "$target" 2>/dev/null || true
  fi
  arr_cleanup_temp_path "$tmp"
  return 1
}

detect_compose_cmd() {
  local compose_cmd=""

  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1 || docker compose -v >/dev/null 2>&1; then
      compose_cmd="docker compose"
    fi
  fi

  if [[ -z "$compose_cmd" ]] && command -v docker-compose >/dev/null 2>&1; then
    if docker-compose version >/dev/null 2>&1 || docker-compose -v >/dev/null 2>&1; then
      compose_cmd="docker-compose"
    fi
  fi

  if [[ -z "$compose_cmd" ]]; then
    warn "Docker Compose not detected; skipping syntax validation."
    return 1
  fi

  printf '%s\n' "$compose_cmd"
}

arr_compose_trim_log() {
  local log_file="$1"
  local max_bytes=$((666 * 1024))

  if [[ -z "$log_file" || ! -f "$log_file" ]]; then
    return 0
  fi

  local size=0
  size="$(wc -c <"$log_file" 2>/dev/null || printf '0')"
  if ((size <= max_bytes)); then
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${log_file}.trim.XXXXXX")"; then
    return 0
  fi

  if ! tail -c "$max_bytes" "$log_file" >"$tmp" 2>/dev/null; then
    arr_cleanup_temp_path "$tmp"
    return 0
  fi

  local first_line=""
  first_line="$(head -n 1 "$tmp" 2>/dev/null || printf '')"
  if [[ -n "$first_line" && ! "$first_line" =~ ^\[[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}\] ]]; then
    local tmp2=""
    if tmp2="$(arr_mktemp_file "${log_file}.trimline.XXXXXX")"; then
      if tail -n +2 "$tmp" >"$tmp2" 2>/dev/null; then
        if mv "$tmp2" "$tmp" 2>/dev/null; then
          arr_unregister_temp_path "$tmp2"
        else
          arr_cleanup_temp_path "$tmp2"
        fi
      else
        arr_cleanup_temp_path "$tmp2"
      fi
    fi
  fi

  if mv "$tmp" "$log_file" 2>/dev/null; then
    arr_unregister_temp_path "$tmp"
  else
    arr_cleanup_temp_path "$tmp"
  fi
}

arr_compose_prepare_log_file() {
  local log_file="$1"

  if [[ -z "$log_file" ]]; then
    return 1
  fi

  : >"$log_file" 2>/dev/null || return 1
  return 0
}

arr_compose_log_message() {
  local log_file="$1"
  shift
  if [[ -z "$log_file" || $# -eq 0 ]]; then
    return 0
  fi

  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$log_file" 2>/dev/null || true
  arr_compose_trim_log "$log_file"
}

arr_compose_log_offending_lines() {
  local log_file="$1"
  local source_file="$2"
  local lint_output="$3"

  if [[ -z "$log_file" || -z "$source_file" || -z "$lint_output" ]]; then
    return 0
  fi

  if [[ ! -f "$source_file" ]]; then
    arr_compose_log_message "$log_file" "Unable to display offending lines; ${source_file} missing"
    return 0
  fi

  local -A seen_lines=()
  local lint_line=""
  while IFS= read -r lint_line; do
    if [[ "$lint_line" =~ :([0-9]+):([0-9]+): ]]; then
      local line_no="${BASH_REMATCH[1]}"
      if [[ -n "${seen_lines["$line_no"]:-}" ]]; then
        continue
      fi

      local offending_line=""
      offending_line="$(sed -n "${line_no}p" "$source_file" 2>/dev/null || printf '')"
      if [[ -n "$offending_line" ]]; then
        arr_compose_log_message "$log_file" "Line ${line_no}: ${offending_line}"
      else
        arr_compose_log_message "$log_file" "Line ${line_no}: <unavailable>"
      fi

      seen_lines["$line_no"]=1
    fi
  done <<<"$lint_output"
}

arr_compose_save_artifact() {
  local staging="$1"
  local log_file="$2"
  local label="$3"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  local log_dir="${log_file%/*}"
  if [[ "$log_dir" == "$log_file" ]]; then
    log_dir="."
  fi

  ensure_dir "$log_dir"

  local timestamp="$(date '+%Y%m%d_%H%M%S')"
  local sha_segment="unknown"
  if [[ -f "$staging" ]]; then
    sha_segment="$(sha256sum "$staging" 2>/dev/null | awk '{print substr($1,1,8)}')"
  fi

  local artifact="${log_dir}/compose-repair-${timestamp}-${sha_segment}"
  if [[ -n "$label" ]]; then
    artifact+="-${label}"
  fi
  artifact+=".yml.bak"

  if cp -f "$staging" "$artifact" 2>/dev/null; then
    arr_compose_log_message "$log_file" "Saved ${label:-snapshot} copy at ${artifact}"
    printf '%s\n' "$artifact"
    return 0
  fi

  return 1
}

arr_compose_run_yq_roundtrip() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  ARR_COMPOSE_YQ_CHANGED=0

  if ! command -v yq >/dev/null 2>&1; then
    arr_compose_log_message "$log_file" "yq not available; skipping canonicalization"
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.yq.XXXXXX")"; then
    arr_compose_log_message "$log_file" "Unable to allocate temporary file for yq canonicalization"
    return 1
  fi

  local sha_before=""
  sha_before="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"

  if yq eval --no-colors --indent 2 '.' "$staging" >"$tmp" 2>>"$log_file"; then
    if cmp -s "$staging" "$tmp" 2>/dev/null; then
      arr_cleanup_temp_path "$tmp"
      arr_compose_log_message "$log_file" "yq canonicalization produced no structural changes"
      return 0
    fi

    if mv "$tmp" "$staging" 2>/dev/null; then
      arr_unregister_temp_path "$tmp"
      local sha_after=""
      sha_after="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"
      arr_compose_log_message "$log_file" "yq canonicalization updated compose (sha ${sha_before:0:8} → ${sha_after:0:8})"
      ARR_COMPOSE_YQ_CHANGED=1
      return 0
    fi

    arr_cleanup_temp_path "$tmp"
    arr_compose_log_message "$log_file" "Failed to promote yq canonicalization result"
    return 1
  fi

  arr_compose_log_message "$log_file" "Primary yq canonicalization failed; attempting fallback yq -i '.'"
  arr_cleanup_temp_path "$tmp"

  local yq_output=""
  local yq_status=0
  yq_output="$(yq eval --inplace '.' "$staging" 2>&1)" || yq_status=$?
  if ((yq_status != 0)); then
    arr_compose_log_message "$log_file" "Fallback yq canonicalization failed"
    if [[ -n "$yq_output" ]]; then
      printf '%s\n' "$yq_output" >>"$log_file" 2>/dev/null || true
    fi
    return 1
  fi

  if [[ -n "$yq_output" ]]; then
    printf '%s\n' "$yq_output" >>"$log_file" 2>/dev/null || true
  fi

  local sha_after=""
  sha_after="$(sha256sum "$staging" 2>/dev/null | awk '{print $1}')"
  arr_compose_log_message "$log_file" "Fallback yq canonicalization updated compose (sha ${sha_before:0:8} → ${sha_after:0:8})"
  ARR_COMPOSE_YQ_CHANGED=1
  return 0
}

arr_compose_validate_with_compose() {
  local staging="$1"
  local log_file="$2"
  local compose_cmd_raw="$3"
  local context="$4"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  if [[ -z "$compose_cmd_raw" ]]; then
    arr_compose_log_message "$log_file" "Compose validation skipped (${context:-autorepair}; compose command unavailable)"
    return 0
  fi

  local -a compose_cmd=()
  read -r -a compose_cmd <<<"$compose_cmd_raw"
  if ((${#compose_cmd[@]} == 0)); then
    arr_compose_log_message "$log_file" "Compose validation skipped (${context:-autorepair}; compose command unavailable)"
    return 0
  fi

  local compose_output=""
  local compose_status=0
  compose_output="$("${compose_cmd[@]}" -f "$staging" config --quiet 2>&1)" || compose_status=$?

  if ((compose_status != 0)); then
    arr_compose_log_message "$log_file" "Compose validation failed during ${context:-autorepair}"
    if [[ -n "$compose_output" ]]; then
      printf '%s\n' "$compose_output" >>"$log_file" 2>/dev/null || true
    fi
    return 1
  fi

  if [[ -n "$compose_output" ]]; then
    printf '%s\n' "$compose_output" >>"$log_file" 2>/dev/null || true
  fi

  arr_compose_log_message "$log_file" "Compose validation succeeded during ${context:-autorepair} via ${compose_cmd[*]} config --quiet"
  return 0
}

arr_compose_replace_line() {
  local target="$1"
  local line_no="$2"
  local new_content="$3"

  if [[ -z "$target" || -z "$line_no" || -z "$new_content" ]]; then
    return 1
  fi

  if [[ ! -f "$target" ]]; then
    return 1
  fi

  if [[ ! "$line_no" =~ ^[0-9]+$ || "$line_no" -le 0 ]]; then
    return 1
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${target}.repline.XXXXXX")"; then
    return 1
  fi

  export REPLACEMENT_CONTENT="$new_content"
  if awk -v target_line="$line_no" '
    BEGIN {status=1}
    {
      if (NR == target_line) {
        print ENVIRON["REPLACEMENT_CONTENT"];
        status=0;
      } else {
        print $0;
      }
    }
    END {exit status}
  ' "$target" >"$tmp" 2>/dev/null; then
    unset REPLACEMENT_CONTENT
    if mv "$tmp" "$target" 2>/dev/null; then
      arr_unregister_temp_path "$tmp"
      return 0
    fi
  fi

  arr_cleanup_temp_path "$tmp"
  return 1
}

arr_compose_attempt_yaml_fixes() {
  local staging="$1"
  local log_file="$2"
  local lint_output="$3"

  if [[ -z "$staging" || -z "$log_file" || -z "$lint_output" ]]; then
    printf 'changed=0\n'
    printf 'rerun=0\n'
    return 0
  fi

  local -A colon_targets=()
  local -A blank_targets=()

  local lint_line=""
  while IFS= read -r lint_line; do
    if [[ "$lint_line" =~ ^[^:]+:([0-9]+):[0-9]+:[[:space:]]*(.*)$ ]]; then
      local line_no="${BASH_REMATCH[1]}"
      local message="${BASH_REMATCH[2]}"
      if [[ "$message" == *"could not find expected ':'"* ]]; then
        colon_targets["$line_no"]=1
      elif [[ "$message" == *"(empty-lines)"* && "$message" == *"too many blank lines"* ]]; then
        blank_targets["$line_no"]=1
      fi
    fi
  done <<<"$lint_output"

  local needs_rerun=0
  local changed=0
  local -a summary_lines=()

  local -a sorted_colon_lines=()
  mapfile -t sorted_colon_lines < <(printf '%s\n' "${!colon_targets[@]}" | sort -n)

  local line_no=""
  for line_no in "${sorted_colon_lines[@]}"; do
    local offending_line=""
    offending_line="$(sed -n "${line_no}p" "$staging" 2>/dev/null || printf '')"

    if [[ -z "$offending_line" ]]; then
      arr_compose_log_message "$log_file" "Unable to inspect line ${line_no} for missing colon repair"
      continue
    fi

    if [[ "$offending_line" == *":"* ]]; then
      arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: existing ':' makes lint output ambiguous (${offending_line})"
      continue
    fi

    local new_line=""
    if [[ "$offending_line" =~ ^([[:space:]]*-[[:space:]]*)([A-Za-z0-9_.-]+)[[:space:]]+([^[:space:]].*)$ ]]; then
      local prefix="${BASH_REMATCH[1]}"
      local key="${BASH_REMATCH[2]}"
      local value="${BASH_REMATCH[3]}"
      local value_token="${value%%[[:space:]]*}"
      if [[ "$value" == *":"* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value contains ':' (${value})"
        continue
      fi
      if [[ "$value" == *'${'* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value contains placeholder syntax (${value})"
        continue
      fi
      if [[ -n "$value_token" && "${value_token:0:1}" == "#" ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value begins with comment (${value})"
        continue
      fi
      case "$value_token" in
        '|'|'|-'|'|+'|'>'|'>-'|'>+')
          arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: sequence value is a block scalar indicator (${value})"
          continue
          ;;
      esac
      new_line="${prefix}${key}: ${value}"
    elif [[ "$offending_line" =~ ^([[:space:]]*)([A-Za-z0-9_.-]+)[[:space:]]+([^[:space:]].*)$ ]]; then
      local indent="${BASH_REMATCH[1]}"
      local key="${BASH_REMATCH[2]}"
      local value="${BASH_REMATCH[3]}"
      local value_token="${value%%[[:space:]]*}"
      if [[ "$value" == *":"* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value contains ':' (${value})"
        continue
      fi
      if [[ "$value" == *'${'* ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value contains placeholder syntax (${value})"
        continue
      fi
      if [[ -n "$value_token" && "${value_token:0:1}" == "#" ]]; then
        arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value begins with comment (${value})"
        continue
      fi
      case "$value_token" in
        '|'|'|-'|'|+'|'>'|'>-'|'>+')
          arr_compose_log_message "$log_file" "Skipping colon repair for line ${line_no}: mapping value is a block scalar indicator (${value})"
          continue
          ;;
      esac
      new_line="${indent}${key}: ${value}"
    else
      arr_compose_log_message "$log_file" "Unable to derive safe colon fix for line ${line_no}: ${offending_line}"
      continue
    fi

    arr_compose_log_message "$log_file" "Attempting colon repair on line ${line_no}:"
    arr_compose_log_message "$log_file" "  before: ${offending_line}"
    arr_compose_log_message "$log_file" "  after:  ${new_line}"

    if arr_compose_replace_line "$staging" "$line_no" "$new_line"; then
      summary_lines+=("corrected missing ':' on line ${line_no}")
      needs_rerun=1
      changed=1
    else
      arr_compose_log_message "$log_file" "Failed to rewrite line ${line_no} for colon repair"
    fi
  done

  if ((${#blank_targets[@]} > 0)); then
    local removed=0
    local -a sorted_blank_lines=()
    mapfile -t sorted_blank_lines < <(printf '%s\n' "${!blank_targets[@]}" | sort -nr)
    for line_no in "${sorted_blank_lines[@]}"; do
      local blank_line=""
      blank_line="$(sed -n "${line_no}p" "$staging" 2>/dev/null || printf '')"
      if [[ -n "${blank_line//[[:space:]]/}" ]]; then
        continue
      fi
      arr_compose_log_message "$log_file" "Removing yamllint empty-line violation at ${line_no}"
      if sed -i "${line_no}d" "$staging" 2>>"$log_file"; then
        ((removed++))
        needs_rerun=1
        changed=1
      else
        arr_compose_log_message "$log_file" "Failed to remove blank line at ${line_no}"
      fi
    done

    if ((removed > 0)); then
      summary_lines+=("removed ${removed} empty-line violation(s)")
    fi
  fi

  printf 'changed=%d\n' "$changed"
  printf 'rerun=%d\n' "$needs_rerun"
  if ((${#summary_lines[@]} > 0)); then
    printf '%s\n' "${summary_lines[@]}"
  fi
}

arr_compose_ensure_document_start() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || ! -f "$staging" ]]; then
    return 1
  fi

  local first_content_line=""
  while IFS= read -r line; do
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    first_content_line="$line"
    break
  done <"$staging"

  if [[ "$first_content_line" =~ ^[[:space:]]*---[[:space:]]*$ ]]; then
    return 0
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.docstart.XXXXXX")"; then
    return 1
  fi

  local inserted=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if ((inserted == 0)); then
      if [[ -n "${line//[[:space:]]/}" && ! "$line" =~ ^[[:space:]]*# ]]; then
        printf '---\n' >>"$tmp"
        inserted=1
      fi
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$staging"

  if ((inserted == 0)); then
    printf '---\n' >>"$tmp"
  fi

  if mv "$tmp" "$staging" 2>/dev/null; then
    arr_unregister_temp_path "$tmp"
    arr_compose_log_message "$log_file" "Inserted YAML document start delimiter"
    printf '%s' "inserted YAML document start delimiter"
    return 0
  fi

  arr_cleanup_temp_path "$tmp"
  return 1
}

arr_compose_collapse_blank_runs() {
  local staging="$1"
  local log_file="$2"

  if [[ -z "$staging" || ! -f "$staging" ]]; then
    return 1
  fi

  local tmp=""
  if ! tmp="$(arr_mktemp_file "${staging}.noblanks.XXXXXX")"; then
    return 1
  fi

  if awk 'BEGIN {blank=0} {
    if ($0 ~ /^[[:space:]]*$/) {
      blank++;
    } else {
      blank=0;
    }
    if (blank <= 1) {
      print $0;
    }
  } END {exit 0}' "$staging" >"$tmp" 2>/dev/null; then
    if ! cmp -s "$staging" "$tmp" 2>/dev/null; then
      if mv "$tmp" "$staging" 2>/dev/null; then
        arr_unregister_temp_path "$tmp"
        arr_compose_log_message "$log_file" "Collapsed consecutive blank lines"
        printf '%s' "collapsed consecutive blank lines"
        return 0
      fi
    else
      arr_cleanup_temp_path "$tmp"
      return 0
    fi
  fi

  arr_cleanup_temp_path "$tmp"
  return 1
}

arr_compose_capture_matches() {
  local pattern="$1"
  local file="$2"
  local matches_ref="$3"
  local rc_ref="$4"

  if [[ -z "$pattern" || -z "$file" || -z "$matches_ref" || -z "$rc_ref" ]]; then
    return 1
  fi

  local err_file=""
  if ! err_file="$(arr_mktemp_file "${file}.grep.XXXXXX" '')"; then
    return 1
  fi

  local output=""
  local status=0
  if ! output="$(LC_ALL=C grep -oE "$pattern" "$file" 2>"$err_file")"; then
    status=$?
  fi

  local err_payload=""
  err_payload="$(cat "$err_file" 2>/dev/null)"
  arr_cleanup_temp_path "$err_file"

  if ((status > 1)); then
    if [[ "$err_payload" =~ [Pp]ermission[[:space:]]+denied ]]; then
      output=""
      status=1
    else
      return 1
    fi
  fi

  declare -n matches_out="$matches_ref"
  declare -n rc_out="$rc_ref"
  matches_out="$output"
  rc_out="$status"

  return 0
}


arr_compose_autofix_env_names() {
  local compose_file="$1"
  local env_file="$2"

  if [[ -z "$compose_file" || ! -f "$compose_file" ]]; then
    return 1
  fi

  declare -A canonical_set=()
  declare -A canonical_by_norm=()
  declare -A norm_conflicts=()

  local key=""
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    if [[ -n "${canonical_set[$key]:-}" ]]; then
      continue
    fi
    canonical_set["$key"]=1
    local norm=""
    norm="$(arr_compose_normalize_env_name "$key")"
    if [[ -n "${canonical_by_norm[$norm]:-}" && "${canonical_by_norm[$norm]}" != "$key" ]]; then
      norm_conflicts["$norm"]=1
    else
      canonical_by_norm["$norm"]="$key"
    fi
  done < <(arr_compose_collect_canonical_env_names "$env_file")

  if ((${#canonical_set[@]} == 0)); then
    return 0
  fi

  declare -A replacements=()
  declare -a replacement_keys=()
  declare -a summary=()
  declare -a ambiguous_tokens=()
  declare -a unresolved_tokens=()

  local template_rc=0
  local template_matches=""
  if ! arr_compose_capture_matches '__[A-Za-z0-9_]+__' "$compose_file" template_matches template_rc; then
    return 1
  fi
  if ((template_rc == 0)) && [[ -n "$template_matches" ]]; then
    template_matches="$(printf '%s\n' "$template_matches" | LC_ALL=C sort -u)"
    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      local raw_name="${token#__}"
      raw_name="${raw_name%__}"
      local canonical_name=""
      local match_status=1
      if [[ -n "${canonical_set[$raw_name]:-}" ]]; then
        canonical_name="$raw_name"
        match_status=0
      else
        local normalized=""
        normalized="$(arr_compose_normalize_env_name "$raw_name")"
        if [[ -n "${norm_conflicts[$normalized]:-}" ]]; then
          match_status=2
        elif [[ -n "${canonical_by_norm[$normalized]:-}" ]]; then
          canonical_name="${canonical_by_norm[$normalized]}"
          match_status=0
        fi
      fi
      if ((match_status == 0)); then
        if [[ -z "${replacements[$token]+x}" ]]; then
          replacement_keys+=("$token")
        fi
        local replacement_value=""
        printf -v replacement_value "\${%s}" "$canonical_name"
        replacements["$token"]="$replacement_value"
        local summary_entry=""
        printf -v summary_entry "%s → \${%s}" "$token" "$canonical_name"
        summary+=("$summary_entry")
      elif ((match_status == 2)); then
        ambiguous_tokens+=("$token")
      else
        unresolved_tokens+=("$token")
      fi
    done <<<"$template_matches"
  fi

  local docker_rc=0
  local docker_matches=""
  if ! arr_compose_capture_matches '\$\{[A-Za-z0-9_]+\}' "$compose_file" docker_matches docker_rc; then
    return 1
  fi
  if ((docker_rc == 0)) && [[ -n "$docker_matches" ]]; then
    docker_matches="$(printf '%s\n' "$docker_matches" | LC_ALL=C sort -u)"
    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      local placeholder_name="${token:2:${#token}-3}"
      if [[ -n "${canonical_set[$placeholder_name]:-}" ]]; then
        continue
      fi
      local canonical_name=""
      local match_status=1
      local normalized=""
      normalized="$(arr_compose_normalize_env_name "$placeholder_name")"
      if [[ -n "${norm_conflicts[$normalized]:-}" ]]; then
        match_status=2
      elif [[ -n "${canonical_by_norm[$normalized]:-}" ]]; then
        canonical_name="${canonical_by_norm[$normalized]}"
        match_status=0
      fi
      if ((match_status == 0)); then
        if [[ -z "${replacements[$token]+x}" ]]; then
          replacement_keys+=("$token")
        fi
        local replacement_value=""
        printf -v replacement_value "\${%s}" "$canonical_name"
        replacements["$token"]="$replacement_value"
        local summary_entry=""
        printf -v summary_entry "%s → \${%s}" "$token" "$canonical_name"
        summary+=("$summary_entry")
      elif ((match_status == 2)); then
        ambiguous_tokens+=("$token")
      else
        unresolved_tokens+=("$token")
      fi
    done <<<"$docker_matches"
  fi

  if ((${#replacement_keys[@]} > 0)); then
    local tmp=""
    tmp="$(arr_mktemp_file "${compose_file}.envfix.XXXXXX")" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
      local updated_line="$line"
      local placeholder=""
      for placeholder in "${replacement_keys[@]}"; do
        updated_line="${updated_line//${placeholder}/${replacements[$placeholder]}}"
      done
      printf '%s\n' "$updated_line" >>"$tmp"
    done <"$compose_file"
    if mv "$tmp" "$compose_file" 2>/dev/null; then
      arr_unregister_temp_path "$tmp"
    else
      arr_cleanup_temp_path "$tmp"
      return 1
    fi
  fi

  if ((${#summary[@]} > 0)); then
    msg "compose env auto-repair mapped ${#summary[@]} placeholder(s):"
    local summary_entry=""
    for summary_entry in "${summary[@]}"; do
      msg "  ${summary_entry}"
    done
  fi

  if ((${#ambiguous_tokens[@]} > 0)); then
    warn "compose env auto-repair skipped ambiguous placeholder(s):"
    local ambiguous_entry=""
    for ambiguous_entry in "${ambiguous_tokens[@]}"; do
      warn "  ${ambiguous_entry}"
    done
  fi

  if ((${#unresolved_tokens[@]} > 0)); then
    warn "compose env auto-repair could not resolve placeholder(s):"
    local unresolved_entry=""
    for unresolved_entry in "${unresolved_tokens[@]}"; do
      warn "  ${unresolved_entry}"
    done
  fi

  return 0
}


arr_compose_autorepair() {
  local staging="$1"
  local log_file="$2"
  local compose_cmd_raw="${3-}"

  if [[ -z "$staging" || -z "$log_file" ]]; then
    return 1
  fi

  arr_compose_log_message "$log_file" "=== compose autorepair start ==="

  local snapshot_path=""
  snapshot_path="$(arr_compose_save_artifact "$staging" "$log_file" "snapshot" 2>/dev/null || printf '')"
  if [[ -z "$snapshot_path" ]]; then
    arr_compose_log_message "$log_file" "Warning: unable to persist initial snapshot; reverting will rely on staging copy"
  fi

  local -a summary=()
  local validation_needed=0
  local yq_summary_added=0

  if LC_ALL=C grep -q $'\r' "$staging" 2>/dev/null; then
    local crlf_samples=""
    crlf_samples="$(LC_ALL=C grep -n $'\r$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$crlf_samples" ]]; then
      arr_compose_log_message "$log_file" "CRLF-terminated lines before fix (first 3):"
      printf '%s\n' "$crlf_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i 's/\r$//' "$staging" 2>>"$log_file"; then
      summary+=("normalized CRLF line endings")
      arr_compose_log_message "$log_file" "Normalized CRLF line endings"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to normalize CRLF line endings"
    fi
  fi

  if LC_ALL=C grep -q $'\t' "$staging" 2>/dev/null; then
    local tab_samples=""
    tab_samples="$(LC_ALL=C grep -n $'\t' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$tab_samples" ]]; then
      arr_compose_log_message "$log_file" "Tab characters before fix (first 3):"
      printf '%s\n' "$tab_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i $'s/\t/  /g' "$staging" 2>>"$log_file"; then
      summary+=("replaced tabs with spaces")
      arr_compose_log_message "$log_file" "Replaced hard tabs with two spaces"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to replace hard tabs"
    fi
  fi

  if LC_ALL=C grep -q '[[:space:]]$' "$staging" 2>/dev/null; then
    local trailing_samples=""
    trailing_samples="$(LC_ALL=C grep -n '[[:space:]]$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$trailing_samples" ]]; then
      arr_compose_log_message "$log_file" "Trailing whitespace before fix (first 3):"
      printf '%s\n' "$trailing_samples" >>"$log_file" 2>/dev/null || true
    fi
    # Strip trailing whitespace except inside YAML block scalars
    local tmp_strip=""
    if tmp_strip="$(arr_mktemp_file "${staging}.strip.XXXXXX")"; then
      if awk '
        function is_block_start(line) {
          return (line ~ /^[[:space:]]*([|>])([+-])?[[:space:]]*$/);
        }
        {
          line=$0;
          # Track indentation and block scalar regions
          if (is_block_start(line)) {
            in_block=1;
            block_indent=match(line, /[^[:space:]]/)-1;
            print line; next;
          }
          if (in_block) {
            # End block when indentation drops below block_indent
            curr_indent=match(line, /[^[:space:]]/)-1;
            if (curr_indent < block_indent) {
              in_block=0;
            }
          }
          if (in_block) {
            print line; # preserve as-is
          } else {
            sub(/[[:space:]]+$/, "", line);
            print line;
          }
        }
      ' "$staging" >"$tmp_strip" 2>>"$log_file"; then
        if mv "$tmp_strip" "$staging" 2>/dev/null; then
          arr_unregister_temp_path "$tmp_strip"
          summary+=("stripped trailing whitespace (safe mode)")
          arr_compose_log_message "$log_file" "Stripped trailing whitespace (excluding YAML block scalars)"
          validation_needed=1
        else
          arr_cleanup_temp_path "$tmp_strip"
          arr_compose_log_message "$log_file" "Failed to promote stripped file"
        fi
      else
        arr_cleanup_temp_path "$tmp_strip"
        arr_compose_log_message "$log_file" "Failed to strip trailing whitespace (awk error)"
      fi
    fi
  fi

  local doc_start_summary=""
  if doc_start_summary="$(arr_compose_ensure_document_start "$staging" "$log_file" 2>/dev/null)"; then
    if [[ -n "$doc_start_summary" ]]; then
      summary+=("$doc_start_summary")
      validation_needed=1
    fi
  else
    arr_compose_log_message "$log_file" "Failed to ensure YAML document start"
  fi

  local blank_summary=""
  if blank_summary="$(arr_compose_collapse_blank_runs "$staging" "$log_file" 2>/dev/null)"; then
    if [[ -n "$blank_summary" ]]; then
      summary+=("$blank_summary")
      validation_needed=1
    fi
  else
    arr_compose_log_message "$log_file" "Failed to collapse blank line runs"
  fi

  if LC_ALL=C grep -q '^[[:space:]]*\\[[:space:]]*$' "$staging" 2>/dev/null; then
    local slash_samples=""
    slash_samples="$(LC_ALL=C grep -n '^[[:space:]]*\\[[:space:]]*$' "$staging" 2>/dev/null | head -n 3)"
    if [[ -n "$slash_samples" ]]; then
      arr_compose_log_message "$log_file" "Standalone backslash lines before fix (first 3):"
      printf '%s\n' "$slash_samples" >>"$log_file" 2>/dev/null || true
    fi
    if sed -i '/^[[:space:]]*\\[[:space:]]*$/d' "$staging" 2>>"$log_file"; then
      summary+=("removed stray backslash lines")
      arr_compose_log_message "$log_file" "Removed stray standalone backslash lines"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to remove stray backslash lines"
    fi
  fi

  local last_char=""
  if [[ -s "$staging" ]]; then
    last_char="$(tail -c1 "$staging" 2>/dev/null || printf '')"
  fi
  if [[ -z "$last_char" || "$last_char" != $'\n' ]]; then
    if printf '\n' >>"$staging" 2>>"$log_file"; then
      summary+=("ensured trailing newline")
      arr_compose_log_message "$log_file" "Ensured file ends with newline"
      validation_needed=1
    else
      arr_compose_log_message "$log_file" "Failed to append trailing newline"
    fi
  fi

  if ((validation_needed)); then
    if ! arr_compose_run_yq_roundtrip "$staging" "$log_file"; then
      arr_compose_save_artifact "$staging" "$log_file" "failed"
      if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
        cp -f "$snapshot_path" "$staging" 2>/dev/null || true
        arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yq failure"
      fi
      printf '%s\n' "auto-repair aborted: yq canonicalization failed"
      return 1
    fi
    if ((ARR_COMPOSE_YQ_CHANGED)) && ((yq_summary_added == 0)); then
      summary+=("normalized YAML with yq")
      yq_summary_added=1
    fi
    if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "formatting"; then
      arr_compose_save_artifact "$staging" "$log_file" "failed"
      if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
        cp -f "$snapshot_path" "$staging" 2>/dev/null || true
        arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after compose validation failure"
      fi
      printf '%s\n' "auto-repair aborted: compose validation failed"
      return 1
    fi
    validation_needed=0
  fi

  if command -v yamllint >/dev/null 2>&1; then
    local lint_output=""
    local lint_status=0
    local -a yamllint_cmd=(
      yamllint
      --config-data
      '{extends: default, rules: {line-length: {max: 140, level: warning}}}'
    )

    lint_output="$("${yamllint_cmd[@]}" "$staging" 2>&1)" || lint_status=$?

    if ((lint_status == 0)); then
      if [[ -n "$lint_output" ]]; then
        arr_compose_log_message "$log_file" $'yamllint reported warnings:'
        printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
        arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
      else
        arr_compose_log_message "$log_file" "yamllint completed without issues"
      fi
    else
      arr_compose_log_message "$log_file" $'yamllint reported issues:'
      printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
      arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
    fi

    if ((lint_status != 0)); then
      local fix_output=""
      local fix_changed=0
      local lint_needs_rerun=0
      fix_output="$(arr_compose_attempt_yaml_fixes "$staging" "$log_file" "$lint_output" 2>/dev/null)"
      local fix_line=""
      while IFS= read -r fix_line; do
        if [[ "$fix_line" =~ ^changed=([01])$ ]]; then
          fix_changed="${BASH_REMATCH[1]}"
        elif [[ "$fix_line" =~ ^rerun=([01])$ ]]; then
          lint_needs_rerun="${BASH_REMATCH[1]}"
        elif [[ -n "$fix_line" ]]; then
          summary+=("$fix_line")
        fi
      done <<<"$fix_output"

      if ((fix_changed)); then
        if ! arr_compose_run_yq_roundtrip "$staging" "$log_file"; then
          arr_compose_save_artifact "$staging" "$log_file" "failed"
          if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
            cp -f "$snapshot_path" "$staging" 2>/dev/null || true
            arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yq failure"
          fi
          printf '%s\n' "auto-repair aborted: yq canonicalization failed"
          return 1
        fi
        if ((ARR_COMPOSE_YQ_CHANGED)) && ((yq_summary_added == 0)); then
          summary+=("normalized YAML with yq")
          yq_summary_added=1
        fi
        if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "yamllint repair"; then
          arr_compose_save_artifact "$staging" "$log_file" "failed"
          if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
            cp -f "$snapshot_path" "$staging" 2>/dev/null || true
            arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after compose validation failure"
          fi
          printf '%s\n' "auto-repair aborted: compose validation failed"
          return 1
        fi
      fi

      if ((lint_needs_rerun)); then
        arr_compose_log_message "$log_file" "Re-running yamllint after autorepair fixes"
        lint_status=0
        lint_output="$("${yamllint_cmd[@]}" "$staging" 2>&1)" || lint_status=$?

        if ((lint_status == 0)); then
          if [[ -n "$lint_output" ]]; then
            arr_compose_log_message "$log_file" $'yamllint reported warnings after autorepair:'
            printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
            arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
          else
            arr_compose_log_message "$log_file" "yamllint completed without issues after autorepair"
          fi
        else
          arr_compose_log_message "$log_file" $'yamllint reported issues after autorepair:'
          printf '%s\n' "$lint_output" >>"$log_file" 2>/dev/null || true
          arr_compose_log_offending_lines "$log_file" "$staging" "$lint_output"
        fi
      fi

      if ((lint_status != 0)); then
        arr_compose_save_artifact "$staging" "$log_file" "failed"
        if [[ -n "$snapshot_path" && -f "$snapshot_path" ]]; then
          cp -f "$snapshot_path" "$staging" 2>/dev/null || true
          arr_compose_log_message "$log_file" "Reverted to snapshot ${snapshot_path} after yamllint failure"
        fi
        printf '%s\n' "auto-repair aborted: yamllint errors remain"
        return 1
      fi
    fi
  else
    arr_compose_log_message "$log_file" "yamllint not available; skipping linting"
  fi

  arr_compose_log_message "$log_file" "Auto-repair completed successfully"
  printf '%s\n' "${summary[@]}"
  return 0
}

arr_compose_autorepair_and_validate() {
  local staging="$1"
  local target="$2"

  if [[ -z "$staging" || ! -f "$staging" || -z "$target" ]]; then
    warn "compose autorepair requires staging and target paths"
    return 1
  fi

  local log_dir
  log_dir="$(arr_log_dir)"
  ensure_dir_mode "$log_dir" "$DATA_DIR_MODE"

  local log_file="${log_dir}/compose-repair.log"

  if ! arr_compose_prepare_log_file "$log_file"; then
    warn "Unable to prepare compose repair log at ${log_file}"
  fi

  local compose_cmd_raw=""
  local compose_detect_status=0
  compose_cmd_raw="$(detect_compose_cmd)" || compose_detect_status=$?
  if ((compose_detect_status != 0)); then
    compose_cmd_raw=""
  fi

  local summary_output=""
  local autorepair_status=0
  summary_output="$(arr_compose_autorepair "$staging" "$log_file" "$compose_cmd_raw" 2>/dev/null)" || autorepair_status=$?
  local -a summary_lines=()
  if [[ -n "$summary_output" ]]; then
    mapfile -t summary_lines <<<"$summary_output"
  fi

  if ((autorepair_status != 0)); then
    warn "Compose auto-repair failed; see ${log_file}"
    return 1
  fi

  local -a compose_cmd=()
  if [[ -z "$compose_cmd_raw" ]]; then
    arr_compose_log_message "$log_file" "Docker Compose unavailable; validation skipped"
    summary_lines+=("validation skipped (compose command unavailable)")
  else
    read -r -a compose_cmd <<<"$compose_cmd_raw"
    if ((${#compose_cmd[@]} > 0)); then
      if ! arr_compose_validate_with_compose "$staging" "$log_file" "$compose_cmd_raw" "final validation"; then
        warn "Docker Compose validation failed; see ${log_file}"
        return 1
      fi
      summary_lines+=("validated with ${compose_cmd[*]} config --quiet")
    fi
  fi

  if ! arr_safe_compose_write "$target" "$staging"; then
    arr_compose_log_message "$log_file" "Failed to install compose file at ${target}"
    warn "Failed to install ${target}"
    return 1
  fi

  ensure_nonsecret_file_mode "$target"
  arr_compose_log_message "$log_file" "Installed compose file at ${target}"

  local summary_message=""
  local applied_count="${#summary_lines[@]}"
  if ((applied_count > 0)); then
    summary_message="$(printf '%s, ' "${summary_lines[@]}")"
    summary_message="${summary_message%, }"
  fi

  if ((applied_count > 0)); then
    arr_compose_log_message "$log_file" "Summary: ${summary_message}"
    msg "compose auto-repair: applied ${applied_count} change(s); see ${log_file}"
  else
    msg "compose auto-repair: no changes required; see ${log_file}"
  fi

  return 0
}

arr_validate_compose_prerequisites() {
  local -a errors=()

  if [[ -z "${PUID:-}" ]]; then
    errors+=("PUID not set")
  fi
  if [[ -z "${PGID:-}" ]]; then
    errors+=("PGID not set")
  fi

  if [[ "${SPLIT_VPN:-0}" == "1" || "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    if [[ -z "${LAN_IP:-}" || "$LAN_IP" == "0.0.0.0" ]]; then
      errors+=("LAN_IP required for split/direct mode")
    fi
  fi

  if ((${#errors[@]} == 0)); then
    return 0
  fi

  warn "Compose prerequisites failed:"
  local err
  for err in "${errors[@]}"; do
    warn "  - ${err}"
  done
  return 1
}
append_sabnzbd_service_body() {
  local target="$1"
  local include_direct_port="${2:-0}"
  local sab_internal_fallback="${SABNZBD_INT_PORT:-8080}"
  local internal_port="${3:-${sab_internal_fallback}}"

  local sab_timeout_for_health
  arr_resolve_positive_int sab_timeout_for_health "${SABNZBD_TIMEOUT:-}" 60
  local health_start_period_seconds=60
  if ((sab_timeout_for_health > health_start_period_seconds)); then
    health_start_period_seconds="$sab_timeout_for_health"
  fi

  cat <<'YAML' >>"$target"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/sab/config:/config"
      - "${ARR_DOCKER_DIR}/sab/incomplete:/incomplete"
      - "${ARR_DOCKER_DIR}/sab/downloads:/downloads"
YAML

  if [[ "$include_direct_port" == "1" ]]; then
    cat <<'YAML' >>"$target"
    ports:
YAML
    arr_yaml_list_item "      " "${LAN_IP}:${SABNZBD_PORT}:${internal_port}" >>"$target"
  fi

  printf '%s\n' "    healthcheck:" >>"$target"
  local _health_url
  _health_url="$(arr_yaml_escape "http://${LOCALHOST_IP}:${internal_port}/api?mode=version&output=json")"
  printf '%s\n' "      test: [\"CMD\", \"curl\", \"-fsS\", ${_health_url}]" >>"$target"
  arr_yaml_kv "      " "interval" "30s" >>"$target"
  arr_yaml_kv "      " "timeout" "5s" >>"$target"
  arr_yaml_kv "      " "retries" "5" >>"$target"
  arr_yaml_kv "      " "start_period" "${health_start_period_seconds}s" >>"$target"

  cat <<'YAML' >>"$target"
    restart: "unless-stopped"
    # NOTE: Future hardening opportunity — consider CPU/memory limits and a read_only filesystem once defaults are vetted.
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML
}

# Generates docker-compose.yml tuned for split VPN (qBittorrent-only tunnel)
write_compose_split_mode() {
  step "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local tmp
  local sab_internal_port
  arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080

  if ! arr_validate_compose_prerequisites; then
    die "Compose prerequisites not satisfied"
  fi

  LOCAL_DNS_STATE="split-disabled"
  LOCAL_DNS_STATE_REASON="Local DNS disabled in split mode (SPLIT_VPN=1)"

  tmp="$(arr_mktemp_file "${compose_path}.XXXXXX.tmp" "$NONSECRET_FILE_MODE")" || die "Failed to create temp file for ${compose_path}"
  ensure_nonsecret_file_mode "$tmp"

  cat <<'YAML' >>"$tmp"
# -----------------------------------------------------------------------------
# docker-compose.yml is auto-generated by the stack script. Do not edit manually.
# Split VPN mode is active: only qBittorrent shares gluetun's network namespace
# while the *Arr applications run on arr_net (standard bridge) outside the VPN.
# -----------------------------------------------------------------------------
# Caddy reverse proxy disabled automatically (SPLIT_VPN=1).
services:
  gluetun:
    image: "${GLUETUN_IMAGE}"
    container_name: "gluetun"
    profiles:
      - "ipdirect"
YAML

  cat <<'YAML' >>"$tmp"
    cap_add:
      - "NET_ADMIN"
    devices:
      - "/dev/net/tun"
    environment:
      VPN_SERVICE_PROVIDER: "${VPN_SERVICE_PROVIDER}"
      VPN_TYPE: "openvpn"
      OPENVPN_USER: "${OPENVPN_USER}"
      OPENVPN_PASSWORD: "${OPENVPN_PASSWORD}"
      FREE_ONLY: "off"
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: "protonvpn"
      HTTP_CONTROL_SERVER_ADDRESS: "0.0.0.0:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: "${GLUETUN_API_KEY}"
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: "${QBT_USER}"
      QBT_PASS: "${QBT_PASS}"
      QBITTORRENT_ADDR: "http://${LOCALHOST_IP}:${QBT_INT_PORT}"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_INPUT_PORTS: "${GLUETUN_FIREWALL_INPUT_PORTS}"
      UPDATER_PERIOD: "24h"
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/gluetun:/gluetun"
    ports:
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:${QBT_PORT}:${QBT_INT_PORT}"
YAML

  cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          set -eu;
          /gluetun-entrypoint healthcheck >/dev/null;
          if ! ({ ip -4 route show default; ip -6 route show default; } 2>/dev/null | LC_ALL=C grep -Eq 'dev (tun[0-9]+|wg[0-9]+)' || \
            ip -o link show 2>/dev/null | LC_ALL=C grep -Eq '[[:space:]](tun[0-9]+|wg[0-9]+):'); then
            exit 1;
          fi;
          if command -v curl >/dev/null 2>&1; then
            curl -fsS --connect-timeout 5 --max-time 8 https://api.ipify.org >/dev/null || exit 1;
          elif command -v wget >/dev/null 2>&1; then
            wget -q -T 8 -O- https://api.ipify.org >/dev/null || exit 1;
          else
            exit 1;
          fi
      interval: "30s"
      timeout: "30s"
      retries: "10"
      start_period: "120s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "3"

YAML

  cat <<'YAML' >>"$tmp"
  qbittorrent:
    image: "${QBITTORRENT_IMAGE}"
    container_name: "qbittorrent"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
      QBT_INT_PORT: "${QBT_INT_PORT}"
      QBT_BIND_ADDR: "${QBT_BIND_ADDR}"
      QBT_ENFORCE_WEBUI: "${QBT_ENFORCE_WEBUI}"
      QBT_WEBUI_INIT_HOOK: 1
YAML

  if [[ -n "${QBT_DOCKER_MODS}" ]]; then
    #  write the literal ${QBT_DOCKER_MODS} token instead of expanding it at generation time
    # shellcheck disable=SC2016  # intentional literal for compose placeholder
    arr_yaml_kv "      " "DOCKER_MODS" '${QBT_DOCKER_MODS}' >>"$tmp"
  fi

  cat <<'YAML' >>"$tmp"
    volumes:
      - "${ARR_DOCKER_DIR}/qbittorrent:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${ARR_STACK_DIR}/scripts/qbt-helper.sh:/custom-cont-init.d/00-qbt-webui:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD", "/custom-cont-init.d/00-qbt-webui", "healthcheck"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: "${SONARR_IMAGE}"
    container_name: "sonarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/sonarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${TV_DIR}:/tv"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: "${RADARR_IMAGE}"
    container_name: "radarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/radarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${MOVIES_DIR}:/movies"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: "${PROWLARR_IMAGE}"
    container_name: "prowlarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/prowlarr:/config"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: "${BAZARR_IMAGE}"
    container_name: "bazarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/bazarr:/config"
      - "${TV_DIR}:/tv"
      - "${MOVIES_DIR}:/movies"
YAML

  if [[ -n "${SUBS_DIR:-}" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${SUBS_DIR}:/subs"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: "${FLARR_IMAGE}"
    container_name: "flaresolverr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
YAML

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
    ports:
      - "${LAN_IP}:${FLARR_PORT}:${FLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    environment:
      LOG_LEVEL: "info"
    healthcheck:
      test: ["CMD-SHELL", "if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 10 http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health; elif command -v wget >/dev/null 2>&1; then wget -q --timeout=10 -O- http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health; else exit 1; fi"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
      start_period: "40s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML

  if [[ "${SABNZBD_ENABLED}" == "1" ]]; then
    local sab_internal_port
    arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080
    cat <<'YAML' >>"$tmp"
  sabnzbd:
    image: "${SABNZBD_IMAGE}"
    container_name: "sabnzbd"
    profiles:
      - "ipdirect"
YAML
    if [[ "${SABNZBD_USE_VPN}" == "1" ]]; then
      cat <<'YAML' >>"$tmp"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
      append_sabnzbd_service_body "$tmp" "0" "$sab_internal_port"
    else
      cat <<'YAML' >>"$tmp"
    networks:
      - "arr_net"
YAML
      local expose_direct_port="0"
      if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
        expose_direct_port="1"
      fi
      append_sabnzbd_service_body "$tmp" "$expose_direct_port" "$sab_internal_port"
    fi
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
  configarr:
    image: "${CONFIGARR_IMAGE}"
    container_name: "configarr"
    profiles:
      - "ipdirect"
    networks:
      - "arr_net"
    depends_on:
      sonarr:
        condition: "service_started"
      radarr:
        condition: "service_started"
    volumes:
      - "${ARR_DOCKER_DIR}/configarr/config.yml:/app/config.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/secrets.yml:/app/secrets.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/cfs:/app/cfs:ro"
    working_dir: "/app"
    entrypoint: ["/bin/sh","-lc","node dist/index.js || exit 1"]
    environment:
      TZ: "${TIMEZONE}"
    restart: "no"
    logging:
      driver: "json-file"
      options:
        max-size: "512k"
        max-file: "2"
YAML
  fi

  cat <<'YAML' >>"$tmp"

networks:
  arr_net:
    name: "${COMPOSE_PROJECT_NAME}_arr_net"
    driver: "bridge"
YAML

  printf '\n' >>"$tmp"

  if ! verify_single_level_env_placeholders "$tmp"; then
    arr_cleanup_temp_path "$tmp"
    die "Generated docker-compose.yml contains nested environment placeholders"
  fi

  if ! arr_compose_autofix_env_names "$tmp" "${ARR_ENV_FILE:-}"; then
    arr_cleanup_temp_path "$tmp"
    die "Failed to normalize compose environment placeholders"
  fi

  if ! arr_verify_compose_placeholders "$tmp" "${ARR_ENV_FILE:-}"; then
    arr_cleanup_temp_path "$tmp"
    die "Generated docker-compose.yml contains unexpected environment placeholders"
  fi

  if ! arr_compose_autorepair_and_validate "$tmp" "$compose_path"; then
    arr_cleanup_temp_path "$tmp"
    die "Compose validation failed (see logs/compose-repair.log)"
  fi

  msg "  Local DNS status: ${LOCAL_DNS_STATE_REASON} (LOCAL_DNS_STATE=${LOCAL_DNS_STATE})"
}

# Generates docker-compose.yml for default mode, gating optional services on runtime checks
write_compose() {
  if [[ "${SPLIT_VPN:-0}" == "1" ]]; then
    write_compose_split_mode
    return
  fi

  step "🐳 Writing docker-compose.yml"

  local compose_path="${ARR_STACK_DIR}/docker-compose.yml"
  local tmp

  if ! arr_validate_compose_prerequisites; then
    die "Compose prerequisites not satisfied"
  fi

  LOCAL_DNS_STATE="inactive"
  LOCAL_DNS_STATE_REASON="Local DNS container disabled (ENABLE_LOCAL_DNS=0)"
  local include_caddy=0
  local include_local_dns=0
  local -a upstream_dns_servers=()
  local userconf_path="${ARR_USERCONF_PATH:-}"
  if [[ -z "${userconf_path}" ]]; then
    if ! userconf_path="$(arr_default_userconf_path 2>/dev/null)"; then
      userconf_path="userr.conf"
    fi
  fi

  mapfile -t upstream_dns_servers < <(collect_upstream_dns_servers)

  if [[ "${ENABLE_CADDY:-0}" == "1" ]]; then
    include_caddy=1
  fi

  if [[ "${ENABLE_LOCAL_DNS:-0}" == "1" ]]; then
    include_local_dns=1
    LOCAL_DNS_STATE="requested"
    LOCAL_DNS_STATE_REASON="Local DNS container requested"
  fi

  if ((include_local_dns)); then
    if port_bound_any udp 53 || port_bound_any tcp 53; then
      include_local_dns=0
      LOCAL_DNS_STATE="blocked"
      LOCAL_DNS_STATE_REASON="Local DNS disabled automatically (port 53 already in use)"
      warn "Port 53 is already in use (likely systemd-resolved). Local DNS will be disabled (LOCAL_DNS_STATE=blocked)."
    fi
  fi

  if ((include_local_dns)); then
    LOCAL_DNS_STATE="active"
    LOCAL_DNS_STATE_REASON="Local DNS container enabled"
    if [[ -z "${LAN_IP:-}" || "${LAN_IP}" == "0.0.0.0" ]]; then
      warn "Local DNS will bind to all interfaces (0.0.0.0:53)"
    fi
  fi

  tmp="$(arr_mktemp_file "${compose_path}.XXXXXX.tmp" "$NONSECRET_FILE_MODE")" || die "Failed to create temp file for ${compose_path}"
  ensure_nonsecret_file_mode "$tmp"

  cat <<'YAML' >>"$tmp"
# -----------------------------------------------------------------------------
# docker-compose.yml is auto-generated by the stack script. Do not edit manually.
# All application containers join gluetun's network namespace so every request
# exits via the VPN (network_mode: "service:gluetun"). container_name values
# are fixed to give helper scripts predictable targets; scaling is out of scope.
# -----------------------------------------------------------------------------
YAML

  if ((include_caddy == 0)); then
    arr_yaml_comment "" "Caddy reverse proxy disabled (ENABLE_CADDY=0)." >>"$tmp"
    arr_yaml_comment "" "Set ENABLE_CADDY=1 in ${userconf_path} and rerun ./${STACK}.sh to add HTTPS hostnames via Caddy." >>"$tmp"
  fi

  cat <<'YAML' >>"$tmp"
services:
  gluetun:
    image: "${GLUETUN_IMAGE}"
    container_name: "gluetun"
    profiles:
      - "ipdirect"
    cap_add:
      - "NET_ADMIN"
    devices:
      - "/dev/net/tun"
    environment:
      VPN_SERVICE_PROVIDER: "${VPN_SERVICE_PROVIDER}"
      VPN_TYPE: "openvpn"
      OPENVPN_USER: "${OPENVPN_USER}"
      OPENVPN_PASSWORD: "${OPENVPN_PASSWORD}"
      FREE_ONLY: "off"
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: "protonvpn"
      HTTP_CONTROL_SERVER_ADDRESS: "0.0.0.0:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_AUTH: "apikey"
      HTTP_CONTROL_SERVER_APIKEY: "${GLUETUN_API_KEY}"
      VPN_PORT_FORWARDING_UP_COMMAND: "/gluetun/hooks/update-qbt-port.sh {{PORTS}}"
      QBT_USER: "${QBT_USER}"
      QBT_PASS: "${QBT_PASS}"
      QBITTORRENT_ADDR: "http://${LOCALHOST_IP}:${QBT_INT_PORT}"
      HEALTH_TARGET_ADDRESS: "1.1.1.1:443"
      HEALTH_VPN_DURATION_INITIAL: "30s"
      HEALTH_VPN_DURATION_ADDITION: "10s"
      HEALTH_SUCCESS_WAIT_DURATION: "10s"
      DNS_KEEP_NAMESERVER: "off"
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_INPUT_PORTS: "${GLUETUN_FIREWALL_INPUT_PORTS}"
      UPDATER_PERIOD: "24h"
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
    volumes:
      - "${ARR_DOCKER_DIR}/gluetun:/gluetun"
    ports:
      # Centralize host exposure since all services share gluetun's namespace
      - "${LOCALHOST_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"
      - "${LAN_IP}:${QBT_PORT}:${QBT_INT_PORT}"
YAML

  if ((include_caddy)); then
    cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${CADDY_HTTP_PORT}:${CADDY_HTTP_PORT}"
      - "${LAN_IP}:${CADDY_HTTPS_PORT}:${CADDY_HTTPS_PORT}"
YAML
  fi

  if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_INT_PORT}"
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_INT_PORT}"
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_INT_PORT}"
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_INT_PORT}"
      - "${LAN_IP}:${FLARR_PORT}:${FLARR_INT_PORT}"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          set -eu;
          /gluetun-entrypoint healthcheck >/dev/null;
          if ! ({ ip -4 route show default; ip -6 route show default; } 2>/dev/null | LC_ALL=C grep -Eq 'dev (tun[0-9]+|wg[0-9]+)' || \
            ip -o link show 2>/dev/null | LC_ALL=C grep -Eq '[[:space:]](tun[0-9]+|wg[0-9]+):'); then
            exit 1;
          fi;
          if command -v curl >/dev/null 2>&1; then
            curl -fsS --connect-timeout 5 --max-time 8 https://api.ipify.org >/dev/null || exit 1;
          elif command -v wget >/dev/null 2>&1; then
            wget -q -T 8 -O- https://api.ipify.org >/dev/null || exit 1;
          else
            exit 1;
          fi
      interval: "30s"
      timeout: "30s"
      retries: "10"
      start_period: "120s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "3"
YAML

  if ((include_local_dns)); then
    cat <<'YAML' >>"$tmp"
  local_dns:
    image: "${LOCALDNS_IMAGE}"
    container_name: "arr_local_dns"
    profiles:
      - "localdns"
    cap_add:
      - "NET_ADMIN"
    ports:
      - "${LAN_IP}:53:53/udp"
      - "${LAN_IP}:53:53/tcp"
    command:
      - "--log-facility=-"
      - "--log-async=5"
      - "--log-queries"
      - "--no-resolv"
YAML
    local server
    for server in "${upstream_dns_servers[@]}"; do
      arr_yaml_list_item "      " "--server=${server}" >>"$tmp"
    done
    cat <<'YAML' >>"$tmp"
      - "--domain-needed"
      - "--bogus-priv"
      - "--local-service"
      - "--domain=${LAN_DOMAIN_SUFFIX}"
      - "--local=/${LAN_DOMAIN_SUFFIX}/"
      - "--address=/${LAN_DOMAIN_SUFFIX}/${DNS_HOST_ENTRY}"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          if command -v drill >/dev/null 2>&1; then
            drill -Q example.com @${LOCALHOST_IP} >/dev/null 2>&1;
          elif command -v nslookup >/dev/null 2>&1; then
            nslookup example.com ${LOCALHOST_IP} >/dev/null 2>&1;
          elif command -v dig >/dev/null 2>&1; then
            dig +time=2 +tries=1 @${LOCALHOST_IP} example.com >/dev/null 2>&1;
          else
            exit 1;
          fi
      interval: "10s"
      timeout: "3s"
      retries: "6"
      start_period: "10s"

YAML
  fi

  cat <<'YAML' >>"$tmp"
  qbittorrent:
    image: "${QBITTORRENT_IMAGE}"
    container_name: "qbittorrent"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
      QBT_INT_PORT: "${QBT_INT_PORT}"
      QBT_BIND_ADDR: "${QBT_BIND_ADDR}"
      QBT_ENFORCE_WEBUI: "${QBT_ENFORCE_WEBUI}"
      QBT_WEBUI_INIT_HOOK: "1"
YAML
  if [[ -n "${QBT_DOCKER_MODS}" ]]; then
    #  write the literal ${QBT_DOCKER_MODS} token instead of expanding it at generation time
    # shellcheck disable=SC2016  # intentional literal for compose placeholder
    arr_yaml_kv "      " "DOCKER_MODS" '${QBT_DOCKER_MODS}' >>"$tmp"
  fi
  cat <<'YAML' >>"$tmp"
    volumes:
      - "${ARR_DOCKER_DIR}/qbittorrent:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${ARR_STACK_DIR}/scripts/qbt-helper.sh:/custom-cont-init.d/00-qbt-webui:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD", "/custom-cont-init.d/00-qbt-webui", "healthcheck"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  sonarr:
    image: "${SONARR_IMAGE}"
    container_name: "sonarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/sonarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${TV_DIR}:/tv"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  radarr:
    image: "${RADARR_IMAGE}"
    container_name: "radarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/radarr:/config"
      - "${DOWNLOADS_DIR}:/downloads"
      - "${COMPLETED_DIR}:/completed"
      - "${MOVIES_DIR}:/movies"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  prowlarr:
    image: "${PROWLARR_IMAGE}"
    container_name: "prowlarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/prowlarr:/config"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  bazarr:
    image: "${BAZARR_IMAGE}"
    container_name: "bazarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      PUID: "${PUID}"
      PGID: "${PGID}"
      TZ: "${TIMEZONE}"
      LANG: "en_US.UTF-8"
    volumes:
      - "${ARR_DOCKER_DIR}/bazarr:/config"
      - "${TV_DIR}:/tv"
      - "${MOVIES_DIR}:/movies"
YAML

  if [[ -n "${SUBS_DIR:-}" ]]; then
    cat <<'YAML' >>"$tmp"
      - "${SUBS_DIR}:/subs"
YAML
  fi

  cat <<'YAML' >>"$tmp"
    depends_on:
      gluetun:
        condition: "service_healthy"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"

  flaresolverr:
    image: "${FLARR_IMAGE}"
    container_name: "flaresolverr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: "info"
    depends_on:
      gluetun:
        condition: "service_healthy"
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS --max-time 10 http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health || wget -q --timeout=10 -O- http://${LOCALHOST_IP}:${FLARR_INT_PORT}/health || exit 1"]
      interval: "30s"
      timeout: "10s"
      retries: "3"
      start_period: "40s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML

  if [[ "${SABNZBD_ENABLED}" == "1" ]]; then
    local sab_internal_port
    arr_resolve_port sab_internal_port "${SABNZBD_INT_PORT:-}" 8080
    cat <<'YAML' >>"$tmp"
  sabnzbd:
    image: "${SABNZBD_IMAGE}"
    container_name: "sabnzbd"
    profiles:
      - "ipdirect"
YAML
    if [[ "${SABNZBD_USE_VPN}" == "1" ]]; then
      cat <<'YAML' >>"$tmp"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
      append_sabnzbd_service_body "$tmp" "0" "$sab_internal_port"
    else
      local expose_direct_port="0"
      if [[ "${EXPOSE_DIRECT_PORTS:-0}" == "1" ]]; then
        expose_direct_port="1"
      fi
      append_sabnzbd_service_body "$tmp" "$expose_direct_port" "$sab_internal_port"
    fi
  fi

  if [[ "${ENABLE_CONFIGARR:-0}" == "1" ]]; then
    cat <<'YAML' >>"$tmp"
  configarr:
    image: "${CONFIGARR_IMAGE}"
    container_name: "configarr"
    profiles:
      - "ipdirect"
    network_mode: "service:gluetun"
    depends_on:
      gluetun:
        condition: "service_healthy"
      sonarr:
        condition: "service_started"
      radarr:
        condition: "service_started"
    volumes:
      - "${ARR_DOCKER_DIR}/configarr/config.yml:/app/config.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/secrets.yml:/app/secrets.yml:ro"
      - "${ARR_DOCKER_DIR}/configarr/cfs:/app/cfs:ro"
    working_dir: "/app"
    entrypoint: ["/bin/sh","-lc","node dist/index.js || exit 1"]
    environment:
      TZ: "${TIMEZONE}"
    restart: "no"
    logging:
      driver: "json-file"
      options:
        max-size: "512k"
        max-file: "2"
YAML
  fi

  if ((include_caddy)); then
    cat <<'YAML' >>"$tmp"
  caddy:
    image: "${CADDY_IMAGE}"
    container_name: "caddy"
    profiles:
      - "proxy"
    network_mode: "service:gluetun"
    volumes:
      - "${ARR_DOCKER_DIR}/caddy/Caddyfile:/etc/caddy/Caddyfile:ro"
      - "${ARR_DOCKER_DIR}/caddy/data:/data"
      - "${ARR_DOCKER_DIR}/caddy/config:/config"
      - "${ARR_DOCKER_DIR}/caddy/ca-pub:/ca-pub:ro"
    depends_on:
      gluetun:
        condition: "service_healthy"
YAML
    if ((include_local_dns)); then
      cat <<'YAML' >>"$tmp"
      local_dns:
        condition: "service_healthy"
YAML
    fi
    cat <<'YAML' >>"$tmp"
    healthcheck:
      test:
        - "CMD-SHELL"
        - >-
          curl -fsS --max-time 3 http://${LOCALHOST_IP}:${CADDY_HTTP_PORT}/healthz >/dev/null 2>&1 || curl -fsS --max-time 3 http://${LOCALHOST_IP}/healthz >/dev/null 2>&1 || wget -qO- --timeout=3 http://${LOCALHOST_IP}:${CADDY_HTTP_PORT}/healthz >/dev/null 2>&1
      interval: "10s"
      timeout: "5s"
      retries: "6"
      start_period: "20s"
    restart: "unless-stopped"
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
YAML
  fi

  printf '\n' >>"$tmp"

  if ! verify_single_level_env_placeholders "$tmp"; then
    arr_cleanup_temp_path "$tmp"
    die "Generated docker-compose.yml contains nested environment placeholders"
  fi

  if ! arr_compose_autofix_env_names "$tmp" "${ARR_ENV_FILE:-}"; then
    arr_cleanup_temp_path "$tmp"
    die "Failed to normalize compose environment placeholders"
  fi

  if ! arr_verify_compose_placeholders "$tmp" "${ARR_ENV_FILE:-}"; then
    arr_cleanup_temp_path "$tmp"
    die "Generated docker-compose.yml contains unexpected environment placeholders"
  fi

  if ! arr_compose_autorepair_and_validate "$tmp" "$compose_path"; then
    arr_cleanup_temp_path "$tmp"
    die "Compose validation failed (see logs/compose-repair.log)"
  fi

  msg "  Local DNS status: ${LOCAL_DNS_STATE_REASON} (LOCAL_DNS_STATE=${LOCAL_DNS_STATE})"
}
# Writes Gluetun hook/auth assets so API key and port forwarding stay aligned

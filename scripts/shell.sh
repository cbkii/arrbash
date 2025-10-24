# shellcheck shell=bash

: "${ARR_SHELL_RELOAD_PENDING:=0}"
ARR_SHELL_LAST_STATUS="${ARR_SHELL_LAST_STATUS:-}"

# Detects current shell and whether oh-my-zsh is installed for reload hooks
detect_shell_kind() {
  local kind="other"
  local omz=0

  if [ -n "${ZSH_VERSION:-}" ]; then
    kind="zsh"
    if [ -n "${ZSH:-}" ] && [ -d "$ZSH" ] && [ -f "$ZSH/oh-my-zsh.sh" ]; then
      omz=1
    elif [ -d "$HOME/.oh-my-zsh" ] && [ -f "$HOME/.oh-my-zsh/oh-my-zsh.sh" ]; then
      omz=1
    fi
  elif [ -n "${BASH_VERSION:-}" ]; then
    kind="bash"
  elif printf '%s' "${SHELL:-}" | grep -q 'zsh'; then
    kind="zsh"
  elif printf '%s' "${SHELL:-}" | grep -q 'bash'; then
    kind="bash"
  fi

  printf '%s %s\n' "$kind" "$omz"
}

arr_shell_is_linux() {
  local uname_s
  if ! uname_s="$(uname -s 2>/dev/null)"; then
    return 1
  fi

  case "${uname_s}" in
    Linux|LINUX)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

arr_shell_resolve_rc_path() {
  local prefer_existing=0
  if [[ "${1:-}" == "--prefer-existing" ]]; then
    prefer_existing=1
    shift
  fi

  local signature kind omz rc=""
  signature="$(detect_shell_kind)"
  read -r kind omz <<<"${signature}"

  case "${kind}" in
    zsh)
      rc="${HOME}/.zshrc"
      if (( prefer_existing )) && [[ ! -r "${rc}" ]]; then
        rc=""
      fi
      ;;
    bash)
      rc="${HOME}/.bashrc"
      if (( prefer_existing )) && [[ ! -r "${rc}" ]]; then
        if [[ -r "${HOME}/.bash_profile" ]]; then
          rc="${HOME}/.bash_profile"
        elif [[ -r "${HOME}/.profile" ]]; then
          rc="${HOME}/.profile"
        else
          rc=""
        fi
      fi
      ;;
    *)
      if [[ -r "${HOME}/.profile" ]]; then
        rc="${HOME}/.profile"
      elif [[ -r "${HOME}/.bash_profile" ]]; then
        rc="${HOME}/.bash_profile"
      elif (( prefer_existing == 0 )); then
        rc="${HOME}/.profile"
      fi
      ;;
  esac

  printf '%s\n' "${rc}"
}

arr_shell_clear_env() {
  local -A skip=()
  local name

  for name in "$@"; do
    [[ -n "${name}" ]] || continue
    skip["${name}"]=1
  done

  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    if [[ -n "${skip[${name}]:-}" ]]; then
      continue
    fi
    unset -v "${name}" 2>/dev/null || :
  done < <(compgen -v ARR_)

  for name in STACK STACK_UPPER STACK_TAG; do
    [[ -n "${name}" ]] || continue
    if [[ -n "${skip[${name}]:-}" ]]; then
      continue
    fi
    unset -v "${name}" 2>/dev/null || :
  done
}

arr_mark_shell_reload_pending() {
  ARR_SHELL_RELOAD_PENDING=1
}

arr_shell_print_manual_steps() {
  local -a steps=("$@")
  (( ${#steps[@]} )) || return 0

  warn "Could not automatically reload your shell configuration"
  msg "ℹ️ Run these commands to refresh your session:"
  local step
  for step in "${steps[@]}"; do
    msg "   ${step}"
  done
}

arr_shell_safe_source() {
  local file="$1"
  local export_all="${2:-0}"

  local had_nounset=0 had_errexit=0 had_allexport=0
  case $- in
    *u*)
      had_nounset=1
      set +u
      ;;
  esac
  case $- in
    *e*)
      had_errexit=1
      set +e
      ;;
  esac
  if (( export_all )); then
    had_allexport=1
    set -a
  fi

  # shellcheck disable=SC1090
  . "${file}"
  local status=$?

  if (( had_allexport )); then
    set +a
  fi
  if (( had_nounset )); then
    set -u
  fi
  if (( had_errexit )); then
    set -e
  fi

  return "${status}"
}

# Reloads the active shell configuration after alias updates
reload_shell_rc() {
  local clear_env=0
  local require_pending=0
  local schedule_only=0

  while [[ $# -gt 0 ]]; do
    case "${1}" in
      --clear-env)
        clear_env=1
        ;;
      --if-pending)
        require_pending=1
        ;;
      --schedule)
        schedule_only=1
        ;;
      *)
        ;;
    esac
    shift || true
  done

  if (( schedule_only )); then
    arr_mark_shell_reload_pending
    ARR_SHELL_LAST_STATUS="scheduled"
    return 0
  fi

  ARR_SHELL_LAST_STATUS=""

  if (( require_pending )) && (( ARR_SHELL_RELOAD_PENDING == 0 )); then
    ARR_SHELL_LAST_STATUS="skipped"
    return 0
  fi

  local stack_dir="${ARR_STACK_DIR:-}"
  if [[ -z "${stack_dir}" ]] && declare -f arr_stack_dir >/dev/null 2>&1; then
    stack_dir="$(arr_stack_dir)"
  fi

  local alias_path=""
  if [[ -n "${stack_dir}" ]]; then
    alias_path="${stack_dir%/}/.aliasarr"
  fi

  local env_file="${ARR_ENV_FILE:-}"
  if [[ -z "${env_file}" ]] && [[ -n "${stack_dir}" ]]; then
    env_file="${stack_dir%/}/.env"
  fi

  local user_conf="${ARR_USERCONF_PATH:-}"
  if [[ -z "${user_conf}" && -n "${ARRCONF_DIR:-}" ]]; then
    user_conf="${ARRCONF_DIR%/}/userr.conf"
  fi
  if [[ -z "${user_conf}" ]] && declare -f arr_conf_dir >/dev/null 2>&1; then
    user_conf="$(arr_conf_dir)/userr.conf"
  fi

  local rc_path="$(arr_shell_resolve_rc_path)"
  local rc_source_path="$(arr_shell_resolve_rc_path --prefer-existing)"
  if [[ -z "${rc_source_path}" && -n "${rc_path}" ]]; then
    rc_source_path="${rc_path}"
  fi

  local -a manual_steps=()
  if [[ -n "${user_conf}" && -r "${user_conf}" ]]; then
    manual_steps+=("source \"${user_conf}\"")
  fi
  if [[ -n "${env_file}" && -r "${env_file}" ]]; then
    manual_steps+=("set -a; source \"${env_file}\"; set +a")
  fi
  if [[ -n "${alias_path}" && -r "${alias_path}" ]]; then
    manual_steps+=("source \"${alias_path}\"")
  fi
  if [[ -n "${rc_source_path}" && -r "${rc_source_path}" ]]; then
    manual_steps+=("source \"${rc_source_path}\"")
  fi

  ARR_SHELL_RELOAD_PENDING=0

  if (( clear_env )); then
    arr_shell_clear_env "ARR_SHELL_RELOAD_PENDING" "ARR_SHELL_LAST_STATUS"
  fi

  if ! arr_shell_is_linux; then
    arr_shell_print_manual_steps "${manual_steps[@]}"
    ARR_SHELL_LAST_STATUS="manual"
    return 1
  fi

  local signature kind omz
  signature="$(detect_shell_kind)"
  read -r kind omz <<<"${signature}"

  if [[ ! -t 0 || ! -t 1 ]]; then
    arr_shell_print_manual_steps "${manual_steps[@]}"
    ARR_SHELL_LAST_STATUS="manual"
    return 1
  fi

  if [[ "${kind}" == "zsh" && -z "${ZSH_VERSION:-}" ]]; then
    arr_shell_print_manual_steps "${manual_steps[@]}"
    ARR_SHELL_LAST_STATUS="manual"
    return 1
  fi

  local success=1

  if [[ -n "${user_conf}" && -r "${user_conf}" ]]; then
    if ! arr_shell_safe_source "${user_conf}"; then
      success=0
    fi
  fi

  if (( success )) && [[ -n "${env_file}" && -r "${env_file}" ]]; then
    if ! arr_shell_safe_source "${env_file}" 1; then
      success=0
    fi
  fi

  if (( success )) && [[ -n "${alias_path}" && -r "${alias_path}" ]]; then
    if ! arr_shell_safe_source "${alias_path}"; then
      success=0
    fi
  fi

  if (( success )) && [[ -n "${rc_source_path}" && -r "${rc_source_path}" ]]; then
    if ! arr_shell_safe_source "${rc_source_path}"; then
      success=0
    fi
  fi

  if (( success )); then
    ARR_SHELL_LAST_STATUS="auto"
    return 0
  fi

  arr_shell_print_manual_steps "${manual_steps[@]}"
  ARR_SHELL_LAST_STATUS="manual"
  return 1
}

arr_finalize_shell_reload() {
  if reload_shell_rc --clear-env --if-pending; then
    msg "♻️ Shell configuration reloaded"
  elif [[ "${ARR_SHELL_LAST_STATUS}" == "manual" ]]; then
    return 0
  fi
  return 0
}

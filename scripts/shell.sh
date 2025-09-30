# shellcheck shell=bash
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

reload_shell_rc() {
  local force=0
  if [ "${1:-}" = "--force" ]; then
    force=1
  fi

  local kind=""
  local omz=""
  local shell_signature=""
  shell_signature="$(detect_shell_kind)"
  local IFS=' '
  read -r kind omz <<<"$shell_signature"
  [ -n "$kind" ] || kind="other"
  [ -n "$omz" ] || omz=0

  if [ "$kind" = "zsh" ] && [ -n "${ZSH_VERSION:-}" ] && [ "$omz" -eq 1 ] && have_command omz; then
    if omz reload; then
      return 0
    fi
  fi

  if [ "$kind" = "zsh" ] && [ -z "${ZSH_VERSION:-}" ]; then
    warn "Detected zsh login shell but running under bash; skipping automatic zsh reload"
    if [ "$force" -eq 1 ]; then
      return 0
    fi
    return 1
  fi

  local rc=""
  case "$kind" in
    zsh)
      [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
      ;;
    bash)
      if [ -r "$HOME/.bashrc" ]; then
        rc="$HOME/.bashrc"
      elif [ -r "$HOME/.bash_profile" ]; then
        rc="$HOME/.bash_profile"
      elif [ -r "$HOME/.profile" ]; then
        rc="$HOME/.profile"
      fi
      ;;
    *)
      [ -r "$HOME/.profile" ] && rc="$HOME/.profile"
      ;;
  esac

  if [ -z "$rc" ] && [ "$kind" = "zsh" ] && [ "$omz" -eq 1 ]; then
    [ -r "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
  fi

  if [ -n "$rc" ] && [ -r "$rc" ]; then
    local had_nounset=0 had_errexit=0
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

    # shellcheck disable=SC1090
    if ! . "$rc"; then
      local status=$?
      if [ "$had_nounset" -eq 1 ]; then
        set -u
      fi
      if [ "$had_errexit" -eq 1 ]; then
        set -e
      fi
      return $status
    fi

    if [ "$had_nounset" -eq 1 ]; then
      set -u
    fi
    if [ "$had_errexit" -eq 1 ]; then
      set -e
    fi
    return 0
  fi

  if [ "$force" -eq 1 ]; then
    return 0
  fi

  return 1
}

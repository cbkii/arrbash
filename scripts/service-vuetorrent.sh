# shellcheck shell=bash
# Purpose: Manage VueTorrent assets, detecting manual installs and orchestrating LSIO mod usage.
# Inputs: Uses ARR_DOCKER_DIR, VUETORRENT_MODE, VUETORRENT_ROOT, and environment-configured credentials.
# Outputs: Updates VueTorrent deployment directories and status variables consumed by summary/reporting.
# Exit codes: Functions return non-zero when manual install verification fails or downloads error out.

if [[ -n "${__SERVICE_VUETORRENT_LOADED:-}" ]]; then
  return 0
fi
__SERVICE_VUETORRENT_LOADED=1

vuetorrent_manual_is_complete() {
  local dir="$1"

  [[ -d "$dir" && -f "$dir/public/index.html" ]]
}

# Reads installed VueTorrent version from version.txt when available
vuetorrent_manual_version() {
  local dir="$1"

  if [[ -f "$dir/version.txt" ]]; then
    head -n1 "$dir/version.txt" 2>/dev/null | tr -d '\r\n'
  fi
}

vuetorrent_manual_unavailable() {
  # shellcheck disable=SC2034
  VUETORRENT_VERSION=""
  # shellcheck disable=SC2034
  VUETORRENT_ALT_ENABLED=0
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_LEVEL="warn"
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_MESSAGE="Manual VueTorrent install unavailable; qBittorrent default UI active."
  write_qbt_config
}

# Manages VueTorrent deployment, choosing LSIO mod or manual download as configured
install_vuetorrent() {
  local manual_dir="${ARR_DOCKER_DIR}/qbittorrent/vuetorrent"
  if [[ "${VUETORRENT_MODE}" != "manual" ]]; then
    step "Ensuring VueTorrent (LSIO Docker mod)"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_VERSION=""
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent via LSIO Docker mod (WebUI root ${VUETORRENT_ROOT})."
    if [[ -d "$manual_dir" ]]; then
      rm -rf "$manual_dir" 2>/dev/null || warn "Could not remove manual VueTorrent directory at ${manual_dir}"
    fi
    return 0
  fi

  step "Ensuring VueTorrent (manual mode)"

  if vuetorrent_manual_is_complete "$manual_dir"; then
    local version
    version="$(vuetorrent_manual_version "$manual_dir")"
    # shellcheck disable=SC2034
    VUETORRENT_VERSION="$version"
    # shellcheck disable=SC2034
    VUETORRENT_ALT_ENABLED=1
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_LEVEL="msg"
    if [[ -n "$version" ]]; then
      msg "  VueTorrent already present at ${manual_dir} (version ${version})"
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT} (version ${version})."
    else
      msg "  VueTorrent already present at ${manual_dir}"
      # shellcheck disable=SC2034
      VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT}."
    fi
    chown -R "${PUID}:${PGID}" "$manual_dir" 2>/dev/null || true
    return 0
  fi

  if ! check_dependencies curl unzip sha256sum; then
    warn "Missing curl, unzip, or sha256sum; skipping VueTorrent download"
    vuetorrent_manual_unavailable
    return 0
  fi

  local download_url
  if [[ -n "${VUETORRENT_DOWNLOAD_URL:-}" ]]; then
    download_url="${VUETORRENT_DOWNLOAD_URL}"
  else
    download_url="https://github.com/VueTorrent/VueTorrent/releases/latest/download/vuetorrent.zip"
  fi

  local tmp_archive
  if ! tmp_archive="$(arr_mktemp_file "/tmp/vuetorrent.download.XXXXXX" "$NONSECRET_FILE_MODE")"; then
    warn "Unable to create temporary file for VueTorrent archive"
    vuetorrent_manual_unavailable
    return 0
  fi

  local -a curl_args=(
    --fail
    --location
    --silent
    --show-error
    --output "$tmp_archive"
  )

  if ! curl "${curl_args[@]}" "$download_url" >/dev/null 2>&1; then
    local curl_status=$?
    arr_cleanup_temp_path "$tmp_archive"
    warn "Failed to download VueTorrent archive (curl exit status ${curl_status})"
    vuetorrent_manual_unavailable
    return 0
  fi

  local archive_sha
  archive_sha="$(sha256sum "$tmp_archive" 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$archive_sha" ]]; then
    msg "  VueTorrent archive SHA256 ${archive_sha}"
  fi

  if [[ -n "${VUETORRENT_SHA256:-}" && "$archive_sha" != "${VUETORRENT_SHA256}" ]]; then
    arr_cleanup_temp_path "$tmp_archive"
    warn "Downloaded VueTorrent archive checksum mismatch"
    vuetorrent_manual_unavailable
    return 0
  fi

  local extract_dir
  if ! extract_dir="$(arr_mktemp_dir "/tmp/vuetorrent.extract.XXXXXX")"; then
    arr_cleanup_temp_path "$tmp_archive"
    warn "Unable to create extraction directory for VueTorrent"
    vuetorrent_manual_unavailable
    return 0
  fi

  if ! unzip -qo "$tmp_archive" -d "$extract_dir"; then
    arr_cleanup_temp_path "$tmp_archive"
    arr_cleanup_temp_path "$extract_dir"
    warn "Failed to unzip VueTorrent archive"
    vuetorrent_manual_unavailable
    return 0
  fi

  arr_cleanup_temp_path "$tmp_archive"

  local source_root="$extract_dir"
  if [[ ! -f "$source_root/public/index.html" ]]; then
    local nested_public
    nested_public="$(find "$extract_dir" -type f -path '*/public/index.html' -print -quit 2>/dev/null || printf '')"
    if [[ -n "$nested_public" ]]; then
      source_root="$(dirname "$(dirname "$nested_public")")"
    fi
  fi

  if [[ ! -f "$source_root/public/index.html" ]]; then
    arr_cleanup_temp_path "$extract_dir"
    warn "VueTorrent archive missing public/index.html"
    vuetorrent_manual_unavailable
    return 0
  fi

  local staging_dir
  if ! staging_dir="$(arr_mktemp_dir "/tmp/vuetorrent.staging.XXXXXX")"; then
    arr_cleanup_temp_path "$extract_dir"
    warn "Unable to stage VueTorrent files"
    vuetorrent_manual_unavailable
    return 0
  fi

  if ! cp -a "$source_root"/. "$staging_dir"/; then
    arr_cleanup_temp_path "$extract_dir"
    arr_cleanup_temp_path "$staging_dir"
    warn "Failed to prepare VueTorrent files"
    vuetorrent_manual_unavailable
    return 0
  fi

  arr_cleanup_temp_path "$extract_dir"

  ensure_dir "${ARR_DOCKER_DIR}/qbittorrent"

  local backup_dir=""
  if [[ -d "$manual_dir" ]]; then
    backup_dir="${manual_dir}.bak.$$"
    if ! mv "$manual_dir" "$backup_dir"; then
      arr_cleanup_temp_path "$staging_dir"
      warn "Unable to move existing VueTorrent directory"
      vuetorrent_manual_unavailable
      return 0
    fi
  fi

  if ! mv "$staging_dir" "$manual_dir"; then
    arr_cleanup_temp_path "$staging_dir"
    if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
      mv "$backup_dir" "$manual_dir" 2>/dev/null || rm -rf "$backup_dir" 2>/dev/null || true
    fi
    warn "Failed to activate VueTorrent manual install"
    vuetorrent_manual_unavailable
    return 0
  fi

  arr_unregister_temp_path "$staging_dir"

  if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
    rm -rf "$backup_dir" 2>/dev/null || true
  fi

  chown -R "${PUID}:${PGID}" "$manual_dir" 2>/dev/null || true

  local version
  version="$(vuetorrent_manual_version "$manual_dir")"
  # shellcheck disable=SC2034
  VUETORRENT_VERSION="$version"
  # shellcheck disable=SC2034
  VUETORRENT_ALT_ENABLED=1
  # shellcheck disable=SC2034
  VUETORRENT_STATUS_LEVEL="msg"
  if [[ -n "$version" ]]; then
    msg "  VueTorrent installed at ${manual_dir} (version ${version})"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT} (version ${version})."
  else
    msg "  VueTorrent installed at ${manual_dir}"
    # shellcheck disable=SC2034
    VUETORRENT_STATUS_MESSAGE="VueTorrent manual install ready at ${VUETORRENT_ROOT}."
  fi
}

# Maps logical service names to compose container identifiers (handles overrides)
service_container_name() {
  local service="$1"
  case "$service" in
    local_dns)
      printf '%s' "arr_local_dns"
      ;;
    *)
      printf '%s' "$service"
      ;;
  esac
}

declare -a ARR_STACK_PREVIOUS_RUNNING_SERVICES=()
ARR_STACK_RUNTIME_STATE_CAPTURED=0
ARR_STACK_RUNTIME_STATE_RESTORED=0

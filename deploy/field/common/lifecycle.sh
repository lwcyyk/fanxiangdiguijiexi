#!/usr/bin/env bash
set -Eeuo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/field/common/lib.sh
source "${COMMON_DIR}/lib.sh"

PACKAGE_ROOT="$(field_package_root)"
KIND="$(<"${PACKAGE_ROOT}/PACKAGE-KIND")"
PACKAGE_VERSION="$(<"${PACKAGE_ROOT}/PACKAGE-VERSION")"
ACTION="${FIELD_ACTION:?FIELD_ACTION is required}"
INSTALL_ROOT="${RI_INSTALL_ROOT:-/opt/resolver-identity}"
CONFIG_DIR=""
REQUESTED_VERSION="${PACKAGE_VERSION}"
PURGE_DATA=false
RUNTIME_CHECK=false

while (($#)); do
  case "$1" in
    --config-dir)
      (($# >= 2)) || field_die "--config-dir requires a value"
      CONFIG_DIR="$2"
      shift 2
      ;;
    --version)
      (($# >= 2)) || field_die "--version requires a value"
      REQUESTED_VERSION="$2"
      shift 2
      ;;
    --purge-data)
      PURGE_DATA=true
      shift
      ;;
    --runtime)
      RUNTIME_CHECK=true
      shift
      ;;
    --installed)
      shift
      ;;
    *)
      field_die "unknown argument: $1"
      ;;
  esac
done

REQUESTED_VERSION="$(field_release_name "${REQUESTED_VERSION}")"

preflight() {
  field_require_command docker
  field_require_command sha256sum
  field_require_command df
  field_require_command cmp
  field_require_command install
  docker compose version >/dev/null
  field_verify_package "${PACKAGE_ROOT}"

  local disk_probe="${INSTALL_ROOT}"
  while [[ ! -e "${disk_probe}" && "${disk_probe}" != "/" ]]; do
    disk_probe="$(dirname "${disk_probe}")"
  done
  local free_mb
  free_mb="$(df -Pm "${disk_probe}" | awk 'NR==2 {print $4}')"
  if [[ -n "${free_mb}" ]]; then
    ((free_mb >= ${RI_FIELD_MIN_FREE_MB:-2048})) ||
      field_die "insufficient free disk space"
  fi

  if [[ "${RI_FIELD_SIMULATION:-false}" != "true" &&
    "${RI_FIELD_ALLOW_UNSYNCED_TIME:-false}" != "true" ]]; then
    field_require_command timedatectl
    [[ "$(timedatectl show -p NTPSynchronized --value)" == "yes" ]] ||
      field_die "system clock is not synchronized"
  fi
  field_log "preflight passed for ${KIND} ${PACKAGE_VERSION}"
}

install_release() {
  [[ -n "${CONFIG_DIR}" ]] || field_die "--config-dir is required"
  [[ -f "${CONFIG_DIR}/.env" && -f "${CONFIG_DIR}/host.json" ]] ||
    field_die "config directory must contain .env and host.json"
  preflight
  mkdir -p "${INSTALL_ROOT}/releases" "${INSTALL_ROOT}/state"
  field_acquire_lock "${INSTALL_ROOT}"

  local target="${INSTALL_ROOT}/releases/${REQUESTED_VERSION}"
  local previous
  previous="$(field_current_target "${INSTALL_ROOT}")"
  local temporary="${target}.tmp.$$"
  rm -rf "${temporary}"
  mkdir -p "${temporary}"
  cp -a "${PACKAGE_ROOT}/." "${temporary}/"
  rm -rf "${temporary}/config"
  cp -a "${CONFIG_DIR}" "${temporary}/config"

  if [[ -d "${target}" ]]; then
    if diff -qr "${target}" "${temporary}" >/dev/null; then
      rm -rf "${temporary}"
      field_log "release ${REQUESTED_VERSION} is already installed"
    else
      rm -rf "${temporary}"
      field_die "release ${REQUESTED_VERSION} already exists with different content"
    fi
  else
    mv "${temporary}" "${target}"
  fi

  field_load_env "${target}/config/.env"
  : "${RI_FIELD_DATA_DIR:?RI_FIELD_DATA_DIR is required}"
  if [[ "${KIND}" == "resolver-link" ]]; then
    field_backup_resolver_config \
      "${INSTALL_ROOT}" "${RI_EXISTING_RESOLVER_CONFIG_PATH:?required}"
    field_prepare_resolver_runtime_dirs
  fi
  field_data_marker "${RI_FIELD_DATA_DIR}"
  ln -sfn "${target}" "${INSTALL_ROOT}/current.new"
  mv -Tf "${INSTALL_ROOT}/current.new" "${INSTALL_ROOT}/current"

  if ! (field_static_health "${target}" "${KIND}"); then
    if [[ -n "${previous}" && -d "${previous}" ]]; then
      ln -sfn "${previous}" "${INSTALL_ROOT}/current"
    else
      rm -f "${INSTALL_ROOT}/current"
    fi
    field_die "health check failed; program symlink rolled back and data was preserved"
  fi
  if [[ -n "${previous}" && "${previous}" != "${target}" ]]; then
    printf '%s\n' "${previous}" >"${INSTALL_ROOT}/state/previous-release"
  fi
  field_log "installed ${KIND} release ${REQUESTED_VERSION}"
}

health_check() {
  local current
  current="$(field_current_target "${INSTALL_ROOT}")"
  [[ -n "${current}" ]] || field_die "no installed release"
  field_static_health "${current}" "${KIND}"
  if [[ "${RUNTIME_CHECK}" == "true" && "${RI_FIELD_SIMULATION:-false}" != "true" ]]; then
    field_load_env "${current}/config/.env"
    field_compose "${current}" ps --status running --quiet | grep -q . ||
      field_die "no runtime service is running"
  fi
  field_log "health check passed for ${current}"
}

rollback_release() {
  local previous_file="${INSTALL_ROOT}/state/previous-release"
  [[ -f "${previous_file}" ]] || field_die "no previous release is recorded"
  local previous
  previous="$(<"${previous_file}")"
  [[ -d "${previous}" ]] || field_die "recorded previous release is missing"
  local current
  current="$(field_current_target "${INSTALL_ROOT}")"
  ln -sfn "${previous}" "${INSTALL_ROOT}/current"
  if ! (field_static_health "${previous}" "${KIND}"); then
    [[ -n "${current}" ]] && ln -sfn "${current}" "${INSTALL_ROOT}/current"
    field_die "rollback target failed health check"
  fi
  [[ -n "${current}" ]] && printf '%s\n' "${current}" >"${previous_file}"
  field_log "rolled back program symlink to ${previous}"
}

uninstall_release() {
  local current
  current="$(field_current_target "${INSTALL_ROOT}")"
  if [[ -n "${current}" ]]; then
    field_load_env "${current}/config/.env"
    if [[ "${RI_FIELD_SIMULATION:-false}" != "true" ]]; then
      field_compose "${current}" down --remove-orphans || true
    fi
    rm -f "${INSTALL_ROOT}/current"
  fi

  if [[ "${PURGE_DATA}" == "true" ]]; then
    : "${RI_FIELD_DATA_DIR:?RI_FIELD_DATA_DIR is required for purge}"
    [[ -f "${RI_FIELD_DATA_DIR}/.ri-field-owned-data" ]] ||
      field_die "refusing to purge an unowned data directory"
    rm -rf "${RI_FIELD_DATA_DIR}"
    field_log "uninstalled program and explicitly purged owned data"
  else
    field_log "uninstalled program; data and releases were preserved"
  fi
}

case "${ACTION}" in
  preflight)
    preflight
    ;;
  install|upgrade)
    install_release
    ;;
  health-check)
    health_check
    ;;
  rollback)
    rollback_release
    ;;
  uninstall)
    uninstall_release
    ;;
  *)
    field_die "unsupported lifecycle action: ${ACTION}"
    ;;
esac

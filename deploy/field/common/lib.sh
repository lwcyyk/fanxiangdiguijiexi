#!/usr/bin/env bash
set -Eeuo pipefail

field_log() {
  printf '[field-delivery] %s\n' "$*" >&2
}

field_die() {
  printf '[field-delivery] ERROR: %s\n' "$*" >&2
  exit 1
}

field_require_command() {
  command -v "$1" >/dev/null 2>&1 ||
    field_die "required command is unavailable: $1"
}

field_package_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

field_require_digest() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
    field_die "${name} must be pinned by a complete sha256 digest"
  [[ "${value}" != *":latest"* ]] ||
    field_die "${name} must not use latest"
}

field_load_env() {
  local env_file="$1"
  [[ -f "${env_file}" ]] || field_die "configuration is missing: ${env_file}"
  set -a
  # shellcheck disable=SC1090
  source "${env_file}"
  set +a
}

field_compose() {
  local release_root="$1"
  shift
  local env_file="${release_root}/config/.env"
  local project="${RI_FIELD_COMPOSE_PROJECT:?RI_FIELD_COMPOSE_PROJECT is required}"
  docker compose \
    --project-name "${project}" \
    --env-file "${env_file}" \
    -f "${release_root}/docker-compose.yml" \
    "$@"
}

field_verify_package() {
  local package_root="$1"
  (
    cd "${package_root}"
    sha256sum --check --strict PACKAGE-SHA256SUMS >/dev/null
  ) || field_die "package checksum verification failed"
}

field_acquire_lock() {
  local root="$1"
  FIELD_LOCK_DIR="${root}/.field-install.lock"
  mkdir "${FIELD_LOCK_DIR}" 2>/dev/null ||
    field_die "another field lifecycle operation is active"
  trap 'rmdir "${FIELD_LOCK_DIR}" 2>/dev/null || true' EXIT
}

field_release_name() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ ]] ||
    field_die "version contains unsafe characters"
  printf '%s' "${value}"
}

field_current_target() {
  local root="$1"
  if [[ -L "${root}/current" ]]; then
    readlink -f "${root}/current"
  fi
}

field_data_marker() {
  local data_dir="$1"
  mkdir -p "${data_dir}"
  : >"${data_dir}/.ri-field-owned-data"
}

field_prepare_resolver_runtime_dirs() {
  local data_dir="${RI_FIELD_DATA_DIR:?}"
  local trace_dir="${RI_TRACE_SOCKET_HOST_DIR:?}"
  local producer_uid="${RI_TRACE_PRODUCER_UID:?}"
  local producer_gid="${RI_TRACE_PRODUCER_GID:?}"
  local resolver_uid="${RI_KNOT_RESOLVER_UID:?}"
  if [[ "${RI_FIELD_SIMULATION:-false}" == "true" ]]; then
    mkdir -p "${data_dir}/knot-cache" "${trace_dir}"
    chmod 2770 "${trace_dir}"
    return
  fi
  [[ "${EUID}" == "0" ]] ||
    field_die "resolver-link installation must run as root"
  install -d -o "${producer_uid}" -g "${producer_gid}" -m 0750 "${data_dir}"
  install -d -o "${resolver_uid}" -g "${resolver_uid}" -m 0750 \
    "${data_dir}/knot-cache"
  install -d -o "${producer_uid}" -g "${producer_gid}" -m 2770 "${trace_dir}"
}

field_backup_resolver_config() {
  local install_root="$1"
  local source_path="$2"
  [[ "${source_path}" == /* && "${source_path}" != *"/../"* ]] ||
    field_die "RI_EXISTING_RESOLVER_CONFIG_PATH must be an absolute normalized path"
  local backup_root="${install_root}/state/resolver-config"
  mkdir -p "${backup_root}"
  chmod 0700 "${backup_root}"
  if [[ -f "${backup_root}/source-path" ]]; then
    [[ "$(<"${backup_root}/source-path")" == "${source_path}" ]] ||
      field_die "recorded Resolver configuration path differs from this release"
    return
  fi
  printf '%s\n' "${source_path}" >"${backup_root}/source-path"
  if [[ -f "${source_path}" ]]; then
    cp -a -- "${source_path}" "${backup_root}/original.conf"
    sha256sum "${backup_root}/original.conf" >"${backup_root}/original.conf.sha256"
    chmod 0600 "${backup_root}/original.conf" "${backup_root}/original.conf.sha256"
    field_log "backed up existing Resolver configuration without modifying it"
  else
    : >"${backup_root}/source-was-absent"
    chmod 0600 "${backup_root}/source-was-absent"
    field_log "recorded that no existing Resolver configuration was present"
  fi
}

field_static_health() {
  local release_root="$1"
  local kind="$2"
  field_load_env "${release_root}/config/.env"
  [[ "${RI_FIELD_HOST_ID:?RI_FIELD_HOST_ID is required}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]+$ ]] ||
    field_die "invalid RI_FIELD_HOST_ID"

  case "${kind}" in
    management)
      field_require_digest RI_MANAGEMENT_IMAGE "${RI_MANAGEMENT_IMAGE:?}"
      field_require_digest RI_NORN_IMAGE "${RI_NORN_IMAGE:?}"
      ;;
    norn-node)
      field_require_digest RI_NORN_IMAGE "${RI_NORN_IMAGE:?}"
      field_require_digest RI_NGINX_IMAGE "${RI_NGINX_IMAGE:?}"
      [[ "${RI_NORN_ROLE:?}" == "node-a" || "${RI_NORN_ROLE}" == "node-b" ]] ||
        field_die "RI_NORN_ROLE must be node-a or node-b"
      [[ "${RI_NORN_NATIVE_BIND_ADDRESS:?}" == "127.0.0.1" ]] ||
        field_die "Go-Norn native gRPC must remain loopback-only"
      ;;
    resolver-link)
      field_require_digest RI_IMAGE "${RI_IMAGE:?}"
      field_require_digest RI_KNOT_IMAGE "${RI_KNOT_IMAGE:?}"
      [[ "${RI_RESOLVER_ROLE:?}" == "first-hop" || "${RI_RESOLVER_ROLE}" == "upstream" ]] ||
        field_die "RI_RESOLVER_ROLE must be first-hop or upstream"
      [[ "${RI_CHAIN_ADAPTER:?}" == "norn" ]] ||
        field_die "resolver-link delivery requires the explicit norn adapter"
      [[ "${RI_CHAIN_RPC_URLS:?}" == https://*,https://* ]] ||
        field_die "two HTTPS Norn read endpoints are required"
      [[ "${RI_CHAIN_RPC_URLS}" != *"localhost"* && "${RI_CHAIN_RPC_URLS}" != *"127.0.0.1"* ]] ||
        field_die "cross-server Norn endpoints must not use localhost"
      [[ "${RI_MANAGEMENT_BIND_ADDRESS:?}" != "0.0.0.0" &&
        "${RI_MANAGEMENT_BIND_ADDRESS}" != "::" &&
        "${RI_MANAGEMENT_BIND_ADDRESS}" != "127.0.0.1" ]] ||
        field_die "management services must bind a dedicated non-loopback address"
      [[ "${RI_TRACE_PRODUCER_UID:?}" != "${RI_KNOT_RESOLVER_UID:?}" ]] ||
        field_die "Knot Resolver and Trace Producer must use different UIDs"
      [[ -f "${release_root}/config/kresd.conf" ]] ||
        field_die "generated Knot Resolver configuration is missing"
      cmp --silent "${release_root}/kresd.conf" "${release_root}/config/kresd.conf" ||
        field_die "Knot Resolver configuration differs from the approved generated template"
      [[ "${RI_EXISTING_RESOLVER_CONFIG_PATH:?}" == /* ]] ||
        field_die "existing Resolver configuration path must be absolute"
      ;;
    *)
      field_die "unknown package kind: ${kind}"
      ;;
  esac

  if [[ "${RI_FIELD_FORCE_HEALTH_FAILURE:-false}" == "true" ]]; then
    field_die "forced health failure"
  fi

  field_compose "${release_root}" config --quiet
}

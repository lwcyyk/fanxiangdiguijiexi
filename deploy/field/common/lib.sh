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
      [[ "${RI_RESOLVER_ROLE:?}" == "first-hop" || "${RI_RESOLVER_ROLE}" == "upstream" ]] ||
        field_die "RI_RESOLVER_ROLE must be first-hop or upstream"
      [[ "${RI_CHAIN_ADAPTER:?}" == "norn" ]] ||
        field_die "resolver-link delivery requires the explicit norn adapter"
      [[ "${RI_CHAIN_RPC_URLS:?}" == https://*,https://* ]] ||
        field_die "two HTTPS Norn read endpoints are required"
      [[ "${RI_CHAIN_RPC_URLS}" != *"localhost"* && "${RI_CHAIN_RPC_URLS}" != *"127.0.0.1"* ]] ||
        field_die "cross-server Norn endpoints must not use localhost"
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

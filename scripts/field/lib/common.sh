#!/usr/bin/env bash
set -Eeuo pipefail

FIELD_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIELD_REPO_ROOT="$(cd "${FIELD_LIB_DIR}/../../.." && pwd)"
export FIELD_REPO_ROOT

field_log() {
  printf '[field] %s\n' "$*" >&2
}

field_die() {
  printf '[field] ERROR: %s\n' "$*" >&2
  exit 1
}

field_require_command() {
  command -v "$1" >/dev/null 2>&1 || field_die "required command is unavailable: $1"
}

field_require_commands() {
  local command_name
  for command_name in "$@"; do
    field_require_command "${command_name}"
  done
}

field_retry() {
  local attempts="${RI_FIELD_RETRY_ATTEMPTS:-5}"
  local delay_seconds="${RI_FIELD_RETRY_DELAY_SECONDS:-2}"
  local attempt
  [[ "${attempts}" =~ ^[1-9][0-9]*$ ]] ||
    field_die "RI_FIELD_RETRY_ATTEMPTS must be a positive integer"
  [[ "${delay_seconds}" =~ ^[0-9]+$ ]] ||
    field_die "RI_FIELD_RETRY_DELAY_SECONDS must be a non-negative integer"
  for ((attempt = 1; attempt <= attempts; attempt += 1)); do
    if "$@"; then
      return 0
    fi
    (( attempt < attempts )) && sleep "${delay_seconds}"
  done
  field_log "command failed after ${attempts} attempts: $1"
  return 1
}

field_require_file() {
  [[ -f "$1" ]] || field_die "required file is missing: $1"
}

field_run_root() {
  if (( EUID == 0 )); then
    "$@"
  else
    field_require_command sudo
    sudo "$@"
  fi
}

field_wait_http() {
  local url="$1"
  local timeout_seconds="${2:-120}"
  local deadline=$(( $(date +%s) + timeout_seconds ))
  until curl --fail --silent --show-error --max-time 5 "${url}" >/dev/null; do
    (( $(date +%s) < deadline )) ||
      field_die "readiness endpoint did not become ready: ${url}"
    sleep 2
  done
}

field_wait_agent() {
  local url="$1"
  local tls_dir="$2"
  local timeout_seconds="${3:-120}"
  local deadline=$(( $(date +%s) + timeout_seconds ))
  until curl --fail --silent --show-error --max-time 5 \
    --resolve \
      "${RI_FIELD_AGENT_TLS_SERVER_NAME}:${RI_FIELD_AGENT_SERVICE_PORT}:${AGENT_BIND_ADDRESS}" \
    --cert "${tls_dir}/agent-client.crt" \
    --key "${tls_dir}/agent-client.key" \
    --cacert "${tls_dir}/agent-ca.crt" \
    "${url}" >/dev/null; do
    (( $(date +%s) < deadline )) ||
      field_die "Agent readiness endpoint did not become ready: ${url}"
    sleep 2
  done
}

field_agent_request() {
  local url="$1"
  local tls_dir="$2"
  curl --fail --silent --show-error --max-time 10 \
    --resolve \
      "${RI_FIELD_AGENT_TLS_SERVER_NAME}:${RI_FIELD_AGENT_SERVICE_PORT}:${AGENT_BIND_ADDRESS}" \
    --cert "${tls_dir}/agent-client.crt" \
    --key "${tls_dir}/agent-client.key" \
    --cacert "${tls_dir}/agent-ca.crt" \
    "${url}"
}

field_load_bundle() {
  local supplied_root="${1:-}"
  if [[ -z "${supplied_root}" ]]; then
    supplied_root="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"
  fi
  BUNDLE_ROOT="$(cd "${supplied_root}" && pwd)"
  ENV_FILE="${BUNDLE_ROOT}/deploy/link/.env"
  COMPOSE_FILE="${BUNDLE_ROOT}/deploy/link/docker-compose.yml"
  TLS_DIR="${BUNDLE_ROOT}/deploy/link/tls"
  field_require_file "${BUNDLE_ROOT}/.ri-field-bundle"
  field_require_file "${ENV_FILE}"
  field_require_file "${COMPOSE_FILE}"
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
  : "${RI_FIELD_COMPOSE_PROJECT:?missing RI_FIELD_COMPOSE_PROJECT}"
  PROJECT="${RI_FIELD_COMPOSE_PROJECT}"
  export BUNDLE_ROOT ENV_FILE COMPOSE_FILE TLS_DIR PROJECT
}

field_compose() {
  docker compose \
    --project-name "${PROJECT}" \
    --env-file "${ENV_FILE}" \
    -f "${COMPOSE_FILE}" \
    "$@"
}

field_volume_mountpoint() {
  local volume_name="$1"
  docker volume inspect --format '{{.Mountpoint}}' "${volume_name}"
}

field_sqlite() {
  local database="$1"
  shift
  if [[ -r "${database}" ]]; then
    sqlite3 "${database}" "$@"
  else
    field_run_root sqlite3 "${database}" "$@"
  fi
}

field_sqlite_json() {
  local database="$1"
  shift
  if [[ -r "${database}" ]]; then
    sqlite3 -json "${database}" "$@"
  else
    field_run_root sqlite3 -json "${database}" "$@"
  fi
}

field_utc_now() {
  date -u +'%Y-%m-%dT%H:%M:%SZ'
}

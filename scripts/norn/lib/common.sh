#!/usr/bin/env bash
set -Eeuo pipefail

NORN_COMMIT="a7be734ac2e829e2076d06d45719d2716abd3d72"
NORN_IMAGE="${NORN_IMAGE:-resolver-identity-go-norn:a7be734}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NORN_DEPLOY_DIR="${REPO_ROOT}/deploy/norn-local"
NORN_COMPOSE_FILE="${NORN_DEPLOY_DIR}/docker-compose.yml"
NORN_ENV_FILE="${NORN_DEPLOY_DIR}/runtime.env"
NORN_PROJECT="${NORN_PROJECT:-ri-norn-local}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command is missing: %s\n' "$1" >&2
    exit 1
  }
}

norn_compose() {
  docker compose \
    --project-name "${NORN_PROJECT}" \
    --env-file "${NORN_ENV_FILE}" \
    --file "${NORN_COMPOSE_FILE}" \
    "$@"
}

nornctl() {
  cargo run \
    --quiet \
    --manifest-path "${REPO_ROOT}/rust/Cargo.toml" \
    --package ri-chain-adapter \
    --bin ri-nornctl \
    -- "$@"
}

norn_publish() {
  local target="$1"
  local receiver="$2"
  local key="$3"
  local value_file="$4"
  docker run --rm \
    --network host \
    --user "$(id -u):$(id -g)" \
    --volume "${value_file}:/input/value.json:ro" \
    "${NORN_IMAGE}" \
    /usr/local/bin/norn-local-publisher \
    "${target}" "${receiver}" "${key}" /input/value.json
}

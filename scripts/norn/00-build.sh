#!/usr/bin/env bash
set -Eeuo pipefail

source "$(dirname "$0")/lib/common.sh"
require_command docker

build_args=(
  --file "${NORN_DEPLOY_DIR}/Dockerfile"
  --build-arg "NORN_COMMIT=${NORN_COMMIT}"
  --tag "${NORN_IMAGE}"
)
if [[ "${NORN_CLEAN_BUILD:-false}" == "true" ]]; then
  build_args+=(--no-cache --pull)
fi
docker build "${build_args[@]}" "${NORN_DEPLOY_DIR}"

actual_commit="$(
  docker image inspect "${NORN_IMAGE}" \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
)"
[[ "${actual_commit}" == "${NORN_COMMIT}" ]] || {
  printf 'image revision mismatch: expected %s, got %s\n' \
    "${NORN_COMMIT}" "${actual_commit}" >&2
  exit 1
}
printf 'built %s for pinned Go-Norn commit %s (%s)\n' \
  "${NORN_IMAGE}" "${NORN_COMMIT}" "${actual_commit}"

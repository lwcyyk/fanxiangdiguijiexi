#!/usr/bin/env bash
set -Eeuo pipefail

source "$(dirname "$0")/lib/common.sh"
require_command docker
require_command grep
require_command jq

norn_compose down --volumes --remove-orphans

if docker ps -a --filter "label=com.docker.compose.project=${NORN_PROJECT}" \
  --format '{{.ID}}' | grep -q .; then
  printf 'Norn Compose containers remain after cleanup\n' >&2
  exit 1
fi
if docker network ls --filter "label=com.docker.compose.project=${NORN_PROJECT}" \
  --format '{{.ID}}' | grep -q .; then
  printf 'Norn Compose networks remain after cleanup\n' >&2
  exit 1
fi

destination="${REPO_ROOT}/specs/multichain-registry-adapter/acceptance.json"
if [[ -s "${destination}" ]]; then
  temporary="$(mktemp)"
  jq '.temporary_resources_cleaned = true' "${destination}" >"${temporary}"
  mv "${temporary}" "${destination}"
fi

rm -rf "${NORN_DEPLOY_DIR}/private" "${REPO_ROOT}/deployments/norn-local"
rm -f "${NORN_ENV_FILE}"
printf 'removed Norn containers, network, private material, data, and temporary evidence\n'

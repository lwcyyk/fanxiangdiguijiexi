#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq python3 curl docker
load_sepolia_env
assert_sepolia_network
require_var RI_REVOCATION_TEST_SERVER_ID
PLAN="${SEPOLIA_DEPLOYMENTS}/registry-plan-v2.json"
IDENTITIES="${SEPOLIA_DEPLOYMENTS}/identities-v2.json"
PUBLICATION="${SEPOLIA_DEPLOYMENTS}/publication-transactions.json"
[[ -f "${PLAN}" && -f "${IDENTITIES}" && -f "${PUBLICATION}" ]] ||
  die "replacement plan, identities and publication evidence are required"

if jq -e --arg server_id "${RI_REVOCATION_TEST_SERVER_ID}" \
  '.entries[] | select(.server_id == $server_id)' "${PLAN}" >/dev/null; then
  die "current plan still contains the permanently revoked test identity; publish a replacement plan"
fi
if jq -e --arg server_id "${RI_REVOCATION_TEST_SERVER_ID}" \
  '.identities[] | select(.server_id == $server_id)' "${IDENTITIES}" >/dev/null; then
  die "signed artifact still contains the permanently revoked test identity"
fi
[[ "$(jq -er '.plan_hash' "${PLAN}")" == "$(jq -er '.plan_hash' "${PUBLICATION}")" ]] ||
  die "replacement plan has not completed all publication phases"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" verify-identities \
  --identities "${IDENTITIES}" \
  --issuer-keys "${SEPOLIA_DEPLOYMENTS}/issuer-keys.json"
"${SCRIPT_DIR}/08-sync-runtime-config.sh"

COMPOSE=(
  docker compose
  --project-name ri-sepolia-preprod
  --env-file "${REPO_ROOT}/deploy/link/.env"
  -f "${REPO_ROOT}/deploy/link/docker-compose.yml"
)
"${COMPOSE[@]}" restart registry-sync >/dev/null
READY_DEADLINE="$(( $(date +%s) + 180 ))"
until curl --fail --silent http://127.0.0.1:9109/readyz >/dev/null; do
  (( $(date +%s) < READY_DEADLINE )) ||
    die "Registry Sync did not recover with the replacement identity set"
  sleep 2
done

log "replacement state is ready; the revoked server_id was not and cannot be restored"

#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands docker curl jq
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
REGISTRY_CODE_HASH="$(verified_code_hash)"
assert_live_contract "${REGISTRY_ADDRESS}" "${REGISTRY_CODE_HASH}"
[[ -f "${REPO_ROOT}/deploy/link/.env" ]] || die "runtime .env is absent; run 08 first"
[[ -f "${REPO_ROOT}/deploy/link/identities-v2.json" ]] || die "runtime identities are absent"
[[ -f "${REPO_ROOT}/deploy/issuer-keys.json" ]] || die "runtime Issuer bundle is absent"

COMPOSE=(
  docker compose
  --project-name ri-sepolia-preprod
  --env-file "${REPO_ROOT}/deploy/link/.env"
  -f "${REPO_ROOT}/deploy/link/docker-compose.yml"
)
mkdir -p "${SEPOLIA_DEPLOYMENTS}/private"
"${COMPOSE[@]}" config >/dev/null
"${COMPOSE[@]}" up -d --no-build registry-sync

READY_DEADLINE="$(( $(date +%s) + ${RI_REGISTRY_READY_TIMEOUT_SECONDS:-300} ))"
until curl --fail --silent --show-error http://127.0.0.1:9109/readyz >/dev/null; do
  if (( $(date +%s) >= READY_DEADLINE )); then
    "${COMPOSE[@]}" logs --no-color registry-sync \
      >"${SEPOLIA_DEPLOYMENTS}/private/registry-sync-failed.log" 2>&1 || true
    die "Registry Sync did not become ready"
  fi
  sleep 2
done

curl --fail --silent --show-error http://127.0.0.1:9109/healthz >/dev/null
METRICS="$(curl --fail --silent --show-error http://127.0.0.1:9109/metrics)"
printf '%s\n' "${METRICS}" >"${SEPOLIA_DEPLOYMENTS}/registry-sync.metrics.prom"

grep -F "chain_id=\"${CHAIN_ID}\"" <<<"${METRICS}" >/dev/null ||
  die "Registry Sync metrics do not expose the expected Chain ID"
grep -F "contract_address=\"${REGISTRY_ADDRESS,,}\"" <<<"${METRICS}" >/dev/null ||
  die "Registry Sync metrics do not expose the expected Registry address"
grep -F "contract_code_hash=\"${REGISTRY_CODE_HASH,,}\"" <<<"${METRICS}" >/dev/null ||
  die "Registry Sync metrics do not expose the expected runtime code hash"
FINALIZED_BLOCK="$(awk '/^resolver_identity_registry_finalized_block / {print $2}' <<<"${METRICS}")"
RECORD_COUNT="$(awk '/^resolver_identity_registry_records / {print $2}' <<<"${METRICS}")"
FINALIZED_HASH="$(sed -n 's/^resolver_identity_registry_finalized_info{block_hash="\([^"]*\)"} 1$/\1/p' <<<"${METRICS}")"
[[ "${FINALIZED_BLOCK}" =~ ^[1-9][0-9]*$ ]] || die "Registry Sync finalized height is missing"
validate_bytes32 "${FINALIZED_HASH}" "Registry Sync finalized block hash"
EXPECTED_RECORDS="$(jq '.identities | length' "${REPO_ROOT}/deploy/link/identities-v2.json")"
[[ "${RECORD_COUNT}" == "${EXPECTED_RECORDS}" ]] ||
  die "Registry Sync record count does not match the signed identity artifact"

LOG_FILE="${SEPOLIA_DEPLOYMENTS}/private/registry-sync.log"
"${COMPOSE[@]}" logs --no-color registry-sync >"${LOG_FILE}"
grep -F "chain_id=${CHAIN_ID}" "${LOG_FILE}" >/dev/null ||
  die "Registry Sync startup log does not contain the pinned Chain ID"
IMAGE_ID="$(docker image inspect "${RI_IMAGE:-resolver-identity-rust:sepolia-preprod}" --format '{{.Id}}')"

jq -n \
  --arg checked_at "$(utc_now)" \
  --argjson chain_id "${CHAIN_ID}" \
  --arg contract_address "${REGISTRY_ADDRESS,,}" \
  --arg runtime_code_hash "${REGISTRY_CODE_HASH,,}" \
  --argjson finalized_block "${FINALIZED_BLOCK}" \
  --arg finalized_block_hash "${FINALIZED_HASH}" \
  --argjson identity_count "${RECORD_COUNT}" \
  --arg image_digest "${IMAGE_ID}" \
  '{
    checked_at:$checked_at,chain_id:$chain_id,contract_address:$contract_address,
    runtime_code_hash:$runtime_code_hash,finalized_block:$finalized_block,
    finalized_block_hash:$finalized_block_hash,identity_count:$identity_count,
    image_digest:$image_digest,healthz:"PASS",readyz:"PASS",metrics:"PASS"
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/registry-sync.json"

"${COMPOSE[@]}" ps
log "Registry Sync is ready at finalized block ${FINALIZED_BLOCK}"

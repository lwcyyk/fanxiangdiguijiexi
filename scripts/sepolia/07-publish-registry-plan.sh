#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq python3 cast
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
REGISTRY_CODE_HASH="$(verified_code_hash)"
assert_live_contract "${REGISTRY_ADDRESS}" "${REGISTRY_CODE_HASH}"
PLAN="${SEPOLIA_DEPLOYMENTS}/registry-plan-v2.json"
ROLES="${SEPOLIA_DEPLOYMENTS}/roles.json"
[[ -f "${PLAN}" && -f "${ROLES}" ]] || die "approved plan and roles.json are required"
PLAN_HASH="$(jq -er '.plan_hash' "${PLAN}")"
validate_bytes32 "${PLAN_HASH}" "publication plan hash"

ROOT_PUBLISHER_ADDRESS="$(jq -er '.root_publisher_address' "${ROLES}")"
RESOLVER_PUBLISHER_ADDRESS="$(jq -er '.resolver_publisher_address' "${ROLES}")"
ENDPOINT_MANAGER_ADDRESS="$(jq -er '.endpoint_manager_address' "${ROLES}")"
REVOKER_ADDRESS="$(jq -er '.revoker_address' "${ROLES}")"
ROOT_ROLE="$(role_hash ROOT_PUBLISHER_ROLE)"
RESOLVER_ROLE="$(role_hash RESOLVER_PUBLISHER_ROLE)"
ENDPOINT_ROLE="$(role_hash ENDPOINT_MANAGER_ROLE)"
REVOKER_ROLE="$(role_hash REVOKER_ROLE)"

PUBLICATION_FILE="${SEPOLIA_DEPLOYMENTS}/publication-transactions.json"
if [[ -f "${PUBLICATION_FILE}" ]]; then
  [[ "$(jq -er '.plan_hash' "${PUBLICATION_FILE}")" == "${PLAN_HASH}" ]] ||
    die "existing transaction evidence belongs to another plan"
  ALL_TRANSACTIONS="$(jq -c '.transactions' "${PUBLICATION_FILE}")"
else
  ALL_TRANSACTIONS='[]'
fi

run_phase() {
  local phase="$1"
  local signer_prefix="$2"
  local sender="$3"
  local required_role="$4"
  [[ "$(has_role "${RI_TESTNET_VERIFY_RPC_URL}" "${REGISTRY_ADDRESS}" "${required_role}" "${sender}")" == "true" ]] ||
    die "${sender} does not hold the role required for ${phase}"
  assert_sepolia_network
  assert_live_contract "${REGISTRY_ADDRESS}" "${REGISTRY_CODE_HASH}"
  require_signer_matches "${signer_prefix}" "${sender}"
  export_registry_writer "${signer_prefix}" "${sender}"
  local stage_file="${SEPOLIA_DEPLOYMENTS}/private/${phase}-receipts.json"
  mkdir -p "${SEPOLIA_DEPLOYMENTS}/private"
  log "executing ${phase} as ${sender} on chain ${CHAIN_ID}, Registry=${REGISTRY_ADDRESS}"
  PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" "${phase}" \
    --plan "${PLAN}" \
    --expected-plan-hash "${PLAN_HASH}" \
    --receipt-output "${stage_file}"
  local stage_transactions
  stage_transactions="$(jq -c '.transactions' "${stage_file}")"
  ALL_TRANSACTIONS="$(jq -cn \
    --argjson existing "${ALL_TRANSACTIONS}" \
    --argjson added "${stage_transactions}" \
    '$existing + $added | unique_by(.transaction_hash)')"
  jq -n \
    --arg schema_version registry-publication-transactions-v1 \
    --arg network_name ethereum-sepolia \
    --argjson chain_id "${CHAIN_ID}" \
    --arg contract_address "${REGISTRY_ADDRESS}" \
    --arg plan_hash "${PLAN_HASH}" \
    --arg updated_at "$(utc_now)" \
    --argjson transactions "${ALL_TRANSACTIONS}" \
    '{
      schema_version:$schema_version,network_name:$network_name,chain_id:$chain_id,
      contract_address:$contract_address,plan_hash:$plan_hash,updated_at:$updated_at,
      transactions:$transactions
    }' | write_json_atomic "${PUBLICATION_FILE}"
}

run_phase publish-root ROOT_PUBLISHER "${ROOT_PUBLISHER_ADDRESS}" "${ROOT_ROLE}"
run_phase publish-resolvers RESOLVER_PUBLISHER "${RESOLVER_PUBLISHER_ADDRESS}" "${RESOLVER_ROLE}"
run_phase unbind-endpoints ENDPOINT_MANAGER "${ENDPOINT_MANAGER_ADDRESS}" "${ENDPOINT_ROLE}"
run_phase bind-endpoints ENDPOINT_MANAGER "${ENDPOINT_MANAGER_ADDRESS}" "${ENDPOINT_ROLE}"
run_phase revoke-removed REVOKER "${REVOKER_ADDRESS}" "${REVOKER_ROLE}"

log "all publication phases match the approved plan; receipts are archived"

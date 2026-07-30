#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq cast
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
if [[ ! -f "${SEPOLIA_DEPLOYMENTS}/verification.json" ]]; then
  log "finalized verification is required before role changes; running it now"
  "${SCRIPT_DIR}/04-verify-deployment.sh"
fi
assert_live_contract "${REGISTRY_ADDRESS}" "$(verified_code_hash)"
require_var GOVERNANCE_ADDRESS
validate_address "${GOVERNANCE_ADDRESS}" GOVERNANCE_ADDRESS
require_signer_matches GOVERNANCE "${GOVERNANCE_ADDRESS}"

DEPLOYER_ADDRESS="$(signer_address_for DEPLOYER)"
ROOT_PUBLISHER_ADDRESS="$(signer_address_for ROOT_PUBLISHER)"
RESOLVER_PUBLISHER_ADDRESS="$(signer_address_for RESOLVER_PUBLISHER)"
ENDPOINT_MANAGER_ADDRESS="$(signer_address_for ENDPOINT_MANAGER)"
REVOKER_ADDRESS="$(signer_address_for REVOKER)"
require_distinct_addresses \
  "${DEPLOYER_ADDRESS}" "${GOVERNANCE_ADDRESS}" "${ROOT_PUBLISHER_ADDRESS}" \
  "${RESOLVER_PUBLISHER_ADDRESS}" "${ENDPOINT_MANAGER_ADDRESS}" "${REVOKER_ADDRESS}"

DEFAULT_ADMIN_ROLE="${ZERO_BYTES32}"
ROOT_ROLE="$(role_hash ROOT_PUBLISHER_ROLE)"
RESOLVER_ROLE="$(role_hash RESOLVER_PUBLISHER_ROLE)"
ENDPOINT_ROLE="$(role_hash ENDPOINT_MANAGER_ROLE)"
REVOKER_ROLE="$(role_hash REVOKER_ROLE)"
ROLE_TX_JOURNAL="${SEPOLIA_DEPLOYMENTS}/private/role-transactions.json"
mkdir -p "${SEPOLIA_DEPLOYMENTS}/private"
TRANSACTIONS='[]'
if [[ -f "${SEPOLIA_DEPLOYMENTS}/roles.json" ]] &&
  [[ "$(jq -r '.contract_address' "${SEPOLIA_DEPLOYMENTS}/roles.json")" == "${REGISTRY_ADDRESS}" ]] &&
  [[ "$(jq -r '.chain_id' "${SEPOLIA_DEPLOYMENTS}/roles.json")" == "${CHAIN_ID}" ]]; then
  TRANSACTIONS="$(jq -c '.transactions' "${SEPOLIA_DEPLOYMENTS}/roles.json")"
elif [[ -f "${ROLE_TX_JOURNAL}" ]] &&
  [[ "$(jq -r '.contract_address' "${ROLE_TX_JOURNAL}")" == "${REGISTRY_ADDRESS}" ]] &&
  [[ "$(jq -r '.chain_id' "${ROLE_TX_JOURNAL}")" == "${CHAIN_ID}" ]]; then
  TRANSACTIONS="$(jq -c '.transactions' "${ROLE_TX_JOURNAL}")"
fi

record_cast_receipt() {
  local receipt="$1"
  local operation="$2"
  local role="$3"
  local target="$4"
  local tx_hash block_hash sender status_raw gas_raw block_raw status gas block
  tx_hash="$(jq -er '.transactionHash' <<<"${receipt}")"
  block_hash="$(jq -er '.blockHash' <<<"${receipt}")"
  sender="$(jq -er '.from' <<<"${receipt}")"
  status_raw="$(jq -er '.status' <<<"${receipt}")"
  gas_raw="$(jq -er '.gasUsed' <<<"${receipt}")"
  block_raw="$(jq -er '.blockNumber' <<<"${receipt}")"
  status="${status_raw}"
  gas="${gas_raw}"
  block="${block_raw}"
  [[ "${status_raw}" == 0x* ]] && status="$(cast to-dec "${status_raw}")"
  [[ "${gas_raw}" == 0x* ]] && gas="$(cast to-dec "${gas_raw}")"
  [[ "${block_raw}" == 0x* ]] && block="$(cast to-dec "${block_raw}")"
  [[ "${status}" == "1" ]] || die "role transaction failed"
  TRANSACTIONS="$(jq -c \
    --arg transaction_hash "${tx_hash}" \
    --arg sender "${sender}" \
    --arg role "${role}" \
    --argjson block_number "${block}" \
    --arg block_hash "${block_hash}" \
    --argjson status "${status}" \
    --argjson gas_used "${gas}" \
    --arg operation "${operation}" \
    --arg target_object "${target}" \
    '. + [{
      transaction_hash:$transaction_hash,sender:$sender,role:$role,
      block_number:$block_number,block_hash:$block_hash,status:$status,
      gas_used:$gas_used,operation:$operation,target_object:$target_object
    }]' <<<"${TRANSACTIONS}")"
  TRANSACTIONS="$(jq -c 'unique_by(.transaction_hash)' <<<"${TRANSACTIONS}")"
  jq -n \
    --argjson chain_id "${CHAIN_ID}" \
    --arg contract_address "${REGISTRY_ADDRESS}" \
    --argjson transactions "${TRANSACTIONS}" \
    '{chain_id:$chain_id,contract_address:$contract_address,transactions:$transactions}' |
    write_json_atomic "${ROLE_TX_JOURNAL}"
}

send_role_change() {
  local operation="$1"
  local role="$2"
  local account="$3"
  log "${operation} ${role} for ${account} as Governance=${GOVERNANCE_ADDRESS} on chain ${CHAIN_ID}"
  local receipt
  if [[ "${operation}" == "grant" ]]; then
    receipt="$(cast send "${REGISTRY_ADDRESS}" 'grantRole(bytes32,address)' "${role}" "${account}" \
      --rpc-url "${RI_TESTNET_RPC_URL}" \
      --keystore "${GOVERNANCE_KEYSTORE_FILE}" \
      --password-file "${GOVERNANCE_KEYSTORE_PASSWORD_FILE}" \
      --confirmations 1 --json)"
  else
    receipt="$(cast send "${REGISTRY_ADDRESS}" 'revokeRole(bytes32,address)' "${role}" "${account}" \
      --rpc-url "${RI_TESTNET_RPC_URL}" \
      --keystore "${GOVERNANCE_KEYSTORE_FILE}" \
      --password-file "${GOVERNANCE_KEYSTORE_PASSWORD_FILE}" \
      --confirmations 1 --json)"
  fi
  record_cast_receipt "${receipt}" "${operation}-role" "${role}" "${account}"
}

grant_if_missing() {
  local role="$1"
  local account="$2"
  if [[ "$(has_role "${RI_TESTNET_RPC_URL}" "${REGISTRY_ADDRESS}" "${role}" "${account}")" != "true" ]]; then
    send_role_change grant "${role}" "${account}"
  fi
}

revoke_if_present() {
  local role="$1"
  local account="$2"
  if [[ "$(has_role "${RI_TESTNET_RPC_URL}" "${REGISTRY_ADDRESS}" "${role}" "${account}")" == "true" ]]; then
    send_role_change revoke "${role}" "${account}"
  fi
}

grant_if_missing "${ROOT_ROLE}" "${ROOT_PUBLISHER_ADDRESS}"
grant_if_missing "${RESOLVER_ROLE}" "${RESOLVER_PUBLISHER_ADDRESS}"
grant_if_missing "${ENDPOINT_ROLE}" "${ENDPOINT_MANAGER_ADDRESS}"
grant_if_missing "${REVOKER_ROLE}" "${REVOKER_ADDRESS}"

revoke_if_present "${ROOT_ROLE}" "${GOVERNANCE_ADDRESS}"
revoke_if_present "${RESOLVER_ROLE}" "${GOVERNANCE_ADDRESS}"
revoke_if_present "${ENDPOINT_ROLE}" "${GOVERNANCE_ADDRESS}"
revoke_if_present "${REVOKER_ROLE}" "${GOVERNANCE_ADDRESS}"

ROLE_FINALIZED_TARGET="$(jq -r '[.[].block_number] | max // 0' <<<"${TRANSACTIONS}")"
(( ROLE_FINALIZED_TARGET > 0 )) || die "role transaction journal is empty"
ROLE_FINALIZED_DEADLINE="$(( $(date +%s) + ${RI_FINALIZED_WAIT_SECONDS:-1800} ))"
while true; do
  PRIMARY_FINALIZED="$(rpc_block "${RI_TESTNET_RPC_URL}" finalized)"
  VERIFY_FINALIZED="$(rpc_block "${RI_TESTNET_VERIFY_RPC_URL}" finalized)"
  PRIMARY_HEIGHT="$(cast to-dec "$(jq -er '.number' <<<"${PRIMARY_FINALIZED}")")"
  VERIFY_HEIGHT="$(cast to-dec "$(jq -er '.number' <<<"${VERIFY_FINALIZED}")")"
  ROLE_FINALIZED_BLOCK="${PRIMARY_HEIGHT}"
  (( VERIFY_HEIGHT < ROLE_FINALIZED_BLOCK )) && ROLE_FINALIZED_BLOCK="${VERIFY_HEIGHT}"
  if (( ROLE_FINALIZED_BLOCK >= ROLE_FINALIZED_TARGET )); then
    break
  fi
  (( $(date +%s) < ROLE_FINALIZED_DEADLINE )) ||
    die "role transactions did not enter finalized state before timeout"
  log "waiting for role transactions to become finalized (target ${ROLE_FINALIZED_TARGET}, current ${ROLE_FINALIZED_BLOCK})"
  sleep 12
done

ROLE_FINALIZED_TAG="$(cast to-hex "${ROLE_FINALIZED_BLOCK}")"
PRIMARY_ROLE_BLOCK="$(rpc_block "${RI_TESTNET_RPC_URL}" "${ROLE_FINALIZED_TAG}")"
VERIFY_ROLE_BLOCK="$(rpc_block "${RI_TESTNET_VERIFY_RPC_URL}" "${ROLE_FINALIZED_TAG}")"
PRIMARY_ROLE_BLOCK_HASH="$(jq -er '.hash' <<<"${PRIMARY_ROLE_BLOCK}")"
VERIFY_ROLE_BLOCK_HASH="$(jq -er '.hash' <<<"${VERIFY_ROLE_BLOCK}")"
[[ "${PRIMARY_ROLE_BLOCK_HASH}" == "${VERIFY_ROLE_BLOCK_HASH}" ]] ||
  die "RPC role-verification block hashes differ"

for rpc_url in "${RI_TESTNET_RPC_URL}" "${RI_TESTNET_VERIFY_RPC_URL}"; do
  [[ "$(has_role "${rpc_url}" "${REGISTRY_ADDRESS}" \
    "${DEFAULT_ADMIN_ROLE}" "${GOVERNANCE_ADDRESS}" "${ROLE_FINALIZED_TAG}")" == "true" ]] ||
    die "Governance is not the finalized default admin"
  [[ "$(has_role "${rpc_url}" "${REGISTRY_ADDRESS}" \
    "${DEFAULT_ADMIN_ROLE}" "${DEPLOYER_ADDRESS}" "${ROLE_FINALIZED_TAG}")" == "false" ]] ||
    die "Deployer unexpectedly holds the finalized default admin role"
  ADMIN_COUNT_RAW="$(contract_call_raw "${rpc_url}" "${REGISTRY_ADDRESS}" \
    "${ROLE_FINALIZED_TAG}" 'adminCount()')"
  ADMIN_COUNT="$(cast to-dec "${ADMIN_COUNT_RAW}")"
  [[ "${ADMIN_COUNT}" == "1" ]] || die "finalized adminCount is not one"
done

for pair in \
  "${ROOT_ROLE}:${ROOT_PUBLISHER_ADDRESS}" \
  "${RESOLVER_ROLE}:${RESOLVER_PUBLISHER_ADDRESS}" \
  "${ENDPOINT_ROLE}:${ENDPOINT_MANAGER_ADDRESS}" \
  "${REVOKER_ROLE}:${REVOKER_ADDRESS}"; do
  role="${pair%%:*}"
  account="${pair#*:}"
  for rpc_url in "${RI_TESTNET_RPC_URL}" "${RI_TESTNET_VERIFY_RPC_URL}"; do
    [[ "$(has_role "${rpc_url}" "${REGISTRY_ADDRESS}" "${role}" "${account}" "${ROLE_FINALIZED_TAG}")" == "true" ]] ||
      die "target account is missing its finalized business role"
    [[ "$(has_role "${rpc_url}" "${REGISTRY_ADDRESS}" "${role}" "${GOVERNANCE_ADDRESS}" "${ROLE_FINALIZED_TAG}")" == "false" ]] ||
      die "Governance unexpectedly retains a finalized business role"
    [[ "$(has_role "${rpc_url}" "${REGISTRY_ADDRESS}" "${role}" "${DEPLOYER_ADDRESS}" "${ROLE_FINALIZED_TAG}")" == "false" ]] ||
      die "Deployer unexpectedly holds a finalized business role"
  done
done

jq -n \
  --arg network_name ethereum-sepolia \
  --argjson chain_id "${CHAIN_ID}" \
  --arg contract_address "${REGISTRY_ADDRESS}" \
  --arg governance_address "${GOVERNANCE_ADDRESS}" \
  --arg root_publisher_address "${ROOT_PUBLISHER_ADDRESS}" \
  --arg resolver_publisher_address "${RESOLVER_PUBLISHER_ADDRESS}" \
  --arg endpoint_manager_address "${ENDPOINT_MANAGER_ADDRESS}" \
  --arg revoker_address "${REVOKER_ADDRESS}" \
  --arg configured_at "$(utc_now)" \
  --argjson finalized_block "${ROLE_FINALIZED_BLOCK}" \
  --arg finalized_block_hash "${PRIMARY_ROLE_BLOCK_HASH}" \
  --arg primary_rpc_host "${PRIMARY_RPC_HOST}" \
  --arg verification_rpc_host "${VERIFY_RPC_HOST}" \
  --argjson transactions "${TRANSACTIONS}" \
  '{
    network_name:$network_name,chain_id:$chain_id,contract_address:$contract_address,
    governance_address:$governance_address,
    root_publisher_address:$root_publisher_address,
    resolver_publisher_address:$resolver_publisher_address,
    endpoint_manager_address:$endpoint_manager_address,
    revoker_address:$revoker_address,
    configured_at:$configured_at,transactions:$transactions,
    finalized_verification:{
      block_number:$finalized_block,
      block_hash:$finalized_block_hash,
      primary_rpc_host:$primary_rpc_host,
      verification_rpc_host:$verification_rpc_host,
      admin_count:1,
      checks:{
        block_hash_match:true,
        governance_default_admin:true,
        governance_business_roles_revoked:true,
        deployer_has_no_roles:true,
        business_roles_split:true
      }
    }
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/roles.json"

log "role split verified through both RPCs at finalized block ${ROLE_FINALIZED_BLOCK}"

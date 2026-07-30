#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq cast curl
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
validate_address "${REGISTRY_ADDRESS}" "Registry address"

DEADLINE="$(( $(date +%s) + ${RI_FINALIZED_WAIT_SECONDS:-1800} ))"
while true; do
  PRIMARY_FINALIZED="$(rpc_block "${RI_TESTNET_RPC_URL}" finalized)"
  VERIFY_FINALIZED="$(rpc_block "${RI_TESTNET_VERIFY_RPC_URL}" finalized)"
  PRIMARY_HEIGHT_RAW="$(jq -er '.number' <<<"${PRIMARY_FINALIZED}")"
  VERIFY_HEIGHT_RAW="$(jq -er '.number' <<<"${VERIFY_FINALIZED}")"
  PRIMARY_HEIGHT="$(cast to-dec "${PRIMARY_HEIGHT_RAW}")"
  VERIFY_HEIGHT="$(cast to-dec "${VERIFY_HEIGHT_RAW}")"
  COMMON_HEIGHT="${PRIMARY_HEIGHT}"
  (( VERIFY_HEIGHT < COMMON_HEIGHT )) && COMMON_HEIGHT="${VERIFY_HEIGHT}"
  COMMON_TAG="$(cast to-hex "${COMMON_HEIGHT}")"
  PRIMARY_BLOCK="$(rpc_block "${RI_TESTNET_RPC_URL}" "${COMMON_TAG}")"
  VERIFY_BLOCK="$(rpc_block "${RI_TESTNET_VERIFY_RPC_URL}" "${COMMON_TAG}")"
  PRIMARY_BLOCK_HASH="$(jq -er '.hash' <<<"${PRIMARY_BLOCK}")"
  VERIFY_BLOCK_HASH="$(jq -er '.hash' <<<"${VERIFY_BLOCK}")"
  PRIMARY_CODE="$(rpc_code "${RI_TESTNET_RPC_URL}" "${REGISTRY_ADDRESS}" "${COMMON_TAG}")"
  VERIFY_CODE="$(rpc_code "${RI_TESTNET_VERIFY_RPC_URL}" "${REGISTRY_ADDRESS}" "${COMMON_TAG}")"
  if [[ "${PRIMARY_CODE}" != "0x" ]]; then
    break
  fi
  (( $(date +%s) < DEADLINE )) || die "Registry did not enter finalized state before timeout"
  log "waiting for deployment to become finalized (current common height ${COMMON_HEIGHT})"
  sleep 12
done

[[ "${PRIMARY_BLOCK_HASH}" == "${VERIFY_BLOCK_HASH}" ]] ||
  die "RPC finalized block hashes differ at the common height"
[[ "${PRIMARY_CODE}" == "${VERIFY_CODE}" ]] ||
  die "RPC finalized runtime bytecode differs"
ARTIFACT="${REPO_ROOT}/contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json"
[[ -f "${ARTIFACT}" ]] || die "compiled Registry artifact is absent"
COMPILED_RUNTIME="$(jq -er '.deployedBytecode.object' "${ARTIFACT}")"
[[ "${COMPILED_RUNTIME}" == 0x* ]] || COMPILED_RUNTIME="0x${COMPILED_RUNTIME}"
[[ "${PRIMARY_CODE}" == "${COMPILED_RUNTIME}" ]] ||
  die "finalized runtime bytecode differs from the compiled Registry artifact"
RUNTIME_CODE_HASH="$(cast keccak "${PRIMARY_CODE}")"
VERIFY_CODE_HASH="$(cast keccak "${VERIFY_CODE}")"
[[ "${RUNTIME_CODE_HASH}" == "${VERIFY_CODE_HASH}" ]] ||
  die "RPC finalized runtime code hashes differ"
validate_bytes32 "${RUNTIME_CODE_HASH}" "runtime code hash"

DEPLOYMENT_BLOCK="$(jq -er '.deployment_block' "${SEPOLIA_DEPLOYMENTS}/deployment.json")"
DEPLOYMENT_BLOCK_HASH="$(jq -er '.deployment_block_hash' "${SEPOLIA_DEPLOYMENTS}/deployment.json")"
DEPLOYMENT_TAG="$(cast to-hex "${DEPLOYMENT_BLOCK}")"
PRIMARY_DEPLOYMENT_HASH="$(rpc_block "${RI_TESTNET_RPC_URL}" "${DEPLOYMENT_TAG}" | jq -er '.hash')"
VERIFY_DEPLOYMENT_HASH="$(rpc_block "${RI_TESTNET_VERIFY_RPC_URL}" "${DEPLOYMENT_TAG}" | jq -er '.hash')"
[[ "${PRIMARY_DEPLOYMENT_HASH}" == "${VERIFY_DEPLOYMENT_HASH}" ]] ||
  die "RPC deployment block hashes differ"
[[ "${PRIMARY_DEPLOYMENT_HASH}" == "${DEPLOYMENT_BLOCK_HASH}" ]] ||
  die "deployment manifest block hash differs from both RPCs"

jq -n \
  --arg network_name ethereum-sepolia \
  --argjson chain_id "${CHAIN_ID}" \
  --arg contract_address "${REGISTRY_ADDRESS}" \
  --arg primary_rpc_host "${PRIMARY_RPC_HOST}" \
  --arg verification_rpc_host "${VERIFY_RPC_HOST}" \
  --arg runtime_bytecode "${PRIMARY_CODE}" \
  --arg runtime_code_hash "${RUNTIME_CODE_HASH}" \
  --argjson deployment_block "${DEPLOYMENT_BLOCK}" \
  --arg deployment_block_hash "${DEPLOYMENT_BLOCK_HASH}" \
  --argjson finalized_block "${COMMON_HEIGHT}" \
  --arg finalized_block_hash "${PRIMARY_BLOCK_HASH}" \
  --arg verified_at "$(utc_now)" \
  '{
    network_name:$network_name,chain_id:$chain_id,contract_address:$contract_address,
    primary_rpc_host:$primary_rpc_host,verification_rpc_host:$verification_rpc_host,
    runtime_bytecode:$runtime_bytecode,runtime_code_hash:$runtime_code_hash,
    deployment_block:$deployment_block,deployment_block_hash:$deployment_block_hash,
    finalized_block:$finalized_block,finalized_block_hash:$finalized_block_hash,
    verified_at:$verified_at,
    checks:{
      chain_id_match:true,contract_address_match:true,runtime_bytecode_match:true,
      runtime_code_hash_match:true,compiled_runtime_match:true,
      deployment_block_hash_match:true,finalized_block_hash_match:true
    }
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/verification.json"

log "finalized Registry verification passed at block ${COMMON_HEIGHT}"

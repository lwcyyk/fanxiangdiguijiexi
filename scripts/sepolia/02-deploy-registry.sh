#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq cast forge git
load_sepolia_env
assert_sepolia_network
source_tree_clean || die "tracked source or untracked implementation files are not committed"
[[ -f "${SEPOLIA_DEPLOYMENTS}/preflight.json" ]] ||
  die "preflight.json is absent; run 00-preflight.sh first"
[[ "$(jq -r '.chain_id' "${SEPOLIA_DEPLOYMENTS}/preflight.json")" == "${CHAIN_ID}" ]] ||
  die "preflight evidence targets another chain"
[[ "$(jq -r '.git_commit' "${SEPOLIA_DEPLOYMENTS}/preflight.json")" == "$(git -C "${REPO_ROOT}" rev-parse HEAD)" ]] ||
  die "preflight evidence targets another Git commit"
[[ "$(jq -r '.source_tree_clean' "${SEPOLIA_DEPLOYMENTS}/preflight.json")" == "true" ]] ||
  die "preflight was not executed from a clean source tree"
require_var GOVERNANCE_ADDRESS
validate_address "${GOVERNANCE_ADDRESS}" GOVERNANCE_ADDRESS
DEPLOYER_ADDRESS="$(signer_address_for DEPLOYER)"
validate_address "${DEPLOYER_ADDRESS}" "Deployer address"
[[ "${DEPLOYER_ADDRESS,,}" != "${GOVERNANCE_ADDRESS,,}" ]] ||
  die "Deployer and Governance addresses must differ"
require_balance "${DEPLOYER_ADDRESS}" Deployer 20000000000000000 >/dev/null

if [[ -f "${SEPOLIA_DEPLOYMENTS}/deployment.json" ]]; then
  EXISTING_ADDRESS="$(contract_address)"
  assert_live_contract "${EXISTING_ADDRESS}"
  EXISTING_CHAIN="$(jq -er '.chain_id' "${SEPOLIA_DEPLOYMENTS}/deployment.json")"
  [[ "${EXISTING_CHAIN}" == "${CHAIN_ID}" ]] || die "existing deployment targets another chain"
  log "existing deployment is live; refusing to create a second Registry"
  exit 0
fi

BROADCAST_FILE="${REPO_ROOT}/contracts/broadcast/DeployResolverIdentityRegistry.s.sol/${CHAIN_ID}/run-latest.json"
if [[ -f "${BROADCAST_FILE}" ]]; then
  PRIOR_ADDRESS="$(jq -r '.transactions[]? | select(.contractName == "ResolverIdentityRegistryV1") | .contractAddress' "${BROADCAST_FILE}" | tail -n 1)"
  PRIOR_TX="$(jq -r '.transactions[]? | select(.contractName == "ResolverIdentityRegistryV1") | .hash' "${BROADCAST_FILE}" | tail -n 1)"
  if [[ -n "${PRIOR_ADDRESS}" && "${PRIOR_ADDRESS}" != "null" && -n "${PRIOR_TX}" && "${PRIOR_TX}" != "null" ]]; then
    PRIOR_STATUS="$(cast receipt "${PRIOR_TX}" status --rpc-url "${RI_TESTNET_RPC_URL}" 2>/dev/null || true)"
    PRIOR_CODE="$(rpc_code "${RI_TESTNET_RPC_URL}" "${PRIOR_ADDRESS}" latest 2>/dev/null || true)"
    if [[ "${PRIOR_STATUS}" == "1" || "${PRIOR_STATUS}" == "0x1" ]] && [[ "${PRIOR_CODE}" != "0x" ]]; then
      die "a successful unarchived deployment broadcast exists; recover its manifest instead of redeploying"
    fi
  fi
fi

log "broadcasting Registry deployment as ${DEPLOYER_ADDRESS} on Sepolia ${CHAIN_ID}; Governance=${GOVERNANCE_ADDRESS}"
mkdir -p "${SEPOLIA_DEPLOYMENTS}/private"
DEPLOY_LOG="${SEPOLIA_DEPLOYMENTS}/private/forge-deploy.log"
(
  cd "${REPO_ROOT}/contracts"
  GOVERNANCE_ADDRESS="${GOVERNANCE_ADDRESS}" forge script \
    script/DeployResolverIdentityRegistry.s.sol:DeployResolverIdentityRegistry \
    --rpc-url "${RI_TESTNET_RPC_URL}" \
    --broadcast \
    --slow \
    --non-interactive \
    --sender "${DEPLOYER_ADDRESS}" \
    --keystore "${DEPLOYER_KEYSTORE_FILE}" \
    --password-file "${DEPLOYER_KEYSTORE_PASSWORD_FILE}" \
    >"${DEPLOY_LOG}" 2>&1
)

[[ -f "${BROADCAST_FILE}" ]] || die "Foundry broadcast receipt file is absent"
CONTRACT_ADDRESS="$(jq -er '.transactions[] | select(.contractName == "ResolverIdentityRegistryV1") | .contractAddress' "${BROADCAST_FILE}" | tail -n 1)"
DEPLOY_TX="$(jq -er '.transactions[] | select(.contractName == "ResolverIdentityRegistryV1") | .hash' "${BROADCAST_FILE}" | tail -n 1)"
validate_address "${CONTRACT_ADDRESS}" "deployed Registry address"
validate_bytes32 "${DEPLOY_TX}" "deployment transaction hash"

RECEIPT="$(cast receipt "${DEPLOY_TX}" --rpc-url "${RI_TESTNET_RPC_URL}" --json)"
STATUS="$(jq -er '.status' <<<"${RECEIPT}")"
[[ "${STATUS}" == "0x1" || "${STATUS}" == "1" ]] || die "deployment transaction failed"
BLOCK_RAW="$(jq -er '.blockNumber' <<<"${RECEIPT}")"
if [[ "${BLOCK_RAW}" == 0x* ]]; then
  DEPLOYMENT_BLOCK="$(cast to-dec "${BLOCK_RAW}")"
else
  DEPLOYMENT_BLOCK="${BLOCK_RAW}"
fi
DEPLOYMENT_BLOCK_HASH="$(jq -er '.blockHash' <<<"${RECEIPT}")"
GAS_RAW="$(jq -er '.gasUsed' <<<"${RECEIPT}")"
if [[ "${GAS_RAW}" == 0x* ]]; then
  GAS_USED="$(cast to-dec "${GAS_RAW}")"
else
  GAS_USED="${GAS_RAW}"
fi

ARTIFACT="${REPO_ROOT}/contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json"
COMPILER_VERSION="$(jq -r '.metadata | fromjson | .compiler.version' "${ARTIFACT}")"
OPTIMIZER_ENABLED="$(jq -r '.metadata | fromjson | .settings.optimizer.enabled // false' "${ARTIFACT}")"
OPTIMIZER_RUNS="$(jq -r '.metadata | fromjson | .settings.optimizer.runs // 200' "${ARTIFACT}")"
SOURCE_VERIFICATION="not-requested"

jq -n \
  --arg network_name ethereum-sepolia \
  --argjson chain_id "${CHAIN_ID}" \
  --argjson deployment_block "${DEPLOYMENT_BLOCK}" \
  --arg deployment_block_hash "${DEPLOYMENT_BLOCK_HASH}" \
  --arg contract_address "${CONTRACT_ADDRESS}" \
  --arg deployment_transaction_hash "${DEPLOY_TX}" \
  --arg deployer_address "${DEPLOYER_ADDRESS}" \
  --arg governance_address "${GOVERNANCE_ADDRESS}" \
  --arg compiler_version "${COMPILER_VERSION}" \
  --argjson optimizer_enabled "${OPTIMIZER_ENABLED}" \
  --argjson optimizer_runs "${OPTIMIZER_RUNS}" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD)" \
  --arg deployment_time "$(utc_now)" \
  --argjson gas_used "${GAS_USED}" \
  --arg source_verification "${SOURCE_VERIFICATION}" \
  '{
    network_name:$network_name,
    chain_id:$chain_id,
    deployment_block:$deployment_block,
    deployment_block_hash:$deployment_block_hash,
    contract_address:$contract_address,
    deployment_transaction_hash:$deployment_transaction_hash,
    deployer_address:$deployer_address,
    governance_address:$governance_address,
    compiler_version:$compiler_version,
    optimizer_settings:{enabled:$optimizer_enabled,runs:$optimizer_runs},
    git_commit:$git_commit,
    deployment_time:$deployment_time,
    gas_used:$gas_used,
    source_verification:$source_verification
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/deployment.json"

assert_live_contract "${CONTRACT_ADDRESS}"

if [[ -n "${EXPLORER_API_KEY:-}" ]]; then
  CONSTRUCTOR_ARGS="$(cast abi-encode 'constructor(address)' "${GOVERNANCE_ADDRESS}")"
  if (
    cd "${REPO_ROOT}/contracts"
    ETHERSCAN_API_KEY="${EXPLORER_API_KEY}" forge verify-contract \
      --chain "${CHAIN_ID}" \
      --rpc-url "${RI_TESTNET_VERIFY_RPC_URL}" \
      --constructor-args "${CONSTRUCTOR_ARGS}" \
      --watch \
      "${CONTRACT_ADDRESS}" \
      src/ResolverIdentityRegistryV1.sol:ResolverIdentityRegistryV1
  ); then
    tmp="${SEPOLIA_DEPLOYMENTS}/deployment.json.tmp"
    jq '.source_verification = "verified"' "${SEPOLIA_DEPLOYMENTS}/deployment.json" >"${tmp}"
    mv "${tmp}" "${SEPOLIA_DEPLOYMENTS}/deployment.json"
  else
    tmp="${SEPOLIA_DEPLOYMENTS}/deployment.json.tmp"
    jq '.source_verification = "failed"' "${SEPOLIA_DEPLOYMENTS}/deployment.json" >"${tmp}"
    mv "${tmp}" "${SEPOLIA_DEPLOYMENTS}/deployment.json"
    die "contract deployed, but requested explorer source verification failed"
  fi
fi

log "Registry deployed at ${CONTRACT_ADDRESS}; run 03-configure-roles.sh next"

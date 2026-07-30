#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands bash curl jq cast forge git python3 stat
load_sepolia_env
assert_sepolia_network

PREFLIGHT_SCOPE="full"
case "${1:-}" in
  "")
    ;;
  --registry-only)
    PREFLIGHT_SCOPE="registry-only"
    ;;
  *)
    die "usage: $0 [--registry-only]"
    ;;
esac

require_var GOVERNANCE_ADDRESS
validate_address "${GOVERNANCE_ADDRESS}" GOVERNANCE_ADDRESS

DEPLOYER_ADDRESS="$(signer_address_for DEPLOYER)"
ROOT_PUBLISHER_ADDRESS="$(signer_address_for ROOT_PUBLISHER)"
RESOLVER_PUBLISHER_ADDRESS="$(signer_address_for RESOLVER_PUBLISHER)"
ENDPOINT_MANAGER_ADDRESS="$(signer_address_for ENDPOINT_MANAGER)"
REVOKER_ADDRESS="$(signer_address_for REVOKER)"

require_signer_matches GOVERNANCE "${GOVERNANCE_ADDRESS}"

validate_address "${DEPLOYER_ADDRESS}" "Deployer address"
validate_address "${ROOT_PUBLISHER_ADDRESS}" "Root Publisher address"
validate_address "${RESOLVER_PUBLISHER_ADDRESS}" "Resolver Publisher address"
validate_address "${ENDPOINT_MANAGER_ADDRESS}" "Endpoint Manager address"
validate_address "${REVOKER_ADDRESS}" "Revoker address"
require_distinct_addresses \
  "${DEPLOYER_ADDRESS}" \
  "${GOVERNANCE_ADDRESS}" \
  "${ROOT_PUBLISHER_ADDRESS}" \
  "${RESOLVER_PUBLISHER_ADDRESS}" \
  "${ENDPOINT_MANAGER_ADDRESS}" \
  "${REVOKER_ADDRESS}"

DEPLOYER_BALANCE="$(require_balance "${DEPLOYER_ADDRESS}" Deployer 20000000000000000)"
GOVERNANCE_BALANCE="$(require_balance "${GOVERNANCE_ADDRESS}" Governance 5000000000000000)"
ROOT_BALANCE="$(require_balance "${ROOT_PUBLISHER_ADDRESS}" "Root Publisher" 5000000000000000)"
RESOLVER_BALANCE="$(require_balance "${RESOLVER_PUBLISHER_ADDRESS}" "Resolver Publisher" 5000000000000000)"
ENDPOINT_BALANCE="$(require_balance "${ENDPOINT_MANAGER_ADDRESS}" "Endpoint Manager" 5000000000000000)"
REVOKER_BALANCE="$(require_balance "${REVOKER_ADDRESS}" Revoker 5000000000000000)"

IDENTITY_INPUTS_VALIDATED=false
if [[ "${PREFLIGHT_SCOPE}" == "full" ]]; then
  require_var ISSUER_PRIVATE_KEY_FILE
  require_var ISSUER_PUBLIC_KEY_FILE
  require_private_file "${ISSUER_PRIVATE_KEY_FILE}" "Issuer private key"
  [[ -f "${ISSUER_PUBLIC_KEY_FILE}" ]] || die "Issuer public key file does not exist"
  require_var RI_UNSIGNED_IDENTITIES_SOURCE
  [[ -f "${RI_UNSIGNED_IDENTITIES_SOURCE}" ]] || die "real unsigned identity source is absent"
  IDENTITY_INPUTS_VALIDATED=true
fi

jq -n \
  --arg checked_at "$(utc_now)" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD)" \
  --argjson source_tree_clean "$(source_tree_clean && printf true || printf false)" \
  --arg scope "${PREFLIGHT_SCOPE}" \
  --argjson identity_inputs_validated "${IDENTITY_INPUTS_VALIDATED}" \
  --argjson chain_id "${CHAIN_ID}" \
  --arg primary_rpc_host "${PRIMARY_RPC_HOST}" \
  --arg verification_rpc_host "${VERIFY_RPC_HOST}" \
  --arg deployer_address "${DEPLOYER_ADDRESS}" \
  --arg governance_address "${GOVERNANCE_ADDRESS}" \
  --arg root_publisher_address "${ROOT_PUBLISHER_ADDRESS}" \
  --arg resolver_publisher_address "${RESOLVER_PUBLISHER_ADDRESS}" \
  --arg endpoint_manager_address "${ENDPOINT_MANAGER_ADDRESS}" \
  --arg revoker_address "${REVOKER_ADDRESS}" \
  --arg deployer_balance_wei "${DEPLOYER_BALANCE}" \
  --arg governance_balance_wei "${GOVERNANCE_BALANCE}" \
  --arg root_balance_wei "${ROOT_BALANCE}" \
  --arg resolver_balance_wei "${RESOLVER_BALANCE}" \
  --arg endpoint_balance_wei "${ENDPOINT_BALANCE}" \
  --arg revoker_balance_wei "${REVOKER_BALANCE}" \
  '{
    checked_at:$checked_at,git_commit:$git_commit,source_tree_clean:$source_tree_clean,
    scope:$scope,identity_inputs_validated:$identity_inputs_validated,
    network_name:"ethereum-sepolia",
    chain_id:$chain_id,
    primary_rpc_host:$primary_rpc_host,
    verification_rpc_host:$verification_rpc_host,
    addresses:{
      deployer:$deployer_address,
      governance:$governance_address,
      root_publisher:$root_publisher_address,
      resolver_publisher:$resolver_publisher_address,
      endpoint_manager:$endpoint_manager_address,
      revoker:$revoker_address
    },
    balances_wei:{
      deployer:$deployer_balance_wei,
      governance:$governance_balance_wei,
      root_publisher:$root_balance_wei,
      resolver_publisher:$resolver_balance_wei,
      endpoint_manager:$endpoint_balance_wei,
      revoker:$revoker_balance_wei
    }
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/preflight.json"

log "${PREFLIGHT_SCOPE} preflight passed for chain ${CHAIN_ID}; no secret value was written to the manifest"

#!/usr/bin/env bash
set -Eeuo pipefail

readonly SEPOLIA_EXPECTED_CHAIN_ID=11155111
readonly MAINNET_CHAIN_ID=1
readonly ZERO_ADDRESS=0x0000000000000000000000000000000000000000
readonly ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
readonly COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${COMMON_DIR}/../../.." && pwd)"
readonly SEPOLIA_DEPLOYMENTS="${REPO_ROOT}/deployments/sepolia"
readonly SEPOLIA_ENV_FILE="${RI_SEPOLIA_ENV_FILE:-${REPO_ROOT}/.env.sepolia.local}"

cd "${REPO_ROOT}"

log() {
  printf '[sepolia] %s\n' "$*" >&2
}

die() {
  printf '[sepolia] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    require_command "${command_name}"
  done
}

require_var() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "required variable is unset: ${name}"
}

require_private_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" ]] || die "${label} file does not exist"
  local mode
  mode="$(stat -c '%a' "${path}")"
  (( (8#${mode} & 8#077) == 0 )) || die "${label} file must not be accessible by group or others"
}

load_sepolia_env() {
  require_private_file "${SEPOLIA_ENV_FILE}" ".env.sepolia.local"
  set -a
  # shellcheck disable=SC1090
  source "${SEPOLIA_ENV_FILE}"
  set +a
}

require_https_url() {
  local value="$1"
  local label="$2"
  [[ "${value}" == https://* ]] || die "${label} must use HTTPS"
}

rpc_host() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.stdin.read().strip()).hostname or "")'
}

rpc_call() {
  local rpc_url="$1"
  local method="$2"
  local params="$3"
  local payload response
  payload="$(jq -cn --arg method "${method}" --argjson params "${params}" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
  response="$(curl --fail --silent --show-error \
    --connect-timeout 10 --max-time 45 \
    -H 'content-type: application/json' \
    --data "${payload}" "${rpc_url}")" || die "JSON-RPC request failed for ${method}"
  if [[ "$(jq -r 'has("error")' <<<"${response}")" == "true" ]]; then
    die "JSON-RPC ${method} returned an error"
  fi
  jq -ce '.result' <<<"${response}"
}

rpc_chain_id() {
  local raw
  raw="$(rpc_call "$1" eth_chainId '[]')"
  raw="$(jq -r '.' <<<"${raw}")"
  cast to-dec "${raw}"
}

rpc_block() {
  local tag="$2"
  rpc_call "$1" eth_getBlockByNumber "$(jq -cn --arg tag "${tag}" '[$tag,false]')"
}

rpc_code() {
  local rpc_url="$1"
  local address="$2"
  local block_tag="${3:-latest}"
  rpc_call "${rpc_url}" eth_getCode \
    "$(jq -cn --arg address "${address}" --arg block "${block_tag}" '[$address,$block]')" |
    jq -r '.'
}

assert_sepolia_network() {
  require_var RI_TESTNET_RPC_URL
  require_var RI_TESTNET_VERIFY_RPC_URL
  require_https_url "${RI_TESTNET_RPC_URL}" RI_TESTNET_RPC_URL
  require_https_url "${RI_TESTNET_VERIFY_RPC_URL}" RI_TESTNET_VERIFY_RPC_URL
  [[ "${RI_TESTNET_RPC_URL}" != "${RI_TESTNET_VERIFY_RPC_URL}" ]] ||
    die "primary and verification RPC URLs must differ"

  PRIMARY_RPC_HOST="$(printf '%s' "${RI_TESTNET_RPC_URL}" | rpc_host)"
  VERIFY_RPC_HOST="$(printf '%s' "${RI_TESTNET_VERIFY_RPC_URL}" | rpc_host)"
  [[ -n "${PRIMARY_RPC_HOST}" && -n "${VERIFY_RPC_HOST}" ]] || die "RPC host name is invalid"
  [[ "${PRIMARY_RPC_HOST}" != "${VERIFY_RPC_HOST}" ]] ||
    die "primary and verification RPC hosts must differ"

  local primary_chain verify_chain
  primary_chain="$(rpc_chain_id "${RI_TESTNET_RPC_URL}")"
  verify_chain="$(rpc_chain_id "${RI_TESTNET_VERIFY_RPC_URL}")"
  [[ "${primary_chain}" != "${MAINNET_CHAIN_ID}" && "${verify_chain}" != "${MAINNET_CHAIN_ID}" ]] ||
    die "Ethereum Mainnet is forbidden"
  [[ "${primary_chain}" == "${verify_chain}" ]] || die "RPC Chain IDs do not match"
  [[ "${primary_chain}" == "${SEPOLIA_EXPECTED_CHAIN_ID}" ]] ||
    die "RPC is not Ethereum Sepolia"
  CHAIN_ID="${primary_chain}"
  export CHAIN_ID PRIMARY_RPC_HOST VERIFY_RPC_HOST
}

validate_address() {
  local address="${1,,}"
  local label="$2"
  [[ "${address}" =~ ^0x[0-9a-f]{40}$ ]] || die "${label} is not a 20-byte EVM address"
  [[ "${address}" != "${ZERO_ADDRESS}" ]] || die "${label} must not be the zero address"
}

validate_bytes32() {
  local value="${1,,}"
  local label="$2"
  [[ "${value}" =~ ^0x[0-9a-f]{64}$ ]] || die "${label} is not bytes32"
  [[ "${value}" != "${ZERO_BYTES32}" ]] || die "${label} must not be zero"
}

require_distinct_addresses() {
  local seen=""
  local value
  for value in "$@"; do
    value="${value,,}"
    [[ " ${seen} " != *" ${value} "* ]] || die "deployment role addresses must all be different"
    seen+=" ${value}"
  done
}

keystore_address() {
  local keystore="$1"
  local password_file="$2"
  require_private_file "${keystore}" "keystore"
  require_private_file "${password_file}" "keystore password"
  cast wallet address --keystore "${keystore}" --password-file "${password_file}"
}

signer_address_for() {
  local prefix="$1"
  local key_var="${prefix}_KEYSTORE_FILE"
  local password_var="${prefix}_KEYSTORE_PASSWORD_FILE"
  require_var "${key_var}"
  require_var "${password_var}"
  keystore_address "${!key_var}" "${!password_var}"
}

require_signer_matches() {
  local prefix="$1"
  local expected="$2"
  local actual
  actual="$(signer_address_for "${prefix}")"
  [[ "${actual,,}" == "${expected,,}" ]] ||
    die "${prefix} keystore address does not match configured address"
}

require_balance() {
  local address="$1"
  local label="$2"
  local minimum_wei="$3"
  local balance
  balance="$(cast balance "${address}" --rpc-url "${RI_TESTNET_RPC_URL}")"
  [[ "${balance}" =~ ^[0-9]+$ ]] || die "could not read ${label} balance"
  (( balance >= minimum_wei )) ||
    die "${label} balance is below required preflight minimum"
  printf '%s' "${balance}"
}

contract_address() {
  [[ -f "${SEPOLIA_DEPLOYMENTS}/deployment.json" ]] ||
    die "deployment.json is absent; deploy the Registry first"
  jq -er '.contract_address' "${SEPOLIA_DEPLOYMENTS}/deployment.json"
}

verified_code_hash() {
  [[ -f "${SEPOLIA_DEPLOYMENTS}/verification.json" ]] ||
    die "verification.json is absent; verify the deployment first"
  jq -er '.runtime_code_hash' "${SEPOLIA_DEPLOYMENTS}/verification.json"
}

assert_live_contract() {
  local address="$1"
  local expected_hash="${2:-}"
  validate_address "${address}" "Registry contract address"
  local primary_code verify_code
  primary_code="$(rpc_code "${RI_TESTNET_RPC_URL}" "${address}" latest)"
  verify_code="$(rpc_code "${RI_TESTNET_VERIFY_RPC_URL}" "${address}" latest)"
  [[ "${primary_code}" != "0x" ]] || die "Registry contract has no runtime code"
  [[ "${primary_code}" == "${verify_code}" ]] || die "RPC runtime bytecode differs"
  local actual_hash
  actual_hash="$(cast keccak "${primary_code}")"
  validate_bytes32 "${actual_hash}" "Registry runtime code hash"
  if [[ -n "${expected_hash}" ]]; then
    [[ "${actual_hash,,}" == "${expected_hash,,}" ]] ||
      die "Registry runtime code hash differs from the pinned value"
  fi
}

role_hash() {
  cast keccak "$1"
}

has_role() {
  local rpc_url="$1"
  local registry="$2"
  local role="$3"
  local account="$4"
  cast call "${registry}" 'hasRole(bytes32,address)(bool)' "${role}" "${account}" \
    --rpc-url "${rpc_url}"
}

wait_for_role() {
  local rpc_url="$1"
  local registry="$2"
  local role="$3"
  local account="$4"
  local expected="$5"
  local deadline="$(( $(date +%s) + ${RI_ROLE_VERIFY_TIMEOUT_SECONDS:-180} ))"
  until [[ "$(has_role "${rpc_url}" "${registry}" "${role}" "${account}")" == "${expected}" ]]; do
    (( $(date +%s) < deadline )) ||
      die "role state did not reach the independent RPC before timeout"
    sleep 3
  done
}

utc_now() {
  date -u +'%Y-%m-%dT%H:%M:%SZ'
}

write_json_atomic() {
  local target="$1"
  local temporary="${target}.tmp"
  mkdir -p "$(dirname "${target}")"
  jq -S . >"${temporary}"
  mv "${temporary}" "${target}"
}

export_registry_writer() {
  local prefix="$1"
  local expected_sender="$2"
  local key_var="${prefix}_KEYSTORE_FILE"
  local password_var="${prefix}_KEYSTORE_PASSWORD_FILE"
  require_var "${key_var}"
  require_var "${password_var}"
  require_private_file "${!key_var}" "${prefix} keystore"
  require_private_file "${!password_var}" "${prefix} keystore password"
  export RESOLVER_IDENTITY_ENVIRONMENT=production
  export RESOLVER_IDENTITY_REGISTRY_MODE=web3
  export RESOLVER_IDENTITY_WEB3_RPC_URL="${RI_TESTNET_RPC_URL}"
  export RESOLVER_IDENTITY_WEB3_CHAIN_ID="${CHAIN_ID}"
  export RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS
  RESOLVER_IDENTITY_WEB3_CONTRACT_ADDRESS="$(contract_address)"
  export RESOLVER_IDENTITY_WEB3_CONTRACT_CODE_HASH
  RESOLVER_IDENTITY_WEB3_CONTRACT_CODE_HASH="$(verified_code_hash)"
  export RESOLVER_IDENTITY_WEB3_ABI_PATH="${REPO_ROOT}/contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json"
  export RESOLVER_IDENTITY_WEB3_SENDER_ADDRESS="${expected_sender}"
  export RESOLVER_IDENTITY_WEB3_KEYSTORE_FILE="${!key_var}"
  export RESOLVER_IDENTITY_WEB3_KEYSTORE_PASSWORD_FILE="${!password_var}"
  unset RESOLVER_IDENTITY_WEB3_PRIVATE_KEY_ENV RESOLVER_IDENTITY_WEB3_PRIVATE_KEY_FILE
}

redacted_rpc_host() {
  printf '%s' "$1" | rpc_host
}

source_tree_clean() {
  git -C "${REPO_ROOT}" diff --quiet &&
    git -C "${REPO_ROOT}" diff --cached --quiet &&
    ! git -C "${REPO_ROOT}" ls-files --others --exclude-standard |
      grep -Ev '^deployments/sepolia/(preflight|test-results)\.json$' |
      grep -q .
}

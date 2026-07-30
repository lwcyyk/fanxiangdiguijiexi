#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INVENTORY="${1:-${RI_FIELD_INVENTORY:-}}"
[[ -n "${INVENTORY}" ]] || field_die "usage: $0 /secure/path/site-inventory.json"
INVENTORY="$(realpath "${INVENTORY}")"

field_require_commands python3 git docker openssl jq sha256sum sqlite3 curl cast timeout
docker compose version >/dev/null
python3 "${FIELD_REPO_ROOT}/tools/manage_field_deployment.py" validate \
  --inventory "${INVENTORY}"

expected_commit="$(jq -er '.release.git_commit' "${INVENTORY}")"
actual_commit="$(git -C "${FIELD_REPO_ROOT}" rev-parse HEAD)"
[[ "${actual_commit}" == "${expected_commit}" ]] ||
  field_die "inventory commit ${expected_commit} does not match source ${actual_commit}"

if ! git -C "${FIELD_REPO_ROOT}" diff --quiet ||
  ! git -C "${FIELD_REPO_ROOT}" diff --cached --quiet; then
  field_die "tracked source tree is dirty"
fi
untracked_files="$(
  git -C "${FIELD_REPO_ROOT}" ls-files --others --exclude-standard
)"
if [[ -n "${untracked_files}" ]]; then
  field_die "source tree contains untracked files"
fi

rpc_url="$(jq -er '.registry.rpc_url' "${INVENTORY}")"
verification_rpc_url="$(jq -er '.registry.verification_rpc_url' "${INVENTORY}")"
expected_chain="$(jq -er '.registry.chain_id' "${INVENTORY}")"
registry_address="$(jq -er '.registry.contract_address' "${INVENTORY}")"
expected_code_hash="$(jq -er '.registry.runtime_code_hash' "${INVENTORY}")"
rpc_cast() {
  local timeout_seconds="${RI_FIELD_RPC_TIMEOUT_SECONDS:-20}"
  [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]] ||
    field_die "RI_FIELD_RPC_TIMEOUT_SECONDS must be a positive integer"
  field_retry timeout "${timeout_seconds}" cast "$@"
}

actual_chain="$(rpc_cast chain-id --rpc-url "${rpc_url}")"
verification_chain="$(rpc_cast chain-id --rpc-url "${verification_rpc_url}")"
[[ "${actual_chain}" != "1" && "${verification_chain}" != "1" ]] ||
  field_die "Ethereum Mainnet is forbidden"
[[ "${actual_chain}" == "${expected_chain}" &&
  "${verification_chain}" == "${expected_chain}" ]] ||
  field_die "live RPC Chain IDs do not match the inventory"

primary_finalized="$(
  rpc_cast block finalized --field number --rpc-url "${rpc_url}"
)"
verification_finalized="$(
  rpc_cast block finalized --field number --rpc-url "${verification_rpc_url}"
)"
common_finalized="${primary_finalized}"
(( verification_finalized < common_finalized )) &&
  common_finalized="${verification_finalized}"
primary_block_hash="$(
  rpc_cast block "${common_finalized}" --field hash --rpc-url "${rpc_url}"
)"
verification_block_hash="$(
  rpc_cast block "${common_finalized}" --field hash --rpc-url "${verification_rpc_url}"
)"
[[ "${primary_block_hash}" == "${verification_block_hash}" ]] ||
  field_die "independent RPC block hashes differ at the common finalized height"

runtime_code="$(
  rpc_cast code "${registry_address}" --block "${common_finalized}" --rpc-url "${rpc_url}"
)"
verification_runtime_code="$(
  rpc_cast code "${registry_address}" --block "${common_finalized}" \
    --rpc-url "${verification_rpc_url}"
)"
[[ "${runtime_code}" != "0x" && "${verification_runtime_code}" != "0x" ]] ||
  field_die "Registry has no finalized runtime bytecode"
[[ "${runtime_code}" == "${verification_runtime_code}" ]] ||
  field_die "independent RPC finalized runtime bytecode differs"
actual_code_hash="$(cast keccak "${runtime_code}")"
[[ "${actual_code_hash,,}" == "${expected_code_hash,,}" ]] ||
  field_die "live finalized runtime code hash does not match the inventory"

roles_file="$(jq -er '.artifacts.roles_file' "${INVENTORY}")"
governance_address="$(jq -er '.governance_address' "${roles_file}")"
default_admin_role="0x$(printf '0%.0s' {1..64})"
root_role="$(cast keccak ROOT_PUBLISHER_ROLE)"
resolver_role="$(cast keccak RESOLVER_PUBLISHER_ROLE)"
endpoint_role="$(cast keccak ENDPOINT_MANAGER_ROLE)"
revoker_role="$(cast keccak REVOKER_ROLE)"

live_has_role() {
  local rpc="$1"
  local role="$2"
  local account="$3"
  rpc_cast call "${registry_address}" 'hasRole(bytes32,address)(bool)' \
    "${role}" "${account}" --block "${common_finalized}" --rpc-url "${rpc}"
}

for rpc in "${rpc_url}" "${verification_rpc_url}"; do
  [[ "$(live_has_role "${rpc}" "${default_admin_role}" "${governance_address}")" == "true" ]] ||
    field_die "Governance is not the live finalized default admin"
  [[ "$(rpc_cast call "${registry_address}" 'adminCount()(uint256)' \
    --block "${common_finalized}" --rpc-url "${rpc}")" == "1" ]] ||
    field_die "live finalized Registry adminCount is not one"
done

for role_and_field in \
  "${root_role}:root_publisher_address" \
  "${resolver_role}:resolver_publisher_address" \
  "${endpoint_role}:endpoint_manager_address" \
  "${revoker_role}:revoker_address"; do
  role="${role_and_field%%:*}"
  address_field="${role_and_field#*:}"
  role_holder="$(jq -er --arg field "${address_field}" '.[$field]' "${roles_file}")"
  for rpc in "${rpc_url}" "${verification_rpc_url}"; do
    [[ "$(live_has_role "${rpc}" "${role}" "${role_holder}")" == "true" ]] ||
      field_die "live finalized business role holder differs from roles evidence"
    [[ "$(live_has_role "${rpc}" "${role}" "${governance_address}")" == "false" ]] ||
      field_die "Governance unexpectedly retains a live finalized business role"
  done
done

identities_file="$(jq -er '.artifacts.identities_file' "${INVENTORY}")"
issuer_keys_file="$(jq -er '.artifacts.issuer_keys_file' "${INVENTORY}")"
PYTHONPATH="${FIELD_REPO_ROOT}/src" \
  python3 "${FIELD_REPO_ROOT}/tools/manage_v2_registry.py" verify-identities \
    --identities "${identities_file}" \
    --issuer-keys "${issuer_keys_file}"

image="$(jq -er '.release.image' "${INVENTORY}")"
docker image inspect "${image}" >/dev/null ||
  field_die "approved digest image is not present on the Hub"

field_log "preflight passed for site $(jq -r '.site_id' "${INVENTORY}") at finalized block ${common_finalized}"

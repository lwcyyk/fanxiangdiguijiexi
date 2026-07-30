#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INVENTORY="${1:-${RI_FIELD_INVENTORY:-}}"
[[ -n "${INVENTORY}" ]] || field_die "usage: $0 /secure/path/site-inventory.json"
INVENTORY="$(realpath "${INVENTORY}")"

field_require_commands python3 git docker openssl jq sha256sum sqlite3 curl cast
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
expected_chain="$(jq -er '.registry.chain_id' "${INVENTORY}")"
registry_address="$(jq -er '.registry.contract_address' "${INVENTORY}")"
expected_code_hash="$(jq -er '.registry.runtime_code_hash' "${INVENTORY}")"
actual_chain="$(ETH_RPC_URL="${rpc_url}" cast chain-id)"
[[ "${actual_chain}" != "1" ]] || field_die "Ethereum Mainnet is forbidden"
[[ "${actual_chain}" == "${expected_chain}" ]] ||
  field_die "live RPC chain ID does not match the inventory"
runtime_code="$(
  ETH_RPC_URL="${rpc_url}" cast code "${registry_address}" --block finalized
)"
[[ "${runtime_code}" != "0x" ]] ||
  field_die "Registry has no finalized runtime bytecode"
actual_code_hash="$(cast keccak "${runtime_code}")"
[[ "${actual_code_hash,,}" == "${expected_code_hash,,}" ]] ||
  field_die "live finalized runtime code hash does not match the inventory"

identities_file="$(jq -er '.artifacts.identities_file' "${INVENTORY}")"
issuer_keys_file="$(jq -er '.artifacts.issuer_keys_file' "${INVENTORY}")"
PYTHONPATH="${FIELD_REPO_ROOT}/src" \
  python3 "${FIELD_REPO_ROOT}/tools/manage_v2_registry.py" verify-identities \
    --identities "${identities_file}" \
    --issuer-keys "${issuer_keys_file}"

image="$(jq -er '.release.image' "${INVENTORY}")"
docker image inspect "${image}" >/dev/null ||
  field_die "approved digest image is not present on the Hub"

field_log "preflight passed for site $(jq -r '.site_id' "${INVENTORY}")"

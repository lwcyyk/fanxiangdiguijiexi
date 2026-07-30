#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq python3 curl cast
load_sepolia_env
assert_sepolia_network
require_var RI_REVOCATION_TEST_SERVER_ID
[[ "${RI_CONFIRM_REVOCATION_TEST:-}" == "IRREVERSIBLY_REVOKE_SEPOLIA_TEST_IDENTITY" ]] ||
  die "set RI_CONFIRM_REVOCATION_TEST=IRREVERSIBLY_REVOKE_SEPOLIA_TEST_IDENTITY"
PLAN="${SEPOLIA_DEPLOYMENTS}/registry-plan-v2.json"
ROLES="${SEPOLIA_DEPLOYMENTS}/roles.json"
[[ -f "${PLAN}" && -f "${ROLES}" ]] || die "plan and role evidence are required"
jq -e --arg server_id "${RI_REVOCATION_TEST_SERVER_ID}" \
  '.entries[] | select(.server_id == $server_id)' "${PLAN}" >/dev/null ||
  die "revocation target is not a dedicated identity in the current plan"
[[ "${RI_REVOCATION_TEST_SERVER_ID,,}" == *test* ]] ||
  die "revocation target server_id must be visibly dedicated to testing"

REVOKER_ADDRESS="$(jq -er '.revoker_address' "${ROLES}")"
REVOKER_ROLE="$(role_hash REVOKER_ROLE)"
[[ "$(has_role "${RI_TESTNET_VERIFY_RPC_URL}" "$(contract_address)" "${REVOKER_ROLE}" "${REVOKER_ADDRESS}")" == "true" ]] ||
  die "configured Revoker does not hold REVOKER_ROLE"
require_signer_matches REVOKER "${REVOKER_ADDRESS}"
export_registry_writer REVOKER "${REVOKER_ADDRESS}"

RECEIPT_FILE="${SEPOLIA_DEPLOYMENTS}/private/revocation-test-receipt.json"
log "irreversibly revoking dedicated test identity ${RI_REVOCATION_TEST_SERVER_ID}"
PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" revoke-resolver \
  --server-id "${RI_REVOCATION_TEST_SERVER_ID}" \
  --receipt-output "${RECEIPT_FILE}"

jq -n \
  --arg revoked_at "$(utc_now)" \
  --arg server_id "${RI_REVOCATION_TEST_SERVER_ID}" \
  --arg warning "This resolver is permanently revoked and cannot be restored." \
  --argjson transactions "$(jq '.transactions' "${RECEIPT_FILE}")" \
  '{revoked_at:$revoked_at,server_id:$server_id,warning:$warning,transactions:$transactions}' |
  write_json_atomic "${SEPOLIA_DEPLOYMENTS}/revocation-test.json"

sleep "$(( ${RI_REGISTRY_MAX_STALENESS_SECONDS:-15} + 4 ))"
if curl --fail --silent http://127.0.0.1:9109/readyz >/dev/null 2>&1; then
  die "Registry Sync remained ready after the published identity was revoked"
fi
log "revocation propagated and Registry Sync failed closed as expected"

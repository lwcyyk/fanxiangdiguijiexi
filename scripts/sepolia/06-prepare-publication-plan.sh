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

IDENTITIES="${SEPOLIA_DEPLOYMENTS}/identities-v2.json"
ISSUER_KEYS="${SEPOLIA_DEPLOYMENTS}/issuer-keys.json"
PLAN="${SEPOLIA_DEPLOYMENTS}/registry-plan-v2.json"
[[ -f "${IDENTITIES}" && -f "${ISSUER_KEYS}" ]] ||
  die "signed identities and Issuer key bundle are required"
ROOT_VERSION="${RI_ROOT_VERSION:-1}"
[[ "${ROOT_VERSION}" =~ ^[1-9][0-9]*$ ]] || die "RI_ROOT_VERSION must be positive"

ARGS=(
  prepare
  --identities "${IDENTITIES}"
  --issuer-keys "${ISSUER_KEYS}"
  --root-version "${ROOT_VERSION}"
  --chain-id "${CHAIN_ID}"
  --contract-address "${REGISTRY_ADDRESS}"
  --contract-code-hash "${REGISTRY_CODE_HASH}"
  --output "${PLAN}"
)
if [[ -n "${RI_PREVIOUS_PLAN_FILE:-}" ]]; then
  [[ -f "${RI_PREVIOUS_PLAN_FILE}" ]] || die "previous approved plan is absent"
  ARGS+=(--previous-plan "${RI_PREVIOUS_PLAN_FILE}")
fi

SUMMARY="$(
  PYTHONPATH="${REPO_ROOT}/src" \
    python3 "${REPO_ROOT}/tools/manage_v2_registry.py" "${ARGS[@]}"
)"
PLAN_HASH="$(jq -er '.plan_hash' <<<"${SUMMARY}")"
validate_bytes32 "${PLAN_HASH}" "publication plan hash"

PYTHONPATH="${REPO_ROOT}/src" python3 - "${PLAN}" "${PLAN_HASH}" <<'PY'
import sys
from pathlib import Path
from tools.manage_v2_registry import load_plan

load_plan(Path(sys.argv[1]), sys.argv[2])
PY

jq -n \
  --arg generated_at "$(utc_now)" \
  --argjson summary "${SUMMARY}" \
  '{generated_at:$generated_at} + $summary' |
  write_json_atomic "${SEPOLIA_DEPLOYMENTS}/plan-summary.json"

log "publication plan generated and independently rehashed: ${PLAN_HASH}"

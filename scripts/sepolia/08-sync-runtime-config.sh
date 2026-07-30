#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands jq install sha256sum
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
REGISTRY_CODE_HASH="$(verified_code_hash)"
assert_live_contract "${REGISTRY_ADDRESS}" "${REGISTRY_CODE_HASH}"

for name in \
  RI_AGENT_SERVER_ID RI_AGENT_KEY_ID RI_TRACE_PRODUCER_UID RI_TRACE_PRODUCER_GID \
  RI_TRACE_SOCKET_HOST_DIR RI_WRAPPER_UPSTREAMS DNS_BIND_ADDRESS; do
  require_var "${name}"
  [[ "${!name}" != *$'\n'* && "${!name}" != *$'\r'* ]] ||
    die "${name} contains a newline"
done

IDENTITIES="${SEPOLIA_DEPLOYMENTS}/identities-v2.json"
ISSUER_KEYS="${SEPOLIA_DEPLOYMENTS}/issuer-keys.json"
PUBLICATION="${SEPOLIA_DEPLOYMENTS}/publication-transactions.json"
[[ -f "${IDENTITIES}" && -f "${ISSUER_KEYS}" && -f "${PUBLICATION}" ]] ||
  die "successful identity publication evidence is required"
[[ "$(jq -c '.completed_phases | sort' "${PUBLICATION}")" ==
  '["bind-endpoints","publish-resolvers","publish-root","revoke-removed","unbind-endpoints"]' ]] ||
  die "identity publication evidence does not contain all five phases"

SEPOLIA_ENV="${REPO_ROOT}/deploy/link/.env.sepolia"
SEPOLIA_IDENTITIES="${REPO_ROOT}/deploy/link/identities-v2.sepolia.json"
SEPOLIA_ISSUERS="${REPO_ROOT}/deploy/issuer-keys.sepolia.json"
RUNTIME_ENV="${REPO_ROOT}/deploy/link/.env"
RUNTIME_IDENTITIES="${REPO_ROOT}/deploy/link/identities-v2.json"
RUNTIME_ISSUERS="${REPO_ROOT}/deploy/issuer-keys.json"

umask 077
{
  printf 'RI_IMAGE=%s\n' "${RI_IMAGE:-resolver-identity-rust:sepolia-preprod}"
  printf 'RI_ENVIRONMENT=production\n'
  printf 'RI_VERIFICATION_MODE=public-hybrid\n'
  printf 'RI_WEB3_RPC_URL=%s\n' "${RI_TESTNET_RPC_URL}"
  printf 'RI_WEB3_CHAIN_ID=%s\n' "${CHAIN_ID}"
  printf 'RI_REGISTRY_CONTRACT_ADDRESS=%s\n' "${REGISTRY_ADDRESS}"
  printf 'RI_REGISTRY_CODE_HASH=%s\n' "${REGISTRY_CODE_HASH}"
  printf 'RI_REGISTRY_POLL_INTERVAL_MS=2000\n'
  printf 'RI_REGISTRY_FALLBACK_CONFIRMATIONS=%s\n' "${RI_REGISTRY_FALLBACK_CONFIRMATIONS:-12}"
  printf 'RI_RPC_MAX_RESPONSE_BYTES=4194304\n'
  printf 'RI_REGISTRY_MAX_STALENESS_SECONDS=%s\n' "${RI_REGISTRY_MAX_STALENESS_SECONDS:-15}"
  printf 'RI_AGENT_SERVER_ID=%s\n' "${RI_AGENT_SERVER_ID}"
  printf 'RI_AGENT_KEY_ID=%s\n' "${RI_AGENT_KEY_ID}"
  printf 'RI_TRACE_PRODUCER_UID=%s\n' "${RI_TRACE_PRODUCER_UID}"
  printf 'RI_TRACE_PRODUCER_GID=%s\n' "${RI_TRACE_PRODUCER_GID}"
  printf 'RI_TRACE_SOCKET_HOST_DIR=%s\n' "${RI_TRACE_SOCKET_HOST_DIR}"
  printf 'RI_WRAPPER_UPSTREAMS=%s\n' "${RI_WRAPPER_UPSTREAMS}"
  printf 'DNS_BIND_ADDRESS=%s\n' "${DNS_BIND_ADDRESS}"
  printf 'DNS_PORT=%s\n' "${DNS_PORT:-53}"
  printf 'METRICS_BIND_ADDRESS=127.0.0.1\n'
  printf 'METRICS_PORT=9108\n'
  printf 'REGISTRY_METRICS_BIND_ADDRESS=127.0.0.1\n'
  printf 'REGISTRY_METRICS_PORT=9109\n'
  printf 'TRACE_METRICS_BIND_ADDRESS=127.0.0.1\n'
  printf 'TRACE_METRICS_PORT=9110\n'
  printf 'AGENT_BIND_ADDRESS=127.0.0.1\n'
  printf 'AGENT_PORT=8443\n'
} >"${SEPOLIA_ENV}"

install -m 0644 "${IDENTITIES}" "${SEPOLIA_IDENTITIES}"
install -m 0644 "${ISSUER_KEYS}" "${SEPOLIA_ISSUERS}"
install -m 0600 "${SEPOLIA_ENV}" "${RUNTIME_ENV}"
install -m 0644 "${SEPOLIA_IDENTITIES}" "${RUNTIME_IDENTITIES}"
install -m 0644 "${SEPOLIA_ISSUERS}" "${RUNTIME_ISSUERS}"

(
  cd "${REPO_ROOT}"
  sha256sum \
    deploy/link/.env.sepolia \
    deploy/link/identities-v2.sepolia.json \
    deploy/issuer-keys.sepolia.json \
    deploy/link/.env \
    deploy/link/identities-v2.json \
    deploy/issuer-keys.json
) >"${SEPOLIA_DEPLOYMENTS}/runtime-files.sha256"

(
  cd "${REPO_ROOT}"
  sha256sum --check "${SEPOLIA_DEPLOYMENTS}/runtime-files.sha256" \
    --ignore-missing >/dev/null
)
log "Sepolia runtime files were installed and hashed; .env files remain ignored by Git"

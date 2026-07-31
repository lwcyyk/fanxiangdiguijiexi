#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command cargo
require_command jq
require_command sqlite3

output_dir="${REPO_ROOT}/deployments/norn-local"
identities="${output_dir}/identities-v2.json"
issuer_keys="${output_dir}/issuer-keys.json"
preparation="${output_dir}/preparation.json"
baseline_database="${output_dir}/evidence-v2.db"
tls_dir="${NORN_DEPLOY_DIR}/private/tls"
[[ -s "${identities}" && -s "${issuer_keys}" && -s "${preparation}" &&
  -s "${baseline_database}" ]] || {
  printf 'run scripts/norn/03-prepare-snapshot.sh and 04-publish-and-sync.sh first\n' >&2
  exit 1
}

cargo build \
  --quiet \
  --manifest-path "${REPO_ROOT}/rust/Cargo.toml" \
  --package ri-registry-sync
sync_binary="${REPO_ROOT}/rust/target/debug/ri-registry-sync"
genesis_hash="$(jq -r .genesis_block_hash "${preparation}")"
registry_address="$(jq -r .registry_address "${preparation}")"
registry_key="$(jq -r .registry_key "${preparation}")"
schema_hash="$(jq -r .registry_schema_hash "${preparation}")"

base_environment=(
  RI_ENVIRONMENT=production
  RI_CHAIN_ADAPTER=norn
  RI_CHAIN_RPC_URLS=https://localhost:46555,https://localhost:46556
  RI_CHAIN_ID=20001
  RI_NORN_GENESIS_BLOCK_HASH="${genesis_hash}"
  RI_CHAIN_REGISTRY_ADDRESS="${registry_address}"
  RI_NORN_REGISTRY_KEY="${registry_key}"
  RI_NORN_SIGNER_ISSUER=norn-local-snapshot-authority
  RI_NORN_SIGNER_KEY_ID=snapshot-key-1
  RI_CHAIN_REGISTRY_SCHEMA_HASH="${schema_hash}"
  RI_CHAIN_CONFIRMATIONS=3
  RI_NORN_REGISTRY_START_HEIGHT=0
  RI_NORN_MAX_SCAN_BLOCKS=1000
  RI_NORN_TLS_CA_FILE="${tls_dir}/ca.crt"
  RI_NORN_TLS_CLIENT_CERT_FILE="${tls_dir}/client.crt"
  RI_NORN_TLS_CLIENT_KEY_FILE="${tls_dir}/client.key"
  RI_RPC_MAX_RESPONSE_BYTES=4194304
  RI_RPC_TIMEOUT_MS=2000
  RI_REGISTRY_POLL_INTERVAL_MS=1000
  RI_REGISTRY_SYNC_ONCE=true
  RI_REGISTRY_MONITORING_BIND=127.0.0.1:0
  RI_IDENTITIES_FILE="${identities}"
  RI_ISSUER_KEYS_FILE="${issuer_keys}"
)

results_file="${output_dir}/negative-results.ndjson"
: >"${results_file}"

cargo test \
  --quiet \
  --manifest-path "${REPO_ROOT}/rust/Cargo.toml" \
  --locked \
  --package ri-store \
  registry_snapshot_rejects_finalized_chain_rollback_atomically \
  >"${output_dir}/negative-store-high-water.log"
for name in low-height-replay same-height-different-hash old-generation-replay; do
  jq -nc --arg name "${name}" \
    '{test:$name,result:"failed-closed",snapshot_unchanged:true,success_heartbeat_unchanged:true}' \
    >>"${results_file}"
done

cargo test \
  --quiet \
  --manifest-path "${REPO_ROOT}/rust/Cargo.toml" \
  --locked \
  --package ri-chain-adapter \
  >"${output_dir}/negative-adapter-security.log"
for name in \
  snapshot-signature-and-signer-pin \
  snapshot-expiration-and-key-rotation \
  external-redirect-denied \
  external-dynamic-upstream-denied \
  non-evm-reference-has-no-evm-fields; do
  jq -nc --arg name "${name}" \
    '{test:$name,result:"failed-closed"}' \
    >>"${results_file}"
done

expect_configuration_failure() {
  local name="$1"
  shift
  local log="${output_dir}/negative-${name}.log"
  if "$@" >"${log}" 2>&1; then
    printf 'configuration test unexpectedly succeeded: %s\n' "${name}" >&2
    exit 1
  fi
  jq -nc --arg name "${name}" \
    '{test:$name,result:"failed-closed",registry_rows_written:0}' \
    >>"${results_file}"
}

expect_failure_without_snapshot() {
  local name="$1"
  shift
  local database="${output_dir}/negative-${name}.db"
  local log="${output_dir}/negative-${name}.log"
  rm -f "${database}" "${database}-shm" "${database}-wal"
  if env "${base_environment[@]}" RI_DATABASE="${database}" "$@" \
    "${sync_binary}" >"${log}" 2>&1; then
    printf 'negative test unexpectedly succeeded: %s\n' "${name}" >&2
    exit 1
  fi
  local rows=0
  if [[ -s "${database}" ]]; then
    rows="$(
      sqlite3 "${database}" \
        "SELECT COUNT(*) FROM ri_v2_registry_snapshot;" 2>/dev/null || printf '0'
    )"
  fi
  [[ "${rows}" == "0" ]] || {
    printf 'negative test wrote Registry state: %s\n' "${name}" >&2
    exit 1
  }
  jq -nc --arg name "${name}" \
    '{test:$name,result:"failed-closed",registry_rows_written:0}' \
    >>"${results_file}"
}

expect_failure_without_snapshot \
  wrong-genesis \
  RI_NORN_GENESIS_BLOCK_HASH=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expect_failure_without_snapshot \
  wrong-registry-id \
  RI_CHAIN_REGISTRY_ADDRESS=0xdddddddddddddddddddddddddddddddddddddddd
expect_failure_without_snapshot \
  wrong-signer-pin \
  RI_NORN_SIGNER_KEY_ID=untrusted-snapshot-key
expect_failure_without_snapshot \
  wrong-schema \
  RI_CHAIN_REGISTRY_SCHEMA_HASH=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
expect_failure_without_snapshot \
  one-production-rpc \
  RI_CHAIN_RPC_URLS=https://localhost:46555
expect_failure_without_snapshot \
  unavailable-verification-rpc \
  RI_CHAIN_RPC_URLS=https://localhost:46555,https://localhost:49999
expect_configuration_failure \
  unknown-adapter \
  env RI_ENVIRONMENT=production RI_CHAIN_ADAPTER=unknown "${sync_binary}"
expect_configuration_failure \
  missing-adapter-no-fallback \
  env -u RI_CHAIN_ADAPTER RI_ENVIRONMENT=production "${sync_binary}"

preserved_database="${output_dir}/negative-preserved.db"
rm -f "${preserved_database}" "${preserved_database}-shm" "${preserved_database}-wal"
cp "${baseline_database}" "${preserved_database}"
before_anchor="$(
  sqlite3 "${preserved_database}" \
    "SELECT finalized_block || ':' || finalized_block_hash || ':' || snapshot_json FROM ri_v2_registry_snapshot ORDER BY snapshot_key;"
)"
before_heartbeat="$(
  sqlite3 "${preserved_database}" \
    "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_last_success_epoch';"
)"
if env "${base_environment[@]}" \
  RI_DATABASE="${preserved_database}" \
  RI_CHAIN_REGISTRY_SCHEMA_HASH=0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  "${sync_binary}" >"${output_dir}/negative-preserved.log" 2>&1; then
  printf 'wrong schema unexpectedly updated an existing SQLite snapshot\n' >&2
  exit 1
fi
after_anchor="$(
  sqlite3 "${preserved_database}" \
    "SELECT finalized_block || ':' || finalized_block_hash || ':' || snapshot_json FROM ri_v2_registry_snapshot ORDER BY snapshot_key;"
)"
after_heartbeat="$(
  sqlite3 "${preserved_database}" \
    "SELECT meta_value FROM ri_v2_meta WHERE meta_key='registry_last_success_epoch';"
)"
[[ "${before_anchor}" == "${after_anchor}" ]] || {
  printf 'failed reconciliation changed the existing SQLite snapshot\n' >&2
  exit 1
}
[[ "${before_heartbeat}" == "${after_heartbeat}" ]] || {
  printf 'failed reconciliation refreshed the success heartbeat\n' >&2
  exit 1
}
jq -nc \
  '{test:"failed-update-preserves-sqlite-and-heartbeat",result:"failed-closed",snapshot_unchanged:true,success_heartbeat_unchanged:true}' \
  >>"${results_file}"

jq -s \
  '{
    adapter: "norn",
    result: "passed",
    tests: .
  }' "${results_file}" >"${output_dir}/acceptance-negative.json"
rm -f "${results_file}"
printf 'Norn negative acceptance completed: %s\n' \
  "${output_dir}/acceptance-negative.json"

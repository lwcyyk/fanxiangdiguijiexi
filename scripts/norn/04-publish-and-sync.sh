#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command cargo
require_command cmp
require_command jq
require_command python3
require_command sqlite3
require_command git

output_dir="${REPO_ROOT}/deployments/norn-local"
snapshot="${output_dir}/registry-snapshot-v1.json"
issuer_keys="${output_dir}/issuer-keys.json"
identities="${output_dir}/identities-v2.json"
preparation="${output_dir}/preparation.json"
[[ -s "${snapshot}" && -s "${preparation}" ]] || {
  printf 'run scripts/norn/03-prepare-snapshot.sh first\n' >&2
  exit 1
}

registry_address="$(jq -r .registry_address "${preparation}")"
registry_key="$(jq -r .registry_key "${preparation}")"
genesis_hash="$(jq -r .genesis_block_hash "${preparation}")"
schema_hash="$(jq -r .registry_schema_hash "${preparation}")"
tls_dir="${NORN_DEPLOY_DIR}/private/tls"
RI_NORNCTL_TLS_CA_FILE="${tls_dir}/ca.crt" \
RI_NORNCTL_TLS_CLIENT_CERT_FILE="${tls_dir}/client.crt" \
RI_NORNCTL_TLS_CLIENT_KEY_FILE="${tls_dir}/client.key" \
nornctl https://localhost:46555 head >/dev/null
RI_NORNCTL_TLS_CA_FILE="${tls_dir}/ca.crt" \
RI_NORNCTL_TLS_CLIENT_CERT_FILE="${tls_dir}/client.crt" \
RI_NORNCTL_TLS_CLIENT_KEY_FILE="${tls_dir}/client.key" \
nornctl https://localhost:46556 head >/dev/null
if docker run --rm \
  --network host \
  --user "$(id -u):$(id -g)" \
  --env NORN_PUBLISHER_TLS_CA_FILE=/tls/ca.crt \
  --env NORN_PUBLISHER_TLS_CLIENT_CERT_FILE=/tls/client.crt \
  --env NORN_PUBLISHER_TLS_CLIENT_KEY_FILE=/tls/client.key \
  --volume "${tls_dir}:/tls:ro" \
  --volume "${snapshot}:/input/value.json:ro" \
  "${NORN_IMAGE}" \
  /usr/local/bin/norn-local-publisher \
  localhost:46555 "${registry_address#0x}" "${registry_key}" \
  /input/value.json >/dev/null 2>&1; then
  printf 'read-only mTLS proxy unexpectedly allowed the Norn write method\n' >&2
  exit 1
fi

transaction="$(
  norn_publish 127.0.0.1:45555 \
    "${registry_address#0x}" "${registry_key}" "${snapshot}"
)"
transaction_hash="$(jq -r .transaction_hash <<<"${transaction}")"

for _ in $(seq 1 90); do
  nornctl http://127.0.0.1:45555 read \
    "${registry_address}" "${registry_key}" >"${output_dir}/read-a.json"
  nornctl http://127.0.0.1:45556 read \
    "${registry_address}" "${registry_key}" >"${output_dir}/read-b.json"
  if cmp -s "${snapshot}" "${output_dir}/read-a.json" &&
    cmp -s "${snapshot}" "${output_dir}/read-b.json"; then
    break
  fi
  sleep 1
done
cmp "${snapshot}" "${output_dir}/read-a.json"
cmp "${snapshot}" "${output_dir}/read-b.json"

confirmations=3
publication_head="$(nornctl http://127.0.0.1:45555 head | jq -r .head)"
for _ in $(seq 1 60); do
  head_a="$(nornctl http://127.0.0.1:45555 head | jq -r .head)"
  head_b="$(nornctl http://127.0.0.1:45556 head | jq -r .head)"
  if ((head_a >= publication_head + confirmations && head_b >= publication_head + confirmations)); then
    break
  fi
  sleep 1
done

database="${output_dir}/evidence-v2.db"
rm -f "${database}" "${database}-shm" "${database}-wal"
cargo build \
  --quiet \
  --manifest-path "${REPO_ROOT}/rust/Cargo.toml" \
  --package ri-registry-sync
RI_ENVIRONMENT=production \
RI_CHAIN_ADAPTER=norn \
RI_CHAIN_RPC_URLS=https://localhost:46555,https://localhost:46556 \
RI_CHAIN_ID=20001 \
RI_NORN_GENESIS_BLOCK_HASH="${genesis_hash}" \
RI_CHAIN_REGISTRY_ADDRESS="${registry_address}" \
RI_NORN_REGISTRY_KEY="${registry_key}" \
RI_NORN_SIGNER_ISSUER=norn-local-snapshot-authority \
RI_NORN_SIGNER_KEY_ID=snapshot-key-1 \
RI_CHAIN_REGISTRY_SCHEMA_HASH="${schema_hash}" \
RI_CHAIN_CONFIRMATIONS="${confirmations}" \
RI_NORN_REGISTRY_START_HEIGHT=0 \
RI_NORN_MAX_SCAN_BLOCKS=1000 \
RI_NORN_TLS_CA_FILE="${tls_dir}/ca.crt" \
RI_NORN_TLS_CLIENT_CERT_FILE="${tls_dir}/client.crt" \
RI_NORN_TLS_CLIENT_KEY_FILE="${tls_dir}/client.key" \
RI_RPC_MAX_RESPONSE_BYTES=4194304 \
RI_RPC_TIMEOUT_MS=5000 \
RI_REGISTRY_POLL_INTERVAL_MS=1000 \
RI_REGISTRY_SYNC_ONCE=true \
RI_REGISTRY_MONITORING_BIND=127.0.0.1:0 \
RI_DATABASE="${database}" \
RI_IDENTITIES_FILE="${identities}" \
RI_ISSUER_KEYS_FILE="${issuer_keys}" \
"${REPO_ROOT}/rust/target/debug/ri-registry-sync"

[[ "$(sqlite3 "${database}" 'PRAGMA integrity_check;')" == "ok" ]]
identity_count="$(
  sqlite3 "${database}" "SELECT COUNT(*) FROM ri_v2_identities WHERE status = 'ACTIVE';"
)"
[[ "${identity_count}" == "1" ]] || {
  printf 'unexpected active identity count in SQLite: %s\n' "${identity_count}" >&2
  exit 1
}
snapshot_anchor_count="$(
  sqlite3 "${database}" \
    "SELECT COUNT(DISTINCT chain_id || ':' || contract_address || ':' || contract_code_hash || ':' || finalized_block || ':' || finalized_block_hash) FROM ri_v2_registry_snapshot;"
)"
[[ "${snapshot_anchor_count}" == "1" ]] || {
  printf 'SQLite Registry rows do not share one finalized chain anchor\n' >&2
  exit 1
}
read -r finalized_block finalized_hash < <(
  sqlite3 -separator ' ' "${database}" \
    "SELECT finalized_block,finalized_block_hash FROM ri_v2_registry_snapshot ORDER BY snapshot_key LIMIT 1;"
)
image_id="$(docker image inspect "${NORN_IMAGE}" --format '{{.Id}}')"
runtime_image="${RI_RUNTIME_IMAGE:-resolver-identity-rust:multichain-acceptance}"
runtime_image_id="$(docker image inspect "${runtime_image}" --format '{{.Id}}')"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_commit="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
plan_hash="$(jq -r .plan_hash "${preparation}")"
signed_checkpoint_height="$(jq -r .signed_checkpoint.number "${preparation}")"
signed_checkpoint_hash="$(jq -r .signed_checkpoint.hash "${preparation}")"
node_isolation="$(<"${output_dir}/node-isolation.json")"
jq -n \
  --arg generated_at "${generated_at}" \
  --arg git_commit "${git_commit}" \
  --arg transaction_hash "${transaction_hash}" \
  --arg norn_image_digest "${image_id}" \
  --arg runtime_image_digest "${runtime_image_id}" \
  --arg genesis_block_hash "${genesis_hash}" \
  --arg registry_address "${registry_address}" \
  --arg registry_key "${registry_key}" \
  --arg registry_schema_hash "${schema_hash}" \
  --arg plan_hash "${plan_hash}" \
  --arg signed_checkpoint_hash "${signed_checkpoint_hash}" \
  --argjson signed_checkpoint_height "${signed_checkpoint_height}" \
  --arg finalized_hash "${finalized_hash}" \
  --argjson finalized_block "${finalized_block}" \
  --argjson identity_count "${identity_count}" \
  --argjson node_isolation "${node_isolation}" \
  '{
    generated_at: $generated_at,
    git_commit: $git_commit,
    adapter: "norn",
    transaction_hash: $transaction_hash,
    image_digests: {
      go_norn: $norn_image_digest,
      registry_sync: $runtime_image_digest
    },
    genesis_block_hash: $genesis_block_hash,
    registry: {
      address: $registry_address,
      key: $registry_key,
      schema_hash: $registry_schema_hash
    },
    plan_hash: $plan_hash,
    signed_checkpoint: {
      height: $signed_checkpoint_height,
      hash: $signed_checkpoint_hash
    },
    registry_sync: {
      checkpoint_height: $finalized_block,
      checkpoint_hash: $finalized_hash,
      identity_count: $identity_count,
      sqlite_integrity: "ok"
    },
    node_isolation: $node_isolation,
    mtls_read_endpoints: [
      "https://localhost:46555",
      "https://localhost:46556"
    ],
    positive_tests: {
      dual_node_agreement: "passed",
      signed_snapshot: "passed",
      signer_pin: "passed",
      finalized_inclusion: "passed",
      atomic_sqlite_sync: "passed",
      mtls_read: "passed",
      write_proxy_denied: "passed"
    }
  }' >"${output_dir}/acceptance.json"

printf 'Norn publication and Registry Sync completed at finalized block %s (%s)\n' \
  "${finalized_block}" "${finalized_hash}"

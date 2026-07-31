#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command base64
require_command jq
require_command openssl
require_command python3
require_command tail

output_dir="${REPO_ROOT}/deployments/norn-local"
private_dir="${output_dir}/private"
install -d -m 0700 "${private_dir}"

generate_ed25519() {
  local name="$1"
  if [[ ! -s "${private_dir}/${name}.key" ]]; then
    openssl genpkey -algorithm ED25519 -out "${private_dir}/${name}.pem"
    openssl pkey -in "${private_dir}/${name}.pem" -outform DER |
      tail -c 32 |
      base64 -w 0 >"${private_dir}/${name}.key"
    openssl pkey -in "${private_dir}/${name}.pem" -pubout -outform DER |
      tail -c 32 |
      base64 -w 0 >"${private_dir}/${name}.pub"
    chmod 0400 "${private_dir}/${name}.key" "${private_dir}/${name}.pem"
    chmod 0444 "${private_dir}/${name}.pub"
  fi
}

generate_ed25519 identity-issuer
generate_ed25519 snapshot-issuer
generate_ed25519 agent

identity_public="$(<"${private_dir}/identity-issuer.pub")"
snapshot_public="$(<"${private_dir}/snapshot-issuer.pub")"
agent_public="$(<"${private_dir}/agent.pub")"
now="$(date +%s)"
identity_valid_until="$((now + 2592000))"
snapshot_valid_until="$((now + 86400))"

jq -n \
  --arg identity_public "${identity_public}" \
  --arg snapshot_public "${snapshot_public}" \
  '{
    keys: [
      {
        issuer: "norn-local-identity-authority",
        key_id: "identity-key-1",
        algorithm: "ed25519",
        public_key: $identity_public
      },
      {
        issuer: "norn-local-snapshot-authority",
        key_id: "snapshot-key-1",
        algorithm: "ed25519",
        public_key: $snapshot_public
      }
    ]
  }' >"${output_dir}/issuer-keys.json"

jq -n \
  --arg agent_public "${agent_public}" \
  --argjson valid_from "${now}" \
  --argjson valid_until "${identity_valid_until}" \
  '{
    identities: [
      {
        schema_version: "dns-server-identity-v2",
        server_id: "local-norn/L01/r1",
        operator_id: "local-norn",
        role: "RECURSIVE",
        endpoints: [
          {ip: "127.0.0.53", port: 53, transport: "udp"},
          {ip: "127.0.0.53", port: 53, transport: "tcp"}
        ],
        anycast: false,
        agent: {
          key_id: "agent-local-norn-L01-r1",
          algorithm: "ed25519",
          public_key: $agent_public,
          service_url: "https://localhost:8443"
        },
        valid_from: $valid_from,
        valid_until: $valid_until,
        object_version: 1,
        status: "ACTIVE",
        issuer: "norn-local-identity-authority",
        key_id: "identity-key-1"
      }
    ]
  }' >"${output_dir}/identities-v2.unsigned.json"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" sign \
  --input "${output_dir}/identities-v2.unsigned.json" \
  --private-key-file "${private_dir}/identity-issuer.key" \
  --output "${output_dir}/identities-v2.json"
PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" verify-identities \
  --identities "${output_dir}/identities-v2.json" \
  --issuer-keys "${output_dir}/issuer-keys.json"

registry_address="0x1000000000000000000000000000000000000001"
schema_hash="0xadb0b846e01c44c8dcc41b612eea34999b5e10b25b3e68c7dab4a3fd70cc3499"
PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" prepare \
  --identities "${output_dir}/identities-v2.json" \
  --issuer-keys "${output_dir}/issuer-keys.json" \
  --root-version 1 \
  --chain-id 20001 \
  --contract-address "${registry_address}" \
  --contract-code-hash "${schema_hash}" \
  --output "${output_dir}/registry-plan-v2.json"

head_a=0
head_b=0
for _ in $(seq 1 120); do
  head_a="$(nornctl http://127.0.0.1:45555 head | jq -r .head)"
  head_b="$(nornctl http://127.0.0.1:45556 head | jq -r .head)"
  if ((head_a > 0 && head_b > 0)); then
    break
  fi
  sleep 1
done
((head_a > 0 && head_b > 0)) || {
  printf 'Go-Norn nodes did not advance past genesis before snapshot preparation\n' >&2
  exit 1
}
if ((head_a < head_b)); then
  checkpoint_height="${head_a}"
else
  checkpoint_height="${head_b}"
fi
checkpoint_a="$(nornctl http://127.0.0.1:45555 block "${checkpoint_height}")"
checkpoint_b="$(nornctl http://127.0.0.1:45556 block "${checkpoint_height}")"
[[ "${checkpoint_a}" == "${checkpoint_b}" ]] || {
  printf 'Norn nodes disagree at snapshot checkpoint %s\n' "${checkpoint_height}" >&2
  exit 1
}
genesis="$(nornctl http://127.0.0.1:45555 block 0 | jq -r .hash)"
checkpoint_hash="$(jq -r .hash <<<"${checkpoint_a}")"
plan_hash="$(jq -r .plan_hash "${output_dir}/registry-plan-v2.json")"

PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" prepare-norn-snapshot \
  --plan "${output_dir}/registry-plan-v2.json" \
  --expected-plan-hash "${plan_hash}" \
  --chain-id 20001 \
  --genesis-block-hash "${genesis}" \
  --registry-address "${registry_address}" \
  --registry-key resolver-identity-registry-v2 \
  --snapshot-version 1 \
  --checkpoint-height "${checkpoint_height}" \
  --checkpoint-hash "${checkpoint_hash}" \
  --valid-until "${snapshot_valid_until}" \
  --issuer norn-local-snapshot-authority \
  --key-id snapshot-key-1 \
  --private-key-file "${private_dir}/snapshot-issuer.key" \
  --issuer-keys "${output_dir}/issuer-keys.json" \
  --output "${output_dir}/registry-snapshot-v1.json"
PYTHONPATH="${REPO_ROOT}/src" python3 "${REPO_ROOT}/tools/manage_v2_registry.py" verify-norn-snapshot \
  --snapshot "${output_dir}/registry-snapshot-v1.json" \
  --issuer-keys "${output_dir}/issuer-keys.json"

jq -n \
  --arg genesis_block_hash "${genesis}" \
  --arg registry_address "${registry_address}" \
  --arg schema_hash "${schema_hash}" \
  --arg plan_hash "${plan_hash}" \
  --arg checkpoint_hash "${checkpoint_hash}" \
  --argjson checkpoint_height "${checkpoint_height}" \
  '{
    chain_id: 20001,
    genesis_block_hash: $genesis_block_hash,
    registry_address: $registry_address,
    registry_key: "resolver-identity-registry-v2",
    registry_schema_hash: $schema_hash,
    plan_hash: $plan_hash,
    signed_checkpoint: {
      number: $checkpoint_height,
      hash: $checkpoint_hash
    }
  }' >"${output_dir}/preparation.json"

printf 'prepared signed Norn snapshot at %s/registry-snapshot-v1.json\n' "${output_dir}"

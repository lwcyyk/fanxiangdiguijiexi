#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
field_require_commands docker curl sqlite3 jq
docker compose version >/dev/null

field_wait_http \
  "http://${REGISTRY_METRICS_BIND_ADDRESS}:${REGISTRY_METRICS_PORT}/readyz" 10
field_wait_http \
  "http://${TRACE_METRICS_BIND_ADDRESS}:${TRACE_METRICS_PORT}/readyz" 10
field_wait_agent \
  "${RI_FIELD_AGENT_SERVICE_URL%/}/readyz" "${TLS_DIR}" 10

evidence_mount="$(field_volume_mountpoint "${PROJECT}_evidence")"
trace_mount="$(field_volume_mountpoint "${PROJECT}_trace-spool")"
[[ "$(field_sqlite "${evidence_mount}/evidence-v2.db" 'PRAGMA integrity_check;')" == "ok" ]] ||
  field_die "evidence SQLite integrity check failed"
[[ "$(field_sqlite "${trace_mount}/trace-spool.db" 'PRAGMA integrity_check;')" == "ok" ]] ||
  field_die "trace spool SQLite integrity check failed"

snapshot_count="$(
  field_sqlite "${evidence_mount}/evidence-v2.db" \
    'SELECT COUNT(*) FROM ri_v2_registry_snapshot;'
)"
(( snapshot_count == 1 )) || field_die "Registry snapshot is absent or ambiguous"
snapshot_json="$(
  field_sqlite_json "${evidence_mount}/evidence-v2.db" \
    'SELECT chain_id,contract_address,contract_code_hash,finalized_block,
            finalized_block_hash
       FROM ri_v2_registry_snapshot;'
)"
jq -e \
  --argjson chain_id "${RI_WEB3_CHAIN_ID}" \
  --arg contract_address "${RI_REGISTRY_CONTRACT_ADDRESS,,}" \
  --arg contract_code_hash "${RI_REGISTRY_CODE_HASH,,}" \
  '
    length == 1 and
    .[0].chain_id == $chain_id and
    (.[0].contract_address | ascii_downcase) == $contract_address and
    (.[0].contract_code_hash | ascii_downcase) == $contract_code_hash and
    .[0].finalized_block > 0 and
    (.[0].finalized_block_hash | test("^0x[0-9a-fA-F]{64}$"))
  ' <<<"${snapshot_json}" >/dev/null ||
  field_die "Registry snapshot pins do not match the unit configuration"

identity_json="$(
  field_sqlite_json "${evidence_mount}/evidence-v2.db" \
    'SELECT server_id,status,registry_json FROM ri_v2_identities;'
)"
jq -e \
  --arg server_id "${RI_AGENT_SERVER_ID}" \
  '
    [.[] | select(.server_id == $server_id)] as $matches |
    if ($matches | length) == 1 then
      ($matches[0].registry_json | fromjson) as $registry |
      $matches[0].status == "ACTIVE" and
      $registry.resolver_status == "ACTIVE" and
      $registry.root_status == "ACTIVE" and
      $registry.endpoint_binding_status == "MATCHED"
    else
      false
    end
  ' <<<"${identity_json}" >/dev/null ||
  field_die "local identity, Root, or Endpoint Registry state is not active and matched"

endpoint_count="$(
  field_sqlite "${evidence_mount}/evidence-v2.db" \
    'SELECT COUNT(*) FROM ri_v2_endpoint_lookup;'
)"
(( endpoint_count > 0 )) || field_die "Registry endpoint lookup is empty"
dead_letters="$(
  field_sqlite "${trace_mount}/trace-spool.db" \
    'SELECT COUNT(*) FROM trace_dead_letter;'
)"
(( dead_letters == 0 )) || field_die "Trace Adapter has dead-letter events"

if [[ "${RI_FIELD_UNIT_ROLE}" == "entry" ]]; then
  field_require_command dig
  field_wait_http "http://${METRICS_BIND_ADDRESS}:${METRICS_PORT}/readyz" 10
  udp_output="$(
    dig @"${DNS_BIND_ADDRESS}" -p "${DNS_PORT}" "${RI_FIELD_SHADOW_TEST_NAME}" A \
      +time=3 +tries=1
  )"
  tcp_output="$(
    dig @"${DNS_BIND_ADDRESS}" -p "${DNS_PORT}" "${RI_FIELD_SHADOW_TEST_NAME}" A \
      +tcp +time=3 +tries=1
  )"
  grep -q 'status: NOERROR' <<<"${udp_output}" ||
    field_die "UDP Shadow query did not return NOERROR"
  grep -q 'status: NOERROR' <<<"${tcp_output}" ||
    field_die "TCP Shadow query did not return NOERROR"
fi

field_log "${RI_FIELD_UNIT_ID}: baseline acceptance checks passed"

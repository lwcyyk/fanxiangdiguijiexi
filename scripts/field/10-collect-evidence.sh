#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
OUTPUT_ROOT="${2:-}"
[[ -n "${OUTPUT_ROOT}" ]] ||
  field_die "usage: $0 <installed-bundle> <private-evidence-root>"
field_require_commands docker curl sqlite3 jq sha256sum
install -d -m 0700 "${OUTPUT_ROOT}"
timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
output="${OUTPUT_ROOT%/}/${RI_FIELD_UNIT_ID}-${timestamp}"
install -d -m 0700 "${output}"

field_compose ps --format json >"${output}/compose-ps.json"
curl --fail --silent --show-error \
  "http://${REGISTRY_METRICS_BIND_ADDRESS}:${REGISTRY_METRICS_PORT}/metrics" \
  >"${output}/registry-sync.metrics"
curl --fail --silent --show-error \
  "http://${TRACE_METRICS_BIND_ADDRESS}:${TRACE_METRICS_PORT}/metrics" \
  >"${output}/trace-adapter.metrics"
field_agent_request \
  "${RI_FIELD_AGENT_SERVICE_URL%/}/metrics" \
  "${TLS_DIR}" \
  >"${output}/agent.metrics"
if [[ "${RI_FIELD_UNIT_ROLE}" == "entry" ]]; then
  curl --fail --silent --show-error \
    "http://${METRICS_BIND_ADDRESS}:${METRICS_PORT}/metrics" \
    >"${output}/wrapper.metrics"
fi

evidence_db="$(field_volume_mountpoint "${PROJECT}_evidence")/evidence-v2.db"
trace_db="$(field_volume_mountpoint "${PROJECT}_trace-spool")/trace-spool.db"
field_sqlite "${evidence_db}" \
  'SELECT chain_id,contract_address,contract_code_hash,finalized_block,finalized_block_hash,last_success_at FROM ri_v2_registry_snapshot;' \
  >"${output}/registry-snapshot.txt"
field_sqlite "${evidence_db}" \
  'SELECT server_id,status,object_version,valid_until FROM ri_v2_identities ORDER BY server_id;' \
  >"${output}/identities.txt"
field_sqlite "${trace_db}" \
  'SELECT COUNT(*) AS pending FROM trace_spool;
   SELECT COUNT(*) AS dead_letter FROM trace_dead_letter;' \
  >"${output}/trace-spool.txt"
install -m 0600 "${BUNDLE_ROOT}/metadata/unit.json" "${output}/"
(
  cd "${output}"
  sha256sum ./* >SHA256SUMS
)
field_log "evidence collected: ${output}"
printf '%s\n' "${output}"

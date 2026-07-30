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

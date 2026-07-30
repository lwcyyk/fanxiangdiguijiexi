#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
QUERY_FILE="${2:-}"
TARGET_QPS="${3:-}"
DURATION_SECONDS="${4:-}"
[[ -f "${QUERY_FILE}" && "${TARGET_QPS}" =~ ^[1-9][0-9]*$ &&
  "${DURATION_SECONDS}" =~ ^[1-9][0-9]*$ ]] ||
  field_die "usage: $0 <installed-bundle> <dnsperf-query-file> <target-qps> <duration-seconds>"
field_require_command dnsperf

if [[ "${DNS_PORT}" == "53" && "${RI_CAPACITY_ALLOW_PRODUCTION_PORT:-false}" != "true" ]]; then
  field_die "capacity test against port 53 requires RI_CAPACITY_ALLOW_PRODUCTION_PORT=true"
fi
output_dir="${RI_CAPACITY_OUTPUT_DIR:-/var/lib/resolver-identity-capacity/${RI_FIELD_UNIT_ID}}"
field_run_root install -d -m 0700 "${output_dir}"

for transport in udp tcp; do
  output="${output_dir}/${transport}-qps-${TARGET_QPS}-$(date -u +'%Y%m%dT%H%M%SZ').txt"
  field_log "running ${transport} capacity test at ${TARGET_QPS} QPS for ${DURATION_SECONDS}s"
  dnsperf \
    -s "${DNS_BIND_ADDRESS}" \
    -p "${DNS_PORT}" \
    -d "${QUERY_FILE}" \
    -l "${DURATION_SECONDS}" \
    -Q "${TARGET_QPS}" \
    -m "${transport}" |
    tee "${output}"
done

#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
PHASE="${2:-all}"
field_require_commands docker curl install
docker compose version >/dev/null

registry_ready="http://${REGISTRY_METRICS_BIND_ADDRESS}:${REGISTRY_METRICS_PORT}/readyz"
trace_ready="http://${TRACE_METRICS_BIND_ADDRESS}:${TRACE_METRICS_PORT}/readyz"
wrapper_ready="http://${METRICS_BIND_ADDRESS}:${METRICS_PORT}/readyz"
agent_ready="${RI_FIELD_AGENT_SERVICE_URL%/}/readyz"

start_registry() {
  field_log "${RI_FIELD_UNIT_ID}: starting Registry Sync"
  field_compose up -d --no-build registry-sync
  field_wait_http "${registry_ready}" "${RI_FIELD_READY_TIMEOUT_SECONDS:-180}"
}

start_control() {
  field_wait_http "${registry_ready}" 10
  field_run_root install -d -o 10002 -g "${RI_TRACE_PRODUCER_GID}" -m 2770 \
    "${RI_TRACE_SOCKET_HOST_DIR}"
  field_log "${RI_FIELD_UNIT_ID}: starting Agent and Trace Adapter"
  field_compose up -d --no-build agent trace-adapter
  field_wait_http "${trace_ready}" "${RI_FIELD_READY_TIMEOUT_SECONDS:-180}"
  field_wait_agent "${agent_ready}" "${TLS_DIR}" "${RI_FIELD_READY_TIMEOUT_SECONDS:-180}"
  [[ -S "${RI_TRACE_SOCKET_HOST_DIR}/events.sock" ]] ||
    field_die "Resolver Trace Socket was not created"
}

start_wrapper() {
  [[ "${RI_FIELD_UNIT_ROLE}" == "entry" ]] ||
    field_die "Wrapper must not be started for an upstream-only unit"
  field_wait_http "${registry_ready}" 10
  field_wait_http "${trace_ready}" 10
  field_wait_agent "${agent_ready}" "${TLS_DIR}" 10
  [[ -S "${RI_TRACE_SOCKET_HOST_DIR}/events.sock" ]] ||
    field_die "Resolver Trace Socket is absent"
  field_log "${RI_FIELD_UNIT_ID}: starting Wrapper"
  field_compose up -d --no-build wrapper
  field_wait_http "${wrapper_ready}" "${RI_FIELD_READY_TIMEOUT_SECONDS:-180}"
}

case "${PHASE}" in
  registry-sync) start_registry ;;
  control) start_control ;;
  wrapper) start_wrapper ;;
  all)
    start_registry
    start_control
    if [[ "${RI_FIELD_UNIT_ROLE}" == "entry" ]]; then
      start_wrapper
    fi
    ;;
  *) field_die "phase must be registry-sync, control, wrapper, or all" ;;
esac

field_compose ps

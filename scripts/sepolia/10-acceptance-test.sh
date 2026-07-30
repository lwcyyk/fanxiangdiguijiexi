#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands docker curl jq sqlite3
load_sepolia_env
assert_sepolia_network
REGISTRY_ADDRESS="$(contract_address)"
REGISTRY_CODE_HASH="$(verified_code_hash)"
assert_live_contract "${REGISTRY_ADDRESS}" "${REGISTRY_CODE_HASH}"

COMPOSE=(
  docker compose
  --project-name ri-sepolia-preprod
  --env-file "${REPO_ROOT}/deploy/link/.env"
  -f "${REPO_ROOT}/deploy/link/docker-compose.yml"
)
curl --fail --silent --show-error http://127.0.0.1:9109/readyz >/dev/null ||
  die "Registry Sync must be ready before acceptance"

CONTAINER_ID="$("${COMPOSE[@]}" ps -q registry-sync)"
[[ -n "${CONTAINER_ID}" ]] || die "Registry Sync container is absent"
"${COMPOSE[@]}" stop registry-sync >/dev/null
if curl --fail --silent --max-time 2 http://127.0.0.1:9109/readyz >/dev/null 2>&1; then
  die "Registry Sync readiness unexpectedly survived a stopped service"
fi

SQLITE_COPY="${SEPOLIA_DEPLOYMENTS}/private/evidence-v2.db"
rm -f "${SQLITE_COPY}"
docker cp "${CONTAINER_ID}:/var/lib/resolver-identity/evidence-v2.db" "${SQLITE_COPY}"
INTEGRITY="$(sqlite3 "${SQLITE_COPY}" 'PRAGMA integrity_check;')"
[[ "${INTEGRITY}" == "ok" ]] || die "SQLite integrity_check failed"
IDENTITIES_JSON="$(sqlite3 -json "${SQLITE_COPY}" \
  'SELECT server_id,status,object_version,valid_until FROM ri_v2_identities ORDER BY server_id;')"
SNAPSHOT_JSON="$(sqlite3 -json "${SQLITE_COPY}" \
  'SELECT DISTINCT chain_id,contract_address,contract_code_hash,finalized_block,finalized_block_hash FROM ri_v2_registry_snapshot;')"
ENDPOINTS_JSON="$(sqlite3 -json "${SQLITE_COPY}" \
  'SELECT endpoint_key,server_id FROM ri_v2_endpoint_lookup ORDER BY endpoint_key;')"
[[ "$(jq 'length' <<<"${IDENTITIES_JSON}")" == "$(jq '.identities | length' deploy/link/identities-v2.json)" ]] ||
  die "SQLite identity count differs from the signed artifact"
[[ "$(jq 'length' <<<"${SNAPSHOT_JSON}")" == "1" ]] ||
  die "SQLite does not contain exactly one distinct Registry checkpoint"
[[ "$(jq -r '.[0].chain_id' <<<"${SNAPSHOT_JSON}")" == "${CHAIN_ID}" ]] ||
  die "SQLite Chain ID differs"
[[ "$(jq -r '.[0].contract_address' <<<"${SNAPSHOT_JSON}")" == "${REGISTRY_ADDRESS,,}" ]] ||
  die "SQLite Registry address differs"
[[ "$(jq -r '.[0].contract_code_hash' <<<"${SNAPSHOT_JSON}")" == "${REGISTRY_CODE_HASH,,}" ]] ||
  die "SQLite runtime code hash differs"

jq -n \
  --arg checked_at "$(utc_now)" \
  --arg integrity_check "${INTEGRITY}" \
  --argjson identities "${IDENTITIES_JSON}" \
  --argjson endpoints "${ENDPOINTS_JSON}" \
  --argjson registry_snapshot "${SNAPSHOT_JSON}" \
  '{
    checked_at:$checked_at,integrity_check:$integrity_check,
    identities:$identities,endpoints:$endpoints,registry_snapshot:$registry_snapshot
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/sqlite-verification.json"

"${COMPOSE[@]}" start registry-sync >/dev/null
READY_DEADLINE="$(( $(date +%s) + 180 ))"
until curl --fail --silent http://127.0.0.1:9109/readyz >/dev/null; do
  (( $(date +%s) < READY_DEADLINE )) || die "Registry Sync did not recover after restart"
  sleep 2
done
RESTART_METRICS="$(curl --fail --silent http://127.0.0.1:9109/metrics)"
RESTART_BLOCK="$(awk '/^resolver_identity_registry_finalized_block / {print $2}' <<<"${RESTART_METRICS}")"
STORED_BLOCK="$(jq -r '.[0].finalized_block' <<<"${SNAPSHOT_JSON}")"
(( RESTART_BLOCK >= STORED_BLOCK )) || die "Registry Sync restarted below its stored high-water mark"

mkdir -p "${SEPOLIA_DEPLOYMENTS}/private/negative"
NEGATIVE_RESULTS='{}'
expect_sync_failure() {
  local name="$1"
  shift
  local log_file="${SEPOLIA_DEPLOYMENTS}/private/negative/${name}.log"
  if "${COMPOSE[@]}" run --rm --no-deps \
    -e RI_REGISTRY_SYNC_ONCE=true "$@" registry-sync >"${log_file}" 2>&1; then
    die "negative Registry Sync test unexpectedly passed: ${name}"
  fi
  NEGATIVE_RESULTS="$(jq -c --arg name "${name}" '. + {($name):"PASS"}' <<<"${NEGATIVE_RESULTS}")"
}

expect_sync_failure wrong_chain -e RI_WEB3_CHAIN_ID=1
expect_sync_failure wrong_contract \
  -e RI_REGISTRY_CONTRACT_ADDRESS=0x1111111111111111111111111111111111111111
expect_sync_failure wrong_runtime_code_hash \
  -e RI_REGISTRY_CODE_HASH=0x2222222222222222222222222222222222222222222222222222222222222222

TAMPERED_ISSUERS="${SEPOLIA_DEPLOYMENTS}/private/negative/issuer-keys.json"
jq '.keys[0].public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="' \
  deploy/issuer-keys.json >"${TAMPERED_ISSUERS}"
expect_sync_failure wrong_issuer_key \
  -v "${TAMPERED_ISSUERS}:/run/config/issuer-keys.json:ro"

TAMPERED_IDENTITIES="${SEPOLIA_DEPLOYMENTS}/private/negative/identities-v2.json"
jq '.identities[0].operator_id += "-tampered"' \
  deploy/link/identities-v2.json >"${TAMPERED_IDENTITIES}"
expect_sync_failure tampered_identity \
  -v "${TAMPERED_IDENTITIES}:/run/config/identities-v2.json:ro"

DATA_PLANE_STATUS="BLOCKED"
UDP_STATUS="NOT_RUN"
TCP_STATUS="NOT_RUN"
KNOWN_GAP="real Resolver Trace plugin and full data-plane execution were not enabled"
if [[ "${RI_RUN_FULL_DATA_PLANE:-false}" == "true" ]]; then
  require_commands dig openssl
  restore_data_plane_services() {
    "${COMPOSE[@]}" start registry-sync agent trace-adapter >/dev/null 2>&1 || true
  }
  trap restore_data_plane_services EXIT
  for path in \
    deploy/link/tls/agent.crt deploy/link/tls/agent.key deploy/link/tls/client-ca.crt \
    deploy/link/tls/agent-client.crt deploy/link/tls/agent-client.key deploy/link/tls/agent-ca.crt \
    deploy/link/tls/trace-client.crt deploy/link/tls/trace-client.key \
    deploy/link/tls/wrapper-client.crt deploy/link/tls/wrapper-client.key \
    deploy/link/secrets/agent_private_key deploy/link/secrets/trace_ingest_token \
    deploy/link/secrets/agent_wrapper_token deploy/link/secrets/agent_peer_token; do
    [[ -f "${path}" ]] || die "full data-plane file is absent: ${path}"
  done
  [[ -S "${RI_TRACE_SOCKET_HOST_DIR}/events.sock" || -d "${RI_TRACE_SOCKET_HOST_DIR}" ]] ||
    die "real Resolver Trace socket directory is absent"
  "${COMPOSE[@]}" up -d --no-build agent trace-adapter
  sleep 3
  curl --fail --silent http://127.0.0.1:9110/readyz >/dev/null ||
    die "Trace Adapter is not ready"
  curl --fail --silent --show-error \
    --cacert deploy/link/tls/agent-ca.crt \
    --cert deploy/link/tls/agent-client.crt \
    --key deploy/link/tls/agent-client.key \
    --resolve agent:8443:127.0.0.1 \
    https://agent:8443/readyz >/dev/null ||
    die "Agent mTLS readiness failed"
  "${COMPOSE[@]}" up -d --no-build wrapper
  READY_DEADLINE="$(( $(date +%s) + 120 ))"
  until curl --fail --silent http://127.0.0.1:9108/readyz >/dev/null; do
    (( $(date +%s) < READY_DEADLINE )) || die "Wrapper did not become ready"
    sleep 2
  done
  require_var RI_ACCEPTANCE_DNS_NAME
  dig @"${DNS_BIND_ADDRESS}" -p "${DNS_PORT:-53}" "${RI_ACCEPTANCE_DNS_NAME}" \
    "${RI_ACCEPTANCE_DNS_TYPE:-A}" +time=3 +tries=1 |
    grep -q 'status: NOERROR' || die "UDP DNS acceptance query failed"
  dig @"${DNS_BIND_ADDRESS}" -p "${DNS_PORT:-53}" "${RI_ACCEPTANCE_DNS_NAME}" \
    "${RI_ACCEPTANCE_DNS_TYPE:-A}" +tcp +time=3 +tries=1 |
    grep -q 'status: NOERROR' || die "TCP DNS acceptance query failed"

  WRONG_TLS_DIR="${SEPOLIA_DEPLOYMENTS}/private/negative/wrong-mtls"
  mkdir -p "${WRONG_TLS_DIR}"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=untrusted-acceptance-client' \
    -keyout "${WRONG_TLS_DIR}/client.key" \
    -out "${WRONG_TLS_DIR}/client.crt" \
    >"${WRONG_TLS_DIR}/openssl.log" 2>&1
  chmod 600 "${WRONG_TLS_DIR}/client.key"
  if curl --fail --silent --show-error \
    --cacert deploy/link/tls/agent-ca.crt \
    --cert "${WRONG_TLS_DIR}/client.crt" \
    --key "${WRONG_TLS_DIR}/client.key" \
    --resolve agent:8443:127.0.0.1 \
    https://agent:8443/readyz >/dev/null 2>&1; then
    die "Agent accepted an untrusted mTLS client certificate"
  fi
  NEGATIVE_RESULTS="$(jq -c '. + {wrong_mtls_certificate:"PASS"}' <<<"${NEGATIVE_RESULTS}")"

  AGENT_REQUEST='{
    "trace_id":"negative-token-test",
    "correlation_id":"0x0000000000000000000000000000000000000000000000000000000000000001",
    "challenge":"00000000000000000000000000000000",
    "query_digest":"0x0000000000000000000000000000000000000000000000000000000000000002",
    "response_digest":"0x0000000000000000000000000000000000000000000000000000000000000003",
    "visited_server_ids":[]
  }'
  agent_status() {
    local endpoint="$1"
    local body="$2"
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --cacert deploy/link/tls/agent-ca.crt \
      --cert deploy/link/tls/agent-client.crt \
      --key deploy/link/tls/agent-client.key \
      --resolve agent:8443:127.0.0.1 \
      -H 'authorization: Bearer deliberately-wrong-acceptance-token' \
      -H 'content-type: application/json' \
      --data "${body}" "https://agent:8443${endpoint}"
  }
  [[ "$(agent_status /v2/evidence-graph "${AGENT_REQUEST}")" == "401" ]] ||
    die "Agent did not reject an invalid Wrapper token"
  [[ "$(agent_status /v2/downstream-evidence-graph "${AGENT_REQUEST}")" == "401" ]] ||
    die "Agent did not reject an invalid peer token"
  [[ "$(agent_status /v2/trace-events/batch '[]')" == "401" ]] ||
    die "Agent did not reject an invalid Trace token"
  NEGATIVE_RESULTS="$(jq -c \
    '. + {wrong_wrapper_token:"PASS",wrong_peer_token:"PASS",wrong_trace_token:"PASS"}' \
    <<<"${NEGATIVE_RESULTS}")"

  dns_expect_servfail() {
    local transport_args=()
    [[ "${1:-udp}" == "tcp" ]] && transport_args+=(+tcp)
    dig @"${DNS_BIND_ADDRESS}" -p "${DNS_PORT:-53}" "${RI_ACCEPTANCE_DNS_NAME}" \
      "${RI_ACCEPTANCE_DNS_TYPE:-A}" "${transport_args[@]}" +time=3 +tries=1 |
      grep -q 'status: SERVFAIL'
  }
  wait_wrapper_not_ready() {
    local deadline="$(( $(date +%s) + 30 ))"
    while curl --fail --silent http://127.0.0.1:9108/readyz >/dev/null 2>&1; do
      (( $(date +%s) < deadline )) || return 1
      sleep 2
    done
  }
  wait_agent_ready() {
    local deadline="$(( $(date +%s) + 90 ))"
    until curl --fail --silent \
      --cacert deploy/link/tls/agent-ca.crt \
      --cert deploy/link/tls/agent-client.crt \
      --key deploy/link/tls/agent-client.key \
      --resolve agent:8443:127.0.0.1 \
      https://agent:8443/readyz >/dev/null; do
      (( $(date +%s) < deadline )) || return 1
      sleep 2
    done
  }
  wait_wrapper_ready() {
    local deadline="$(( $(date +%s) + 90 ))"
    until curl --fail --silent http://127.0.0.1:9108/readyz >/dev/null; do
      (( $(date +%s) < deadline )) || return 1
      sleep 2
    done
  }

  "${COMPOSE[@]}" stop agent >/dev/null
  wait_wrapper_not_ready || die "Wrapper remained ready after Agent stopped"
  dns_expect_servfail udp || die "UDP DNS did not fail closed after Agent stopped"
  dns_expect_servfail tcp || die "TCP DNS did not fail closed after Agent stopped"
  "${COMPOSE[@]}" start agent >/dev/null
  wait_agent_ready || die "Agent did not recover after restart"
  wait_wrapper_ready || die "Wrapper did not recover after Agent restart"
  NEGATIVE_RESULTS="$(jq -c '. + {agent_stopped:"PASS"}' <<<"${NEGATIVE_RESULTS}")"

  "${COMPOSE[@]}" stop trace-adapter >/dev/null
  dns_expect_servfail udp || die "DNS did not fail closed without a Trace Adapter"
  "${COMPOSE[@]}" start trace-adapter >/dev/null
  READY_DEADLINE="$(( $(date +%s) + 90 ))"
  until curl --fail --silent http://127.0.0.1:9110/readyz >/dev/null; do
    (( $(date +%s) < READY_DEADLINE )) || die "Trace Adapter did not recover"
    sleep 2
  done
  NEGATIVE_RESULTS="$(jq -c '. + {trace_missing:"PASS"}' <<<"${NEGATIVE_RESULTS}")"

  "${COMPOSE[@]}" stop registry-sync >/dev/null
  sleep "$(( ${RI_REGISTRY_MAX_STALENESS_SECONDS:-15} + 3 ))"
  if curl --fail --silent \
    --cacert deploy/link/tls/agent-ca.crt \
    --cert deploy/link/tls/agent-client.crt \
    --key deploy/link/tls/agent-client.key \
    --resolve agent:8443:127.0.0.1 \
    https://agent:8443/readyz >/dev/null 2>&1; then
    die "Agent remained ready with a stale Registry snapshot"
  fi
  wait_wrapper_not_ready || die "Wrapper remained ready with a stale Registry snapshot"
  dns_expect_servfail udp || die "DNS did not fail closed with stale Registry state"
  "${COMPOSE[@]}" start registry-sync >/dev/null
  READY_DEADLINE="$(( $(date +%s) + 180 ))"
  until curl --fail --silent http://127.0.0.1:9109/readyz >/dev/null; do
    (( $(date +%s) < READY_DEADLINE )) || die "Registry Sync did not recover"
    sleep 2
  done
  wait_agent_ready || die "Agent did not recover after Registry Sync restart"
  wait_wrapper_ready || die "Wrapper did not recover after Registry Sync restart"
  NEGATIVE_RESULTS="$(jq -c \
    '. + {registry_sync_stopped:"PASS",registry_snapshot_stale:"PASS"}' \
    <<<"${NEGATIVE_RESULTS}")"

  DATA_PLANE_STATUS="PASS"
  UDP_STATUS="PASS"
  TCP_STATUS="PASS"
  KNOWN_GAP=""
  trap - EXIT
fi

jq -n \
  --arg completed_at "$(utc_now)" \
  --arg registry_sync "PASS" \
  --arg sqlite_integrity "PASS" \
  --arg restart_recovery "PASS" \
  --arg stopped_sync_fail_closed "PASS" \
  --argjson negative_tests "${NEGATIVE_RESULTS}" \
  --arg data_plane "${DATA_PLANE_STATUS}" \
  --arg udp_dns "${UDP_STATUS}" \
  --arg tcp_dns "${TCP_STATUS}" \
  --arg known_gap "${KNOWN_GAP}" \
  '{
    completed_at:$completed_at,registry_sync:$registry_sync,
    sqlite_integrity:$sqlite_integrity,restart_recovery:$restart_recovery,
    stopped_sync_fail_closed:$stopped_sync_fail_closed,
    negative_tests:$negative_tests,data_plane:$data_plane,
    udp_dns:$udp_dns,tcp_dns:$tcp_dns,
    known_gaps:(if $known_gap == "" then [] else [$known_gap] end)
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/acceptance-results.json"

for evidence in \
  deployment.json verification.json roles.json registry-plan-v2.json \
  publication-transactions.json registry-sync.json test-results.json \
  acceptance-results.json; do
  [[ -f "${SEPOLIA_DEPLOYMENTS}/${evidence}" ]] ||
    die "final manifest evidence is absent: ${evidence}"
done
[[ "$(jq -c '.completed_phases | sort' \
  "${SEPOLIA_DEPLOYMENTS}/publication-transactions.json")" ==
  '["bind-endpoints","publish-resolvers","publish-root","revoke-removed","unbind-endpoints"]' ]] ||
  die "final manifest publication evidence is incomplete"

jq -n \
  --slurpfile deployment "${SEPOLIA_DEPLOYMENTS}/deployment.json" \
  --slurpfile verification "${SEPOLIA_DEPLOYMENTS}/verification.json" \
  --slurpfile roles "${SEPOLIA_DEPLOYMENTS}/roles.json" \
  --slurpfile plan "${SEPOLIA_DEPLOYMENTS}/registry-plan-v2.json" \
  --slurpfile sync "${SEPOLIA_DEPLOYMENTS}/registry-sync.json" \
  --slurpfile tests "${SEPOLIA_DEPLOYMENTS}/test-results.json" \
  --slurpfile acceptance "${SEPOLIA_DEPLOYMENTS}/acceptance-results.json" \
  '{
    environment:"sepolia-preproduction",
    git_commit:$deployment[0].git_commit,
    network_name:$deployment[0].network_name,
    chain_id:$deployment[0].chain_id,
    primary_rpc_host:$verification[0].primary_rpc_host,
    verification_rpc_host:$verification[0].verification_rpc_host,
    contract_address:$deployment[0].contract_address,
    runtime_code_hash:$verification[0].runtime_code_hash,
    deployment_transaction_hash:$deployment[0].deployment_transaction_hash,
    deployment_block:$deployment[0].deployment_block,
    deployment_block_hash:$deployment[0].deployment_block_hash,
    governance_address:$roles[0].governance_address,
    root_publisher_address:$roles[0].root_publisher_address,
    resolver_publisher_address:$roles[0].resolver_publisher_address,
    endpoint_manager_address:$roles[0].endpoint_manager_address,
    revoker_address:$roles[0].revoker_address,
    state_root:$plan[0].state_root,
    root_version:$plan[0].root_version,
    plan_hash:$plan[0].plan_hash,
    identity_count:($plan[0].entries | length),
    endpoint_count:([$plan[0].entries[].endpoint_keys[]] | length),
    registry_sync_finalized_block:$sync[0].finalized_block,
    image_digest:$sync[0].image_digest,
    deployed_at:$deployment[0].deployment_time,
    test_results:{
      predeployment:$tests[0],
      acceptance:$acceptance[0]
    },
    known_gaps:$acceptance[0].known_gaps
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/deployment-manifest.json"

log "Registry/SQLite acceptance passed; data-plane status=${DATA_PLANE_STATUS}"

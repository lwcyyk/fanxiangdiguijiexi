#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ROOT="${1:-}"
[[ -n "${ROOT}" && -d "${ROOT}" ]] ||
  field_die "usage: $0 <rendered-site-release-directory>"
field_require_commands python3 docker openssl sha256sum
docker compose version >/dev/null

verify_key_pair() {
  local cert="$1"
  local key="$2"
  local cert_digest key_digest
  cert_digest="$(
    openssl x509 -in "${cert}" -pubkey -noout |
      openssl pkey -pubin -outform DER 2>/dev/null |
      sha256sum | awk '{print $1}'
  )"
  key_digest="$(
    openssl pkey -in "${key}" -pubout -outform DER 2>/dev/null |
      sha256sum | awk '{print $1}'
  )"
  [[ -n "${cert_digest}" && "${cert_digest}" == "${key_digest}" ]] ||
    field_die "TLS certificate and private key do not match: ${cert}"
}

count=0
while IFS= read -r -d '' bundle; do
  ((count += 1))
  python3 "${FIELD_REPO_ROOT}/tools/manage_field_deployment.py" \
    verify-bundle --bundle "${bundle}"
  for cert in agent.crt wrapper-client.crt trace-client.crt agent-client.crt \
    client-ca.crt agent-ca.crt; do
    openssl x509 -checkend "${RI_FIELD_TLS_MIN_VALIDITY_SECONDS:-604800}" \
      -noout -in "${bundle}/deploy/link/tls/${cert}" >/dev/null ||
      field_die "TLS certificate expires too soon: ${bundle}/${cert}"
  done
  verify_key_pair \
    "${bundle}/deploy/link/tls/agent.crt" \
    "${bundle}/deploy/link/tls/agent.key"
  verify_key_pair \
    "${bundle}/deploy/link/tls/wrapper-client.crt" \
    "${bundle}/deploy/link/tls/wrapper-client.key"
  verify_key_pair \
    "${bundle}/deploy/link/tls/trace-client.crt" \
    "${bundle}/deploy/link/tls/trace-client.key"
  verify_key_pair \
    "${bundle}/deploy/link/tls/agent-client.crt" \
    "${bundle}/deploy/link/tls/agent-client.key"
  (
    cd "${bundle}"
    set -a
    # shellcheck disable=SC1091
    source deploy/link/.env
    set +a
    openssl verify -CAfile deploy/link/tls/agent-ca.crt \
      deploy/link/tls/agent.crt >/dev/null ||
      field_die "Agent certificate does not chain to agent-ca.crt"
    for client_certificate in \
      wrapper-client.crt trace-client.crt agent-client.crt; do
      openssl verify -CAfile deploy/link/tls/client-ca.crt \
        "deploy/link/tls/${client_certificate}" >/dev/null ||
        field_die "${client_certificate} does not chain to client-ca.crt"
    done
    if [[ "${RI_FIELD_AGENT_TLS_SERVER_NAME}" == *:* ||
      "${RI_FIELD_AGENT_TLS_SERVER_NAME}" =~ ^[0-9.]+$ ]]; then
      openssl x509 -checkip "${RI_FIELD_AGENT_TLS_SERVER_NAME}" \
        -noout -in deploy/link/tls/agent.crt >/dev/null ||
        field_die "Agent certificate SAN does not contain the service IP"
    else
      openssl x509 -checkhost "${RI_FIELD_AGENT_TLS_SERVER_NAME}" \
        -noout -in deploy/link/tls/agent.crt >/dev/null ||
        field_die "Agent certificate SAN does not contain the service host"
    fi
    docker compose \
      --project-name "${RI_FIELD_COMPOSE_PROJECT}" \
      --env-file deploy/link/.env \
      -f deploy/link/docker-compose.yml \
      config --quiet
  )
done < <(find "${ROOT}" -type f -name .ri-field-bundle -print0 | xargs -0 -r -n1 dirname -z)

(( count > 0 )) || field_die "no rendered bundles found below ${ROOT}"
field_log "verified ${count} isolated link bundle(s)"

#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
# shellcheck disable=SC1091
source "${ROOT}/config/.env"
set +a

tls_dir="${RI_NORNCTL_TLS_DIR:?RI_NORNCTL_TLS_DIR is required}"
for file in ca.crt client.crt client.key; do
  [[ -f "${tls_dir}/${file}" ]] || {
    printf 'Norn read client material is missing: %s\n' "${tls_dir}/${file}" >&2
    exit 1
  }
done

exec docker run --rm \
  --network "${RI_FIELD_NETWORK:?RI_FIELD_NETWORK is required}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  --env RI_NORNCTL_TLS_CA_FILE=/tls/ca.crt \
  --env RI_NORNCTL_TLS_CLIENT_CERT_FILE=/tls/client.crt \
  --env RI_NORNCTL_TLS_CLIENT_KEY_FILE=/tls/client.key \
  --volume "${tls_dir}:/tls:ro" \
  --entrypoint /usr/local/bin/ri-nornctl \
  "${RI_MANAGEMENT_IMAGE}" "$@"

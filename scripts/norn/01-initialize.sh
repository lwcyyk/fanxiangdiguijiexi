#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command docker
require_command openssl

for node in node-a node-b; do
  node_dir="${NORN_DEPLOY_DIR}/private/${node}"
  install -d -m 0700 "${node_dir}"
  install -d -m 0700 "${node_dir}/data"
  if [[ ! -s "${node_dir}/config.yml" ]]; then
    docker run --rm \
      --user "$(id -u):$(id -g)" \
      --volume "${node_dir}:/config" \
      --workdir /config \
      "${NORN_IMAGE}" \
      /usr/local/bin/norn-generate
  fi
  chmod 0600 "${node_dir}/config.yml"
done

tls_dir="${NORN_DEPLOY_DIR}/private/tls"
install -d -m 0700 "${tls_dir}"
if [[ ! -s "${tls_dir}/ca.key" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${tls_dir}/ca.key"
  openssl req -x509 -new -sha256 -days 30 \
    -key "${tls_dir}/ca.key" \
    -subj "/CN=ri-norn-local-ca" \
    -out "${tls_dir}/ca.crt"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${tls_dir}/server.key"
  openssl req -new -sha256 \
    -key "${tls_dir}/server.key" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:norn-read-a,DNS:norn-read-b" \
    -out "${tls_dir}/server.csr"
  openssl x509 -req -sha256 -days 30 \
    -in "${tls_dir}/server.csr" \
    -CA "${tls_dir}/ca.crt" \
    -CAkey "${tls_dir}/ca.key" \
    -CAcreateserial \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:norn-read-a,DNS:norn-read-b\nextendedKeyUsage=serverAuth\n') \
    -out "${tls_dir}/server.crt"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${tls_dir}/client.key"
  openssl req -new -sha256 \
    -key "${tls_dir}/client.key" \
    -subj "/CN=ri-registry-sync-local" \
    -out "${tls_dir}/client.csr"
  openssl x509 -req -sha256 -days 30 \
    -in "${tls_dir}/client.csr" \
    -CA "${tls_dir}/ca.crt" \
    -CAkey "${tls_dir}/ca.key" \
    -CAcreateserial \
    -extfile <(printf 'extendedKeyUsage=clientAuth\n') \
    -out "${tls_dir}/client.crt"
fi
chmod 0400 "${tls_dir}"/*.key
chmod 0444 "${tls_dir}"/*.crt

printf 'NORN_IMAGE=%s\nNORN_UID=%s\nNORN_GID=%s\nNORN_BOOTSTRAP=%s\n' \
  "${NORN_IMAGE}" "$(id -u)" "$(id -g)" \
  "/dns4/norn-a/tcp/31258/p2p/not-started" \
  >"${NORN_ENV_FILE}"
chmod 0600 "${NORN_ENV_FILE}"
printf 'generated isolated node and mTLS material under %s/private\n' "${NORN_DEPLOY_DIR}"

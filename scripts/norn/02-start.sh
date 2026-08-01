#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command cargo
require_command docker
require_command jq
require_command sed
require_command sha256sum

[[ -s "${NORN_DEPLOY_DIR}/private/node-a/config.yml" ]] || {
  printf 'run scripts/norn/01-initialize.sh first\n' >&2
  exit 1
}

norn_compose up -d norn-a
for _ in $(seq 1 60); do
  if nornctl http://127.0.0.1:45555 head >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
nornctl http://127.0.0.1:45555 block 0 >/dev/null

peer_id="$(
  norn_compose logs --no-color norn-a |
    sed -n 's#.*Node address: .*\/p2p/\([^"]*\)".*#\1#p' |
    tail -n 1
)"
[[ -n "${peer_id}" ]] || {
  printf 'could not determine norn-a peer ID\n' >&2
  exit 1
}
bootstrap="/dns4/norn-a/tcp/31258/p2p/${peer_id}"
printf 'NORN_IMAGE=%s\nNORN_UID=%s\nNORN_GID=%s\nNORN_BOOTSTRAP=%s\n' \
  "${NORN_IMAGE}" "$(id -u)" "$(id -g)" "${bootstrap}" >"${NORN_ENV_FILE}"
chmod 0600 "${NORN_ENV_FILE}"

norn_compose up -d norn-b norn-read-a norn-read-b
for _ in $(seq 1 90); do
  if nornctl http://127.0.0.1:45556 block 0 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

peer_id_b="$(
  norn_compose logs --no-color norn-b |
    sed -n 's#.*Node address: .*\/p2p/\([^"]*\)".*#\1#p' |
    tail -n 1
)"
[[ -n "${peer_id_b}" && "${peer_id_b}" != "${peer_id}" ]] || {
  printf 'Go-Norn nodes must use distinct node keys and peer IDs\n' >&2
  exit 1
}
node_a_data="$(realpath "${NORN_DEPLOY_DIR}/private/node-a/data")"
node_b_data="$(realpath "${NORN_DEPLOY_DIR}/private/node-b/data")"
[[ "${node_a_data}" != "${node_b_data}" ]] || {
  printf 'Go-Norn nodes must use independent data directories\n' >&2
  exit 1
}
install -d -m 0700 "${REPO_ROOT}/deployments/norn-local"
peer_a_hash="$(printf '%s' "${peer_id}" | sha256sum | cut -d' ' -f1)"
peer_b_hash="$(printf '%s' "${peer_id_b}" | sha256sum | cut -d' ' -f1)"
jq -n \
  --arg peer_a_hash "${peer_a_hash}" \
  --arg peer_b_hash "${peer_b_hash}" \
  '{
    independent_data_directories: true,
    distinct_node_keys: true,
    peer_id_sha256: [$peer_a_hash, $peer_b_hash]
  }' >"${REPO_ROOT}/deployments/norn-local/node-isolation.json"

block_a="$(nornctl http://127.0.0.1:45555 block 0)"
block_b="$(nornctl http://127.0.0.1:45556 block 0)"
[[ "${block_a}" == "${block_b}" ]] || {
  printf 'Go-Norn nodes disagree on genesis: %s != %s\n' "${block_a}" "${block_b}" >&2
  exit 1
}
norn_compose ps
printf 'Go-Norn dual-node network is running with genesis %s\n' "${block_a}"

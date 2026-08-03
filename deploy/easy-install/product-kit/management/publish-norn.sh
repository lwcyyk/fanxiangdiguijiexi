#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
# shellcheck disable=SC1091
source "${ROOT}/config/.env"
set +a

SNAPSHOT="${1:?usage: publish-norn.sh SNAPSHOT REGISTRY_ADDRESS REGISTRY_KEY}"
REGISTRY_ADDRESS="${2:?registry address is required}"
REGISTRY_KEY="${3:?registry key is required}"
[[ -f "${SNAPSHOT}" ]] || {
  printf 'snapshot is missing: %s\n' "${SNAPSHOT}" >&2
  exit 1
}

if [[ "${RI_FIELD_SIMULATION:-false}" == "true" ]]; then
  target="${RI_NORN_SIMULATION_PUBLISH_TARGET:?fixed simulation target is required}"
  [[ "${target}" != localhost:* && "${target}" != 127.0.0.1:* ]] || {
    printf 'simulation publication must use a cross-server hostname\n' >&2
    exit 1
  }
  network_args=(--network "${RI_FIELD_NETWORK:?}")
else
  target="${RI_NORN_PUBLISH_TARGET:?fixed publication target is required}"
  [[ "${RI_NORN_PUBLISH_MODE:?}" == "ssh-tunnel" ]] || {
    printf 'field publication requires the ssh-tunnel transport\n' >&2
    exit 1
  }
  [[ "${target}" == 127.0.0.1:* ]] || {
    printf 'field publication target must be the local end of an authenticated SSH tunnel\n' >&2
    exit 1
  }
  network_args=(--network host)
fi

exec docker run --rm \
  "${network_args[@]}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 10003:10003 \
  --volume "${SNAPSHOT}:/input/snapshot.json:ro" \
  "${RI_NORN_IMAGE}" \
  /usr/local/bin/norn-local-publisher \
  "${target}" "${REGISTRY_ADDRESS#0x}" "${REGISTRY_KEY}" /input/snapshot.json

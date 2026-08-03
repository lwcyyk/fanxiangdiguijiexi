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
  identity="${RI_MANAGEMENT_SECRET_DIR:?management secret directory is required}/publication-ssh-identity"
  [[ -f "${identity}" && ! -L "${identity}" ]] || {
    printf 'publication SSH identity is missing or unsafe\n' >&2
    exit 1
  }
  [[ "$(stat -c '%a' "${identity}")" == "600" ]] || {
    printf 'publication SSH identity permissions must be 0600\n' >&2
    exit 1
  }
  known_hosts="${RI_NORN_SSH_KNOWN_HOSTS:?pinned known_hosts is required}"
  ssh_host="${RI_NORN_SSH_HOST:?SSH publication host is required}"
  ssh_user="${RI_NORN_SSH_USER:?SSH publication user is required}"
  ssh_port="${RI_NORN_SSH_PORT:-22}"
  remote_target="${RI_NORN_SSH_REMOTE_TARGET:?SSH remote publication target is required}"
  local_port="${target#127.0.0.1:}"
  ssh -i "${identity}" -p "${ssh_port}" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="${known_hosts}" \
    -N -L "127.0.0.1:${local_port}:${remote_target}" "${ssh_user}@${ssh_host}" &
  tunnel_pid=$!
  trap 'kill "${tunnel_pid}" 2>/dev/null || true' EXIT
  sleep 1
  kill -0 "${tunnel_pid}" 2>/dev/null || {
    printf 'SSH publication tunnel failed to start\n' >&2
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

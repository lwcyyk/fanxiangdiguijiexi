#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=${1:-$ROOT/config/node.env}
ARCHIVE=$ROOT/images/rust-data-plane-oci-rc14.tar
COMPOSE=$ROOT/compose/docker-compose.yml
EXPECTED_ARCHIVE=95dc54ec9bcda0bb9f206fb24ddd23007cdba9ea490e7dda080a51584ee19f5f
EXPECTED_IMAGE=sha256:d6c4f9da0821dd1387906dae499e0f9e3d6cd9e1dc93cfadd5fbbe71ac10cf80

[ -f "$ENV_FILE" ] || { echo "missing node environment: $ENV_FILE" >&2; exit 1; }
[ "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)" = "$EXPECTED_ARCHIVE" ] || {
  echo "RC14 archive checksum mismatch" >&2
  exit 1
}

docker load --input "$ARCHIVE" >/dev/null
docker image inspect "$EXPECTED_IMAGE" >/dev/null
set -a
. "$ENV_FILE"
set +a
: "${RI_FIELD_DATA_DIR:?required}"
: "${RI_TRACE_SOCKET_HOST_DIR:?required}"
install -d -m 0750 "$RI_FIELD_DATA_DIR" "$RI_FIELD_DATA_DIR/knot-cache" "$RI_TRACE_SOCKET_HOST_DIR"

docker compose --env-file "$ENV_FILE" -f "$COMPOSE" config --quiet
profiles=()
if [ "${RI_NODE_ROLE:-resolver}" = "first-hop" ]; then
  profiles=(--profile first-hop)
fi
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" "${profiles[@]}" up -d
"$ROOT/check.sh" "$ENV_FILE"

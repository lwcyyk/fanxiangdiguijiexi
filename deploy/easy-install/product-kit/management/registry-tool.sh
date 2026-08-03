#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
# shellcheck disable=SC1091
source "${ROOT}/config/.env"
set +a
exec docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  --volume "${RI_MANAGEMENT_WORK_DIR}:/work" \
  --volume "${RI_MANAGEMENT_SECRET_DIR}:/run/field-secrets:ro" \
  --workdir /work \
  "${RI_MANAGEMENT_IMAGE}" "$@"

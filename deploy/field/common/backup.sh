#!/usr/bin/env bash
set -Eeuo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/field/common/lib.sh
source "${COMMON_DIR}/lib.sh"

OUTPUT="${1:?usage: backup.sh OUTPUT_DIRECTORY}"
CURRENT="${RI_INSTALL_ROOT:-/opt/resolver-identity}/current"
[[ -d "${CURRENT}" ]] || field_die "no installed release"
field_load_env "${CURRENT}/config/.env"
: "${RI_FIELD_DATA_DIR:?RI_FIELD_DATA_DIR is required}"
[[ -f "${RI_FIELD_DATA_DIR}/.ri-field-owned-data" ]] ||
  field_die "data ownership marker is missing"
mkdir -p "${OUTPUT}"
tar --create --gzip --file "${OUTPUT}/${RI_FIELD_HOST_ID}-data.tar.gz" \
  --directory "${RI_FIELD_DATA_DIR}" .
sha256sum "${OUTPUT}/${RI_FIELD_HOST_ID}-data.tar.gz" \
  >"${OUTPUT}/${RI_FIELD_HOST_ID}-data.tar.gz.sha256"
field_log "created data backup without changing live state"

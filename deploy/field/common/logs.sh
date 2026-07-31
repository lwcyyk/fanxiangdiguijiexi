#!/usr/bin/env bash
set -Eeuo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/field/common/lib.sh
source "${COMMON_DIR}/lib.sh"

CURRENT="${RI_INSTALL_ROOT:-/opt/resolver-identity}/current"
[[ -d "${CURRENT}" ]] || field_die "no installed release"
field_load_env "${CURRENT}/config/.env"
field_compose "${CURRENT}" logs --since "${RI_FIELD_LOG_SINCE:-15m}" "$@"

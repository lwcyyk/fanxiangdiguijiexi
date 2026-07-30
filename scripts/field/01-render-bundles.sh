#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INVENTORY="${1:-${RI_FIELD_INVENTORY:-}}"
OUTPUT_ROOT="${2:-${RI_FIELD_OUTPUT_ROOT:-${FIELD_REPO_ROOT}/deployments/field/private}}"
[[ -n "${INVENTORY}" ]] ||
  field_die "usage: $0 /secure/path/site-inventory.json [private-output-root]"
field_require_commands python3

arguments=(
  render
  --inventory "$(realpath "${INVENTORY}")"
  --output-root "${OUTPUT_ROOT}"
)
if [[ "${RI_FIELD_RENDER_FORCE:-false}" == "true" ]]; then
  arguments+=(--force)
fi
python3 "${FIELD_REPO_ROOT}/tools/manage_field_deployment.py" "${arguments[@]}"

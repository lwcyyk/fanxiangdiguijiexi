#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

INVENTORY="${1:-}"
SOURCE_LINK="${2:-}"
[[ -f "${INVENTORY}" && -n "${SOURCE_LINK}" ]] ||
  field_die "usage: $0 <private-inventory.json> <source-link-id>"
field_require_commands jq nc timeout

mapfile -t forbidden < <(
  jq -r --arg source "${SOURCE_LINK}" '
    .units[]
    | select(.link_id != $source)
    | [
        "\(.management_ip):\(.agent_port)",
        "\(.management_ip):\(.metrics_ports.wrapper)",
        "\(.management_ip):\(.metrics_ports.registry)",
        "\(.management_ip):\(.metrics_ports.trace)",
        "\(.wrapper_ip):\(.dns_port)"
      ][]
  ' "${INVENTORY}" | sort -u
)
(( ${#forbidden[@]} > 0 )) ||
  field_die "inventory has no other links to test"

for endpoint in "${forbidden[@]}"; do
  host="${endpoint%:*}"
  port="${endpoint##*:}"
  if timeout 3 nc -z "${host}" "${port}" >/dev/null 2>&1; then
    field_die "cross-link TCP access is unexpectedly allowed: ${endpoint}"
  fi
done
field_log "cross-link TCP denial checks passed from ${SOURCE_LINK}"

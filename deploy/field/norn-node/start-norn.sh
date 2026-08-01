#!/usr/bin/env bash
set -Eeuo pipefail

arguments=(
  /usr/local/bin/norn
  -d /data
  -c /config/config.yml
  --metrics
)
if [[ "${RI_NORN_ROLE:?}" == "node-a" ]]; then
  arguments+=(-g)
elif [[ "${RI_NORN_ROLE}" == "node-b" ]]; then
  : "${RI_NORN_BOOTSTRAP:?node-b requires RI_NORN_BOOTSTRAP}"
  arguments+=(-b "${RI_NORN_BOOTSTRAP}")
else
  printf 'unsupported RI_NORN_ROLE: %s\n' "${RI_NORN_ROLE}" >&2
  exit 1
fi
exec "${arguments[@]}"

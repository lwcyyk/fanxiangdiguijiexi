#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
field_require_commands docker sha256sum install cp jq
docker compose version >/dev/null
(
  cd "${BUNDLE_ROOT}"
  sha256sum --check metadata/SHA256SUMS
)

commit="$(jq -er '.git_commit' "${BUNDLE_ROOT}/metadata/unit.json")"
unit_id="$(jq -er '.unit_id' "${BUNDLE_ROOT}/metadata/unit.json")"
release_root="${RI_FIELD_RELEASE_ROOT}/units/${unit_id}"
release_dir="${release_root}/releases/${commit}"

field_run_root install -d -o root -g root -m 0755 \
  "${RI_FIELD_RELEASE_ROOT}" \
  "${RI_FIELD_RELEASE_ROOT}/units" \
  "${release_root}" \
  "${release_root}/releases"

if field_run_root test -e "${release_dir}"; then
  field_run_root test -f "${release_dir}/.ri-field-bundle" ||
    field_die "existing release is not a managed field bundle"
else
  field_run_root install -d -o root -g root -m 0755 "${release_dir}"
  field_run_root cp -a "${BUNDLE_ROOT}/." "${release_dir}/"
fi

field_run_root chown -R root:root "${release_dir}"
field_run_root chmod 0444 \
  "${release_dir}/deploy/issuer-keys.json" \
  "${release_dir}/deploy/link/identities-v2.json" \
  "${release_dir}/deploy/link/docker-compose.yml"
field_run_root chmod 0600 \
  "${release_dir}/deploy/link/.env" \
  "${release_dir}/metadata/unit.json" \
  "${release_dir}/metadata/SHA256SUMS"
field_run_root chown -R 10002:10002 \
  "${release_dir}/deploy/link/secrets" \
  "${release_dir}/deploy/link/tls"
field_run_root find "${release_dir}/deploy/link/secrets" -type f -exec chmod 0400 {} +
field_run_root find "${release_dir}/deploy/link/tls" -type f -name '*.key' -exec chmod 0400 {} +
field_run_root find "${release_dir}/deploy/link/tls" -type f -name '*.crt' -exec chmod 0444 {} +
field_run_root ln -sfn "${release_dir}" "${release_root}/current"

field_log "installed ${unit_id} release at ${release_dir}"
printf '%s\n' "${release_root}/current"

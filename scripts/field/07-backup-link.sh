#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

field_load_bundle "${1:-}"
OUTPUT_ROOT="${2:-}"
[[ -n "${OUTPUT_ROOT}" ]] ||
  field_die "usage: $0 <installed-bundle> <encrypted-private-backup-root>"
field_require_commands docker sqlite3 sha256sum install

timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
backup_dir="${OUTPUT_ROOT%/}/${RI_FIELD_SITE_ID}/${RI_FIELD_UNIT_ID}/${timestamp}"
field_run_root install -d -o root -g root -m 0700 "${backup_dir}"

evidence_source="$(field_volume_mountpoint "${PROJECT}_evidence")/evidence-v2.db"
trace_source="$(field_volume_mountpoint "${PROJECT}_trace-spool")/trace-spool.db"
field_sqlite "${evidence_source}" ".backup '${backup_dir}/evidence-v2.db'"
field_sqlite "${trace_source}" ".backup '${backup_dir}/trace-spool.db'"
field_run_root install -m 0600 "${ENV_FILE}" "${backup_dir}/runtime.env"
field_run_root install -m 0444 \
  "${BUNDLE_ROOT}/deploy/link/identities-v2.json" \
  "${BUNDLE_ROOT}/deploy/issuer-keys.json" \
  "${BUNDLE_ROOT}/metadata/unit.json" \
  "${backup_dir}/"
field_run_root install -d -o root -g root -m 0700 \
  "${backup_dir}/tls-public" \
  "${backup_dir}/registry-evidence"
for certificate in "${TLS_DIR}"/*.crt; do
  field_run_root install -m 0444 "${certificate}" "${backup_dir}/tls-public/"
done
for evidence in "${BUNDLE_ROOT}/deploy/registry-evidence/"*.json; do
  field_run_root install -m 0444 "${evidence}" "${backup_dir}/registry-evidence/"
done
# $1 is intentionally evaluated by the privileged child shell.
# shellcheck disable=SC2016
field_run_root bash -c '
  set -Eeuo pipefail
  cd "$1"
  sha256sum \
    evidence-v2.db trace-spool.db runtime.env \
    identities-v2.json issuer-keys.json unit.json \
    tls-public/*.crt registry-evidence/*.json >SHA256SUMS
  chmod 0600 SHA256SUMS
' _ "${backup_dir}"
field_log "private online backup completed: ${backup_dir}"
printf '%s\n' "${backup_dir}"

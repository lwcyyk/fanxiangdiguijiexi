#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/field/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

BACKUP_DIR="${1:-}"
SCRATCH_ROOT="${2:-}"
[[ -d "${BACKUP_DIR}" && -n "${SCRATCH_ROOT}" ]] ||
  field_die "usage: $0 <private-backup-directory> <isolated-scratch-root>"
field_require_commands sqlite3 sha256sum install
[[ "${SCRATCH_ROOT}" != / && "${SCRATCH_ROOT}" != /opt/resolver-identity* ]] ||
  field_die "restore drill must use an isolated scratch path"

# $1 is intentionally evaluated by the privileged child shell.
# shellcheck disable=SC2016
field_run_root bash -c '
  set -Eeuo pipefail
  cd "$1"
  sha256sum --check SHA256SUMS
' _ "${BACKUP_DIR}"
drill_dir="${SCRATCH_ROOT%/}/restore-drill-$(date -u +'%Y%m%dT%H%M%SZ')"
install -d -m 0700 "${drill_dir}"
field_run_root install -m 0600 \
  "${BACKUP_DIR}/evidence-v2.db" \
  "${BACKUP_DIR}/trace-spool.db" \
  "${drill_dir}/"
field_run_root chown "$(id -u):$(id -g)" \
  "${drill_dir}/evidence-v2.db" \
  "${drill_dir}/trace-spool.db"

[[ "$(sqlite3 "${drill_dir}/evidence-v2.db" 'PRAGMA integrity_check;')" == "ok" ]] ||
  field_die "restored evidence database failed integrity_check"
[[ "$(sqlite3 "${drill_dir}/trace-spool.db" 'PRAGMA integrity_check;')" == "ok" ]] ||
  field_die "restored trace spool failed integrity_check"
sqlite3 "${drill_dir}/evidence-v2.db" \
  'SELECT COUNT(*) AS registry_snapshots FROM ri_v2_registry_snapshot;'
sqlite3 "${drill_dir}/trace-spool.db" \
  'SELECT COUNT(*) AS pending FROM trace_spool;
   SELECT COUNT(*) AS dead_letter FROM trace_dead_letter;'
field_log "isolated restore drill passed: ${drill_dir}"

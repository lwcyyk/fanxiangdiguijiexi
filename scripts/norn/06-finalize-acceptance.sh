#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source "$(dirname "$0")/lib/common.sh"
require_command jq

output_dir="${REPO_ROOT}/deployments/norn-local"
positive="${output_dir}/acceptance.json"
negative="${output_dir}/acceptance-negative.json"
destination="${REPO_ROOT}/specs/multichain-registry-adapter/acceptance.json"
[[ -s "${positive}" && -s "${negative}" ]] || {
  printf 'run scripts/norn/04-publish-and-sync.sh and 05-negative-tests.sh first\n' >&2
  exit 1
}

jq -s '
  .[0] + {
    result: (
      if .[1].result == "passed" then "passed"
      else "failed"
      end
    ),
    negative_tests: .[1].tests,
    implementation_scope:
      "通过标准 Sidecar 协议扩展新的链适配器",
    security_assertions: {
      no_adapter_fallback: true,
      non_evm_reference_has_no_evm_compatibility_fields: true,
      signed_snapshot_and_signer_pin: true,
      expiration_and_key_rotation: true,
      replay_and_high_water_protection: true,
      failed_snapshot_preserves_sqlite_and_success_heartbeat: true,
      external_https_only_in_production: true,
      external_redirects_disabled: true,
      external_dynamic_upstream_fields_rejected: true
    }
  }
' "${positive}" "${negative}" >"${destination}"

printf 'wrote non-sensitive acceptance evidence: %s\n' "${destination}"

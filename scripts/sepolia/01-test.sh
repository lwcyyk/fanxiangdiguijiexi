#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/sepolia/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_commands cargo python3 forge docker
SOURCE_TREE_CLEAN="$(source_tree_clean && printf true || printf false)"

(
  cd "${REPO_ROOT}/rust"
  cargo fmt --all --check
  cargo test --workspace --locked
  cargo clippy --workspace --all-targets --locked -- -D warnings
)

(
  cd "${REPO_ROOT}"
  python3 -m pytest -q
)

(
  cd "${REPO_ROOT}/contracts"
  forge fmt --check
  forge build
  forge test -vvv
)

docker build \
  --file "${REPO_ROOT}/docker/Dockerfile.rust" \
  --tag resolver-identity-rust:sepolia-preprod \
  "${REPO_ROOT}"

docker compose \
  --env-file "${REPO_ROOT}/deploy/link/.env.example" \
  -f "${REPO_ROOT}/deploy/link/docker-compose.yml" \
  config >/dev/null

IMAGE_ID="$(docker image inspect resolver-identity-rust:sepolia-preprod --format '{{.Id}}')"
jq -n \
  --arg tested_at "$(utc_now)" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD)" \
  --argjson source_tree_clean "${SOURCE_TREE_CLEAN}" \
  --arg image_digest "${IMAGE_ID}" \
  '{
    tested_at:$tested_at,git_commit:$git_commit,source_tree_clean:$source_tree_clean,
    rust_fmt:"PASS",rust_tests:"PASS",rust_clippy:"PASS",python_tests:"PASS",
    forge_fmt:"PASS",forge_build:"PASS",forge_tests:"PASS",
    docker_build:"PASS",compose_config:"PASS"
  }' | write_json_atomic "${SEPOLIA_DEPLOYMENTS}/test-results.json"

log "all predeployment test commands passed"

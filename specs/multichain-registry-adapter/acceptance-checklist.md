# Acceptance Checklist

## Common layer

- [x] Registry Sync contains no direct chain-specific RPC calls.
- [x] Unknown adapters fail startup.
- [x] Missing adapter selection fails startup; no implicit EVM fallback exists.
- [x] Stored checkpoint rollback and hash-change tests pass.
- [x] Old generation and same-height/different-hash updates preserve SQLite and
  the last-success heartbeat.
- [x] Adapter identity is included in Registry semantic equality.
- [x] SQLite updates remain atomic.
- [x] Non-EVM references do not serialize EVM chain, contract, or runtime hash
  fields.

## EVM

- [x] Existing `RI_WEB3_*` configuration remains accepted.
- [x] Chain ID, code hash, finalized/fallback, Root, Resolver, and Endpoint tests
  pass.

## Go-Norn

- [x] Genesis hash is pinned and checked.
- [x] Production requires two TLS RPC endpoints.
- [x] Confirmation-derived checkpoint is checked by both nodes.
- [x] Divergent node state or block hashes fail closed.
- [x] Snapshot signature, validity, Root, Resolver, and Endpoint checks pass.
- [x] Snapshot signer is pinned; rotation requires an explicit pin and key
  update.
- [x] Nodes use independent data directories and distinct node keys.
- [x] Runtime adapter cannot submit a transaction.
- [x] Live local dual-node Go-Norn integration, real publication, mTLS reads,
  Registry Sync and SQLite reconciliation pass.

## External protocol

- [x] Runtime selection supports `RI_CHAIN_ADAPTER=external`.
- [x] Production requires two unique HTTPS endpoints.
- [x] Snapshot target, signer, validity, state root and Endpoint ownership are
  verified.
- [x] Dual HTTP sidecars reconcile successfully.
- [x] Same-height different-hash sidecars fail closed.
- [x] Optional mTLS client material is supported.
- [x] Production HTTP URLs are rejected and redirects are not followed.
- [x] Snapshot and target reject unknown dynamic-upstream fields.
- [x] OpenAPI and JSON Schema contracts are present.
- [x] Management CLI generates and independently verifies signed external
  snapshots from an approved publication plan.

## Verification

- [x] `cargo fmt --all --check`
- [x] `cargo test --workspace --locked`
- [x] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [x] `python3 -m pytest -q`
- [x] Docker image build
- [x] Docker Compose EVM configuration render
- [x] Docker Compose Norn configuration render
- [x] Docker Compose External configuration render
- [x] Foundry build and 14 contract tests
- [x] Complete branch and acceptance evidence secret/runtime-artifact audit

## Fresh-clone Go-Norn evidence

The final non-sensitive result is generated only after a clean-clone rebuild:
`specs/multichain-registry-adapter/acceptance.json`. Databases, node keys,
snapshot signing keys, TLS private keys and detailed runtime logs remain under
ignored local directories and are never committed.

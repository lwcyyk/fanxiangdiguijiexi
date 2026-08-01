# Tasks

- [x] Audit EVM-specific coupling in `ri-registry-sync`.
- [x] Review Go-Norn block, state, transaction, and gRPC behavior.
- [x] Define the common adapter capability contract.
- [x] Add explicit multi-chain fields to `RegistryReferenceV2`.
- [x] Implement the `ri-chain-adapter` crate.
- [x] Move existing EVM reads behind `EvmRegistryAdapter`.
- [x] Implement dual-node `NornRegistryAdapter`.
- [x] Add generic and backward-compatible environment parsing.
- [x] Require explicit adapter selection and remove automatic EVM fallback.
- [x] Remove fake EVM fields from Norn and External Registry references.
- [x] Update Docker Compose and environment examples.
- [x] Add EVM regression and Norn snapshot/consensus tests.
- [x] Add Norn snapshot generation/verification tooling.
- [x] Add the standard external sidecar adapter and runtime factory.
- [x] Add external protocol OpenAPI, JSON Schema, dual-endpoint and fork tests.
- [x] Build a pinned local two-node Go-Norn network with mTLS read proxies.
- [x] Patch and verify Go-Norn large-value publishing and restart synchronization.
- [x] Publish a real signed Norn snapshot and reconcile it into SQLite.
- [x] Run wrong-genesis, wrong-schema, single-node, unavailable-node, and
  failed-update preservation tests.
- [x] Add signer pin, expiration, rotation, replay, high-water, redirect,
  dynamic-upstream, wrong Registry ID and unknown-adapter tests.
- [x] Document deployment, security gaps, and adapter extension.
- [x] Run format, tests, Clippy, Python tests, Compose validation, contract tests,
  and the Rust container build.
- [x] Re-run the complete test matrix and EVM, Norn, and External Compose
  rendering from a fresh clone with no prior containers or volumes.
- [x] Audit the complete branch diff and acceptance evidence for private keys,
  credentials, databases, TLS private material, RPC credentials, and runtime
  files before delivery.
- [x] Split common Registry fields from typed EVM, Norn, and External metadata.
- [x] Add an in-place schema-v2 to schema-v3 EVM migration.
- [x] Reject typed metadata confusion and conflicting compatibility variables.
- [x] Require two independent HTTPS+mTLS External endpoints in every mode.
- [x] Add pinned toolchain CI and a required release-candidate gate.
- [x] Consolidate the runbook, security boundary, troubleshooting, OpenAPI, and
  JSON Schema delivery structure.
- [x] Complete the new fresh-clone Norn acceptance run and regenerate
  `acceptance.json`.
- [x] Audit all reachable branch history and push the evidence commits to Draft
  PR #1.

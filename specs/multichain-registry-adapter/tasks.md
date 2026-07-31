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
